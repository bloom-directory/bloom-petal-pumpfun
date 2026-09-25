# Pump.fun Petal — operational notes

## Scope

Buy or sell an existing coin from the Bloom account already selected, and
optionally close an empty token account afterwards. Each of those is one owner
approval. Coin creation, fee collection and fee-sharing configuration are not in
this release and their routes have been removed.

## Compatibility

| Requirement | Why | State |
| --- | --- | --- |
| `[sign].fee_asset` in `petal.toml` | Bloom must know which asset the declared fee is in | bloom#276, unreleased |
| review transport to the ceremony | otherwise the owner approves an opaque digest | see "What the owner sees" |

Bloom v0.3.0 refuses to install this package: it does not recognize
`[sign].fee_asset`. Record the first Bloom release containing it here when it
ships. Release installs also need this package in Bloom's signed release
catalog; until then it runs only on a developer Triad.

This package does **not** need bloom#302 (bounded session keys) or bloom#304
(Exact signing with a Petal's own session key). Both belong to the delegated
session model this Petal no longer uses.

## Setup flow

There is no session to create, no key to derive and no address to fund.

1. `GET trade/<wallet>/preflight.json` — verifies the trading account has a
   readable Solana address, that the RPC is serving mainnet-beta, and that
   Pump's builder is reachable.

   Read all three lists in the response and do not confuse them. `checks` are
   facts the Petal verified itself. `blockers` are checks it ran that failed,
   and `ok` reflects only those. `operator_checks` are facts the Petal cannot
   see from inside the sandbox and has not checked either way — they are not
   failures, and an empty `blockers` list does not mean somebody did them.

2. Make sure wallet policy allows the protocol programs the trade will route
   through. See the table below.

3. `POST trade/<wallet>/buy.json {operationId, mint, amount, minOutputAmount}`.
   The first call returns `approval required` with an `action_id`; complete the
   ceremony, then repeat the identical write to continue.

## What wallet policy has to allow

Bloom compares every destination a claim declares against
`allowed_destinations` as a flat set.

| Destination | Declared by | Needed for |
| --- | --- | --- |
| `6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P` | Pump bonding curve | a buy or sell before the coin migrates |
| `pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA` | PumpSwap AMM | a buy or sell after it migrates |
| the selected Jito tip account | a protected write | only with `frontRunningProtection` |
| the trading account's own Solana address | `close_token_account` | returning the rent — see below |

Which Pump program a given mint routes through depends on whether it has
migrated, and the Petal does not choose — the builder does. Allow both, or read
`coins/<mint>.json` first and allow the one that mint actually uses.

**Closing a token account needs the trading account itself in
`allowed_destinations`.** The close declares the rent destination, which is the
trading account, and Bloom checks every declared destination against policy as
a flat set — including an account the wallet already owns. Without the entry
the write is refused after the owner has already approved it, with
`CLAIM_INVALID: claim names destination <account> for chain "solana" outside
wallet policy`. Add it before the first close.

The eight Jito tip accounts the Petal accepts are listed in
`route/src/lib.rs`. A write declares only the one it selects, and only when
`frontRunningProtection` is set.

Read the current policy before assuming any of this is missing:

```sh
bloom vfs cat /wallets/<wallet>/policy.json
```

## What the owner is prompted for

| # | Ceremony | What the owner is deciding | When it is skipped |
| --- | --- | --- | --- |
| 1 | package eligibility | allow this Petal package version | already allowed |
| 2 | `PolicyUpdate` | admit any protocol destination the policy lacks | policy already covers them |
| 3 | `SealedApproval` | one trade of this kind, up to the SOL ceiling shown | never — one per trade |

Ceremony 3 repeats for every buy, every sell and every close. That is the
design, not an oversight: nothing here signs a trade the owner has not approved,
or spends above the ceiling they saw.

## What the owner sees

The Petal builds a review from the validated transaction and sends it with the
payload as the SDK's `advisory` bytes, a bounded versioned object:

```json
{"schema":"bloom.petal.review.v1","items":["Buy on Pump.fun","Trading account: …"]}
```

Bloom hashes those bytes into the approval's canonical facts, so an approval
prepared for one review cannot sign a different one — changing the review
changes the facts digest and the retry is refused as a different operation.

**On Bloom master those bytes are hashed and go nowhere**: the daemon puts an
`advisory_digest` in its canonical facts and passes no advisory to
`sign_or_prepare_petal`, and Broker's `prepare_approval` sets
`attributed_advisory_items: Vec::new()`. The ceremony then shows the claim's
declared debits, destinations and fee — real figures, already rendered with SOL
units — but not the minimum output or the direction. On a build carrying the
review transport the page shows the lines above, attributed to the app, in
their own block. A live run confirmed it: see
`shared/pumpfun-direct-live-2026-09-22/`.

Bloom does not verify any of it. The page says so, and the review is worded as
the app's own statement for that reason.

## Approval and retry continuation

`execute()` is idempotent per `operationId` and per trading account. Calling it
again with the same id and the same request continues where it stopped; the same
id with different content is refused as `operationId already bound`.

The Petal records whether any signing call for an operation's transaction may
have produced a signature. Once that is possible the operation is never rebuilt,
whatever later attempts report, because a rebuilt transaction could pay twice.

`status` is the one field to read:

| Status | Meaning | What a retry does |
| --- | --- | --- |
| `approval_pending` | an owner ceremony is required; `action_id` is in the response | rebuilds with a fresh blockhash and signs under the approval once the owner has completed it |
| `approval_failed` | signing was refused | rebuilds and asks again, unless the transaction may already be signed |
| `preflight_failed` | the unsigned transaction failed simulation | rebuilds, unless the transaction may already be signed |
| `signing` | a signing call was interrupted before its outcome was recorded | treated as possibly signed: signs the same transaction again |
| `signing_uncertain` | signing returned no answer and may already have signed | signs the same transaction again |
| `broadcast_attempted` | sent, with no acknowledgement — outcome unknown | reports it; never re-broadcasts |
| `submitted` | the RPC returned the signature we sent | reports it |
| `confirmed` / `finalized` | the cluster observed the transaction | reports it |
| `chain_failed` | the transaction failed on-chain | reports it |

A possibly signed transaction that can no longer land stays stuck under its
`operationId`. Confirm on the cluster that it did not land before retrying the
intent under a new `operationId`.

## Timing

Three different clocks bound a trade, and they are not the same thing:

- **chain validity** — the blockhash the builder pinned. Roughly 60 seconds,
  often less by the time the builder answers. The approval does not bind it:
  the retry after the ceremony rebuilds with a fresh one.
- **approval expiry** — how long Bloom's approval stays usable.
- **price** — the quote is fixed when the transaction is built, and the owner
  then reads and approves inside that window. See below: on a buy the price
  may move against the owner up to the maximum spend, and widening slippage
  raises that ceiling. It does not extend chain validity.

### On a buy, `slippagePct` moves the maximum spend, not the tokens

A Pump buy instruction names **a token amount and a ceiling on the SOL in**.
Measured against the live builder on 23 September 2026, on both routes and at
2%, 10% and 40%: the token amount is **exactly** the builder's quote every
time, unchanged by `slippagePct`; only `max_quote_amount_in` moves — 1,020,000,
1,100,000 and 1,400,000 lamports for a 1,000,000 lamport buy.

So the tolerance is on what the trade spends. The pool can move against the
owner between building and landing, and the program pays what the curve now
asks, up to that ceiling; past it the trade fails rather than pay more, which
is what both failed simulations in that run showed at the 2% default.
A wider `slippagePct` buys the same tokens and risks more SOL.

That is why the maximum spend is the figure the review states first and totals
at the end: it is what can change after the owner has read it.

What these measurements do **not** establish is what the program does with the
token amount beyond refusing to overpay for it — whether it always delivers
exactly that amount, or can deliver less in some pool state. The review says
only what the instruction names, and the enforced protection it states is the
maximum spend. They say nothing about **sells**, which were not probed: a sell
names a token amount in and a floor on the SOL out, so its fields sit the other
way round, and the review reports that floor as the instruction's own.

`minOutputAmount` is a **check, not a control**. The Petal compares it against
the token amount the builder baked in and refuses a transaction that promises
less; it cannot change that amount, so asking for less does not make a fill
easier.

The Petal simulates before signing, so a trade the pool can no longer satisfy
within its ceiling stops at `preflight_failed` with the program's own error
preserved, before a ceremony is created. Retrying under the same `operationId`
rebuilds it against a fresh quote. Evidence:
`shared/pumpfun-live-builder-2026-09-23/`.

The retry after the ceremony rebuilds against a fresh blockhash and quote under
the same request, so the same ceiling holds. The Petal never widens slippage on
its own.
