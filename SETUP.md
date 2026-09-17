# Pump.fun Petal — operational notes

## Scope

These notes cover the supported flow: create a session, review its address and
budgets, approve, fund, buy and sell an existing coin, stop, close token
accounts, sweep. Coin creation through `create.json` is **not supported in this
release** and has not been run against Pump's real create program; its checks
remain in place, but do not include it in a setup you intend to use.

## Compatibility

This package needs a Bloom build that includes three changes, none of which is
in a Bloom release yet:

- `[sign].fee_asset` in `petal.toml` (bloom#276);
- bounded session keys: budgets, address before approval, policy binding (bloom#302);
- Exact signing with the Petal's own session key, for close and sweep (bloom#304).

Bloom v0.3.0 refuses to install this package: it does not recognize
`[sign].fee_asset`. Record the first Bloom release containing all three here
when it ships. Release installs also need this package in Bloom's signed
release catalog; until then it runs only on a developer Triad.

## Setup flow

The Petal does not own session-key custody. Every key it uses is requested
from Bloom, which answers either Pending (the owner still has something to do)
or Ready (the session key exists and its trading approval is active).

1. `GET sessions/<wallet>/preflight.json` — verify connectivity, RPC
   genesis and builder reachability.

   Read all three lists in the response and do not confuse them.
   `checks` are facts the Petal verified itself. `blockers` are checks it
   ran that failed, and `ok` reflects only those. `operator_checks` are
   facts the Petal cannot see from inside the sandbox and has not checked
   either way — they are not failures, and an empty `blockers` list does
   not mean somebody did them.

2. `POST sessions/<wallet>/new.json {id, duration_ms, max_lamports, token_limits}`.
   The Petal answers `session authority pending` with the key slot and the
   Bloom path to watch:
   `/wallets/<wallet>/<account>/sessions/<pumpfun mount>/<key slot>/session.json`.
   Complete the key-derivation ceremony it points at (and, the first time,
   the package eligibility ceremony).

3. Retry step 2 with the identical body. Bloom records the key and answers
   Pending again without preparing any approval yet. The session address is now
   in that Bloom `session.json` under `delegated.addresses`.

4. Update the wallet's Solana allowed destinations to cover the whole cycle,
   and complete that policy ceremony. **The session address alone is not
   enough.** See "What wallet policy has to allow" below, and prepare one policy
   diff covering every entry the cycle needs.

5. Retry step 2 again. Bloom now prepares the session's trading approval, with
   its budgets, against the policy you just committed. Complete that ceremony
   and retry once more to receive Ready; the Petal then writes its own
   `session.json`.

   If you retry before committing the policy, the approval is prepared against
   the old policy. That is safe: after the policy commit, the next retry
   prepares a replacement, which costs one more ceremony.

6. Fund the session address from the owner wallet and approve that transfer.
   Fund only what the cycle needs. On current Bloom a native transfer approval
   must be completed within about a minute of preparing it.

7. `POST sessions/<wallet>/sessions/<session>/buy.json {operationId, mint,
   amount, minOutputAmount, ...}` — no further ceremony: trading writes sign
   under the approval from step 5.

Any later wallet policy change makes Bloom refuse that approval. Repeat step 2
with the identical body: the same key and deadline get a replacement approval
after one more ceremony.

## Session budgets and fee asset

`new.json` requires `max_lamports`, a positive decimal string limiting the
**cumulative declared native value of trading writes** over the session: network
fees, buys, and rent allowances. It is not a funding amount or a net-loss limit.

`token_limits` is an optional object mapping mint addresses to positive
raw-token decimal strings. Include every mint the session may sell, with a
ceiling covering the total amount it may sell. An omitted mint has no debit
allowance.

Decide these budgets before step 2: changing them under the same session id is
rejected, and a different budget needs a new session. Bloom checks their shape
(positive, unique assets) and seals them unchanged into the trading approval,
where the owner reviews them. It imposes no ceiling of its own.

Close and sweep are not paid from these budgets. Each of those transactions is
approved separately by the owner, for exactly the value it moves.

Every claim this Petal makes declares a native Solana network fee.
`petal.toml` declares that with `[sign] fee_asset = {chain = "solana", asset =
"native"}`; Bloom's developer enrollment reads it. Release enrollment does not
read it yet.

## What wallet policy has to allow

Bloom compares every destination a claim declares against
`allowed_destinations` as a flat set — one membership test per entry, on both
the native transfer path and the Petal claim path. The Petal declares more
than the funding address:

| Destination | Declared by | Needed for |
| --- | --- | --- |
| the session address | the native funding transfer | funding (step 6) |
| `6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P` | Pump bonding curve | a buy or sell before the coin migrates |
| `pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA` | PumpSwap AMM | a buy or sell after it migrates |
| `pfeeUxB6jkeY1Hxd7CsFCAjcbHA9rWtchMGdZ6VojVZ` | Pump Fees | `collect_fees`, `sharing_config` |
| `AgenTMiC2hvxGebTsgmsD4HHBa8WEcqGFf87iwRRxLo7` | Agent Payments | a tokenized-agent `create` |
| the owner return address | `close_token_account` and `sweep` | the exit |
| the selected Jito tip account | a protected write | only with `frontRunningProtection` |

Which Pump program a given mint routes through depends on whether it has
migrated, and the Petal does not choose — the builder does. Allow both, or
read `coins/<mint>.json` first and allow the one that mint actually uses.

The eight Jito tip accounts the Petal accepts are listed in
`route/src/lib.rs`. A write only declares the one it selects, and only when
`frontRunningProtection` is set, so leave them out unless you intend to use
protected writes.

Read the current policy before assuming any of this is missing:

```sh
bloom vfs cat /wallets/<wallet>/policy.json
```

## What the owner is prompted for

For a wallet whose policy already allows the protocol programs and the return
address:

| # | Ceremony | What the owner is deciding | When it is skipped |
| --- | --- | --- | --- |
| 1 | package eligibility | allow this Petal package version | already allowed |
| 2 | `KeyDerive` | create the session key, with its routes, operation classes and lifetime | never — one per session |
| 3 | `PolicyUpdate` | admit the session address, and any protocol or return destination the policy lacks | never — the session address is new every time |
| 4 | `SealedApproval` | the session's trading approval with its budgets | never; repeated after any later policy change |
| 5 | `SealedApproval` | the funding transfer, for an exact amount | never |
| 6+ | `SealedApproval` | each `close_token_account` and the `sweep`, for that exact transaction | never — one per recovery transaction |

Trading writes add none. A coin's buy and sell therefore cost no ceremony, but
the exit costs one per closed token account plus one for the sweep.

The order of 3 and 4 matters only for cost: an approval prepared before the
policy commit is replaced afterwards by one more ceremony 4.

## Session lifetime

The Petal's `session.json` `expires_ms` is the first `new.json` request time
plus `duration_ms`. Bloom starts the key's lifetime later, when derivation
completes, so this never overstates the key. The trading approval can end
earlier than `expires_ms`, because Bloom keeps it inside the key's lifetime with
a safety margin. Read its end from Bloom's session record at
`/wallets/<wallet>/<account>/sessions/<pumpfun mount>/<key slot>/session.json`
(`expires_at_ms`, with `signing_authority` showing whether it is still usable).
A ceremony page's own countdown is only how long that page stays open.

After the session stops or expires, trading writes are refused, but
`close_token_account` and `sweep` still work: each asks the owner to approve
that exact transaction.

## Approval and retry continuation

`execute()` is idempotent per `operationId`. Calling it again with the same
id and the same request continues where it stopped; calling it with the
same id and different content is refused as `operationId already bound`.

The Petal records whether any signing call for an operation's transaction may
have produced a signature. Once that is possible, the operation is never
rebuilt, whatever later attempts report, because a rebuilt transaction could
pay twice.

`status` is the one field to read:

| Status | Meaning | What a retry does |
| --- | --- | --- |
| `approval_pending` | an owner ceremony is required; `action_id` is in the response | trading writes: refresh the transaction and keep waiting. close/sweep: keep the exact transaction the owner is approving |
| `approval_failed` | signing was refused | rebuilds and asks again, unless the transaction may already be signed |
| `preflight_failed` | the unsigned transaction failed simulation | rebuilds, unless the transaction may already be signed. A close/sweep awaiting approval keeps its transaction and approval, because a failed simulation can clear; only once its blockhash has expired (finalized block height past its last valid height) is the approval dropped and a new one requested |
| `signing` | a signing call was interrupted before its outcome was recorded | treated as possibly signed: signs the same transaction again |
| `signing_uncertain` | signing returned no answer and may already have signed | signs the same transaction again |
| `simulation_failed` | earlier versions only: a signed transaction failed simulation on an RPC and may still land | treated as possibly signed: signs the same transaction again |
| `broadcast_attempted` | sent, with no acknowledgement — outcome unknown | reports it; never re-broadcasts |
| `submitted` | the RPC returned the signature we sent | reports it |
| `confirmed` / `finalized` | the cluster observed the transaction | reports it |
| `chain_failed` | the transaction failed on-chain | reports it |

A possibly signed transaction that can no longer land (a Solana blockhash lasts
about a minute) stays stuck under its `operationId`. Confirm on the cluster that
it did not land before retrying the intent under a new `operationId`.

`broadcast_attempted` needs a person too. The Petal records the signature
before sending, so read that signature against the cluster to settle whether it
landed.
