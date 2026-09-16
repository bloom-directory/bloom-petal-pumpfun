# Pump.fun Petal — operational notes

## Setup flow

The Petal does not own session-key custody. Every key it uses is derived
through `petal::sdk::derive_key`, which returns either `Pending` (Bloom
must run a passkey ceremony) or `Ready` (the ceremony completed and the
key reference is bound to the wallet).

A complete setup looks like:

1. `GET sessions/<wallet>/preflight.json` — verify connectivity, RPC
   genesis and builder reachability.

   Read all three lists in the response and do not confuse them.
   `checks` are facts the Petal verified itself. `blockers` are checks it
   ran that failed, and `ok` reflects only those. `operator_checks` are
   facts the Petal cannot see from inside the sandbox and has not checked
   either way — they are not failures, and an empty `blockers` list does
   not mean somebody did them.

2. `POST sessions/<wallet>/new.json {id, duration_ms, max_lamports, token_limits}` — derive the
   session key. The Petal returns `approval required: {...}` with an
   `operation_id` and `scope_digest`.

3. Complete the key-derivation ceremony, then retry step 2 once. Bloom
   records `key_derived` under `/petal-key-requests/<record>.json`, with
   the session address in `public_key.addresses`. This is still `Pending`
   to the Petal: the reusable approval has not been prepared yet. Use the
   record matching this wallet and key slot for the next step.

4. Update the wallet's Solana allowed destinations to cover the whole cycle,
   and complete that policy ceremony. **The session address alone is not
   enough**, and getting this wrong is only discovered when a trade is
   refused. See "What wallet policy has to allow" below for the full list.
   Prepare one policy diff covering every entry the cycle needs and spend one
   ceremony on it, rather than discovering them one refusal at a time.

   The session address is only known after step 3. The protocol and return
   addresses can be reviewed earlier; combine the missing entries once the
   session address is available.

5. After the policy update is committed, retry step 2 to prepare the
   reusable approval. Complete that ceremony and retry once more to receive
   `Ready`. Do not change wallet policy after activating this approval:
   Broker binds it to that exact policy snapshot.

   Fund the session address from the owner wallet, and approve that
   transfer. Fund only what the cycle needs — the buy, plus the network and
   priority fees for four transactions, plus rent for any token account the
   buy creates — and only when the key's remaining lifetime comfortably
   covers buying, selling, closing the token account and sweeping.

6. `POST sessions/<wallet>/sessions/<session>/buy.json {operationId, mint,
   amount, minOutputAmount, ...}` — stage and run the buy. No further
   ceremony: it signs under the reusable approval from step 3.

## Session budgets and installer provenance

`new.json` requires `max_lamports`, a positive decimal string limiting the
**cumulative declared native value** over the session. This includes network
fees, buys, rent allowances, close-account returns, and the final sweep.
It is not a funding amount or a net-loss limit: returning funds also consumes
this budget. Leave enough budget for the exit before funding the session.

`token_limits` is an optional object mapping mint addresses to positive
raw-token decimal strings. Include every mint the session may sell, with a
ceiling covering the total amount it may sell. An omitted mint has no debit
allowance. Decide these budgets before the two key/approval ceremonies;
changing them under the same session id is rejected. A different budget
requires a new session. `session.json` records the requested limits.

These limits enter the separate owner-approved reusable terms through the
host's `approval_value_limits` key-request field. They do not enlarge the
key's routes, operation classes, or lifetime. Older Bloom builds without this
field cannot run budgeted sessions. No SDK or WIT upgrade is needed: the
pinned SDK exposes `request_key` for canonical JSON requests.

Installer provenance must also declare `{chain:"solana", asset:"native"}`
as the fee asset for all seven Pump.fun operation classes. A catalog that
marks them fee-free causes Broker to reject a correct trade claim. Bloom's
updated developer enrollment supplies these declarations; release enrollment
must carry the same facts in its signed catalog.

## What wallet policy has to allow

Bloom compares every destination a claim declares against
`allowed_destinations` as a flat set — one membership test per entry, on both
the native transfer path and the Petal claim path. The Petal declares more
than the funding address:

| Destination | Declared by | Needed for |
| --- | --- | --- |
| the session address | the native funding transfer | funding (step 5) |
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

For a wallet that already allows this Petal package and already allows the
protocol programs and the return address, one bounded session costs **four**
passkey ceremonies, and none of them are per trade:

| # | Ceremony | What the owner is deciding | When it is skipped |
| --- | --- | --- | --- |
| 1 | package eligibility | allow this Petal package version | already allowed, or the same version was used before |
| 2 | `KeyDerive` | mint the session key, with its routes, operation classes and lifetime | never — one per session |
| 3 | `PolicyUpdate` | add the session address, and any protocol or return destination policy still lacks | never — the session address is new every time |
| 4 | `SealedApproval` | activate the session's reusable approval for that key and its budgets | never — one per session key |
| 5 | `SealedApproval` | the funding transfer, for an exact amount | never |

So: five on a wallet meeting this Petal for the first time, four for each
later session of the same package version. The count is a function of the
wallet's starting policy, not a property of the Petal — check the policy
before quoting it to anyone.

Buy, sell, `close_token_account` and sweep add none. They all sign under
the approval from ceremony 4, whose scope is this package's declared routes
and operation classes, bounded at 256 operations and 256 signatures and
expiring with the scoped key. Broker enforces its cumulative native and
per-mint value limits in addition to wallet policy and the Petal's transaction
checks.

Ceremony 3 follows key derivation, and ceremony 4 must follow the policy
commit. Reversing those last two invalidates the approval's policy snapshot.

Reducing this further means widening what a single approval authorizes.
That is tracked in `bloom-directory/bloom#171`; do not assume it has landed.

## Session lifetime

The session's `expires_ms` is `now + duration_ms`, measured when the derive
returned `Ready`. It is the lifetime this Petal asked for, not the Signer's
view of the grant: the pinned SDK's `PetalKeyOutcome::Ready` carries no
expiry, so the Petal cannot read the authoritative one. If a ceremony sat
waiting for a while, the real scope is older than the recorded deadline.

Treat the recorded deadline as an estimate, and read the authoritative one
before funding. **Three different expiries are in play during setup, and only
one of them is the key's deadline.** Confusing them is easy and expensive, so
be exact about which you are looking at:

| Expiry | What it is | Where |
| --- | --- | --- |
| the session's `expires_ms` | what this Petal asked for, timed from when the derive returned `Ready` | `session.json`, and preflight |
| the reusable approval's **terms** `expires_at_ms` | **the scoped key's deadline.** Bloom sets it to the Signer's `petal_scope_expires_at_ms` exactly, and refuses to prepare the approval at all if the scope has already lapsed | the Machine's Petal key state record, under `public_key.petal_scope_expires_at_ms` |
| the **ceremony** expiry | how long the passkey page stays usable — `min(now + ceremony TTL, the terms expiry)`, normally about five minutes | the ceremony URL, and `ceremony_expires_at_ms` in the approval projections |

The middle row is the one that matters. The last row is not a shorter view of
it: the Signer deliberately clamps a browser ceremony so it cannot outlive the
authority it activates, so the countdown on the passkey page tells you how long
you have to finish clicking, and nothing at all about how long the session key
lives. Reading it as the key deadline understates the session's life by hours.

List `/petal-key-requests` with `bloom vfs ls`, then read the matching JSON
record with `bloom vfs cat /petal-key-requests/<record>.json`. Match its wallet,
package and key slot, and use `public_key.petal_scope_expires_at_ms` as the
key deadline. Compare it with the Petal's `expires_ms` and use the earlier
one. The sibling `ceremony_expires_at_ms` field is only the browser deadline.

If those two are far apart, the ceremony sat waiting and the session has less
time than it claims. Sell, close and sweep while the scope is still live. An
expired scoped key cannot sign, and there is no recovery path that gets
assets out of a session whose key has expired — so do not fund a session that
does not have time left for the whole cycle.

## Approval and retry continuation

`execute()` is idempotent per `operationId`. Calling it again with the same
id and the same request continues where it stopped; calling it with the
same id and different content is refused as `operationId already bound`.

`status` is the one field to read:

| Status | Meaning | What a retry does |
| --- | --- | --- |
| `approval_pending` | a ceremony is still required; `action_id` is in the response | refreshes the transaction, keeps the same approval |
| `approval_failed` | signing was refused | rebuilds and asks for a new approval |
| `signing_uncertain` | signing returned no answer and may already have signed | re-signs the same message under the same approval |
| `preflight_failed` | the unsigned transaction failed simulation; nothing was signed | rebuilds with a fresh blockhash |
| `simulation_failed` | earlier versions only: a signed transaction failed simulation on an RPC and may still land | re-signs the same message; never rebuilds |
| `broadcast_attempted` | sent, with no acknowledgement — outcome unknown | reports it; never re-broadcasts |
| `submitted` | the RPC returned the signature we sent | reports it |
| `confirmed` / `finalized` | the cluster observed the transaction | reports it |
| `chain_failed` | the transaction failed on-chain | reports it |

`broadcast_attempted` is the one status that needs a person. The Petal
records the signature before sending, so read that signature against the
cluster to settle whether it landed. The Petal will not rebuild the
operation, because a rebuild could pay twice.

## Obsolete destination cleanup

An earlier handoff reported that a previous session address
(`9pcUafcrPCajWf8LD8YqJ13zxKEDbufpsaJAUR2dhPRC`) was added to the
`main` wallet's Solana allowed destinations. Check whether it is still
there before spending a ceremony on it:

1. Read the current policy:
   ```sh
   bloom vfs cat /wallets/main/policy.json
   ```
2. If the address is absent, there is nothing to do.
3. Otherwise prepare an updated policy that omits it, and run
   `bloom wallet update-policy main --file policy.json`.
4. Complete the passkey ceremony, then run
   `bloom wallet commit-policy <operation_id>` using the returned operation id.
5. Verify with `bloom vfs cat /wallets/main/policy.json` that the address is gone.

Fold this into the next policy update the session needs rather than
spending a ceremony on it alone.
