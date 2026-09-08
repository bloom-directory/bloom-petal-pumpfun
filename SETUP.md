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

2. `POST sessions/<wallet>/new.json {id, duration_ms}` — derive the
   session key. The Petal returns `approval required: {...}` with an
   `operation_id` and `scope_digest`.

3. The operator opens the ceremony URL in Chromium and completes the
   passkey flow. Retry step 2 afterwards: Bloom then prepares the
   session's reusable approval and returns a second ceremony URL. Complete
   that one too, and the next retry of step 2 returns `Ready` with the
   session address.

4. Update the wallet's Solana allowed destinations to cover the whole cycle,
   and complete that policy ceremony. **The session address alone is not
   enough**, and getting this wrong is only discovered when a trade is
   refused. See "What wallet policy has to allow" below for the full list.
   Prepare one policy diff covering every entry the cycle needs and spend one
   ceremony on it, rather than discovering them one refusal at a time.

   None of it can be prepared before step 3: the derivation index is
   allocated inside the derive ceremony, so the session address does not
   exist until that ceremony has completed.

5. Fund the session address from the owner wallet, and approve that
   transfer. Fund only what the cycle needs — the buy, plus the network and
   priority fees for four transactions, plus rent for any token account the
   buy creates — and only when the key's remaining lifetime comfortably
   covers buying, selling, closing the token account and sweeping.

6. `POST sessions/<wallet>/sessions/<session>/buy.json {operationId, mint,
   amount, minOutputAmount, ...}` — stage and run the buy. No further
   ceremony: it signs under the reusable approval from step 3.

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
bloom policy read <wallet>
```

## What the owner is prompted for

For a wallet that already allows this Petal package and already allows the
protocol programs and the return address, one bounded session costs **four**
passkey ceremonies, and none of them are per trade:

| # | Ceremony | What the owner is deciding | When it is skipped |
| --- | --- | --- | --- |
| 1 | package eligibility | allow this Petal package version | already allowed, or the same version was used before |
| 2 | `KeyDerive` | mint the session key, with its routes, operation classes and lifetime | never — one per session |
| 3 | `SealedApproval` | activate the session's reusable approval for that key | never — one per session key |
| 4 | `PolicyUpdate` | add the session address, and any protocol or return destination policy still lacks | never — the session address is new every time |
| 5 | `SealedApproval` | the funding transfer, for an exact amount | never |

So: five on a wallet meeting this Petal for the first time, four for each
later session of the same package version. The count is a function of the
wallet's starting policy, not a property of the Petal — check the policy
before quoting it to anyone.

Buy, sell, `close_token_account` and sweep add none. They all sign under
the approval from ceremony 3, whose scope is this package's declared routes
and operation classes, bounded at 256 operations and 256 signatures and
expiring with the scoped key. It carries no monetary limit of its own —
what a given transaction may spend is bounded by wallet policy, by the
key's scope, and by the Petal's own transaction checks.

Ceremonies 3 and 4 both have to follow 2, because neither the key nor its
address exists until the derive ceremony has completed.

Reducing this further means widening what a single approval authorizes.
That is tracked in `bloom-directory/bloom#171`; do not assume it has landed.

## Session lifetime

The session's `expires_ms` is `now + duration_ms`, measured when the derive
returned `Ready`. It is the lifetime this Petal asked for, not the Signer's
view of the grant: the pinned SDK's `PetalKeyOutcome::Ready` carries no
expiry, so the Petal cannot read the authoritative one. If a ceremony sat
waiting for a while, the real scope is older than the recorded deadline.

Treat the recorded deadline as an estimate, and read the authoritative one
before funding. It is not hidden: when Bloom prepares the session's reusable
approval it sets that approval's `expires_at_ms` to the Signer's scoped-key
expiry exactly, and refuses to prepare at all if the scope has already
lapsed. **So the expiry shown on the ceremony in step 3, and on the approval
afterwards, is the Signer's own deadline** — not the Petal's estimate. Read
it there, compare it against the Petal's `expires_ms`, and use the earlier of
the two.

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
| `simulation_failed` | the simulated transaction failed before any broadcast | rebuilds with a fresh blockhash |
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
   bloom policy read main
   ```
2. If the address is absent, there is nothing to do.
3. Otherwise prepare an updated policy that omits it, and run
   `bloom policy update main --file policy.json --assurance user_verified`.
4. Complete the passkey ceremony; the new policy lands on commit.
5. Verify with `bloom policy read main` that the address is gone.

Fold this into the next policy update the session needs rather than
spending a ceremony on it alone.
