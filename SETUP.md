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

4. Add the session address to the wallet's Solana allowed destinations and
   complete that policy ceremony. Funding a Petal-controlled derived key is
   a transfer to a destination the wallet has not approved, and Bloom
   refuses it until policy names the address. A shared seed does not make
   this unnecessary: `bloom-broker#40` proposed exempting a wallet's own
   derived accounts and was closed for that reason. The address cannot be
   added before step 3, because the derivation index is allocated inside
   the derive ceremony.

5. Fund the session address from the owner wallet, and approve that
   transfer. Fund only what the cycle needs — the buy, plus the network and
   priority fees for four transactions, plus rent for any token account the
   buy creates — and only when the key's remaining lifetime comfortably
   covers buying, selling, closing the token account and sweeping.

6. `POST sessions/<wallet>/sessions/<session>/buy.json {operationId, mint,
   amount, minOutputAmount, ...}` — stage and run the buy. No further
   ceremony: it signs under the reusable approval from step 3.

## What the owner is prompted for

Running one bounded session end to end costs five passkey ceremonies, and
four of those are setup:

| # | Ceremony | What the owner is deciding |
| --- | --- | --- |
| 1 | package eligibility | allow this Petal package version (once per version, not per session) |
| 2 | `KeyDerive` | mint the session key, with its routes, operation classes and lifetime |
| 3 | `SealedApproval` | activate the session's reusable approval for that key |
| 4 | `PolicyUpdate` | allow the wallet to send to the session address |
| 5 | `SealedApproval` | the funding transfer, for an exact amount |

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

Treat the recorded deadline as an estimate and check the host's view before
funding. Sell, close and sweep while the scope is still live. An expired
scoped key cannot sign, and there is no recovery path that gets assets out
of a session whose key has expired — so do not fund a session that does not
have time left for the whole cycle.

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
