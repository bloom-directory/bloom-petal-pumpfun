# Pump.fun Petal — operational notes

## Setup flow

The Petal does not own session-key custody. Every key it uses is derived
through `petal::sdk::derive_key`, which returns either `Pending` (the
Broker must run a passkey ceremony) or `Ready` (the ceremony completed
and the key reference is bound to the wallet).

A complete setup looks like:

1. `GET sessions/<wallet>/preflight.json` — verify connectivity, RPC
   genesis, builder reachability, and that the operator has updated the
   wallet policy to include the future session address. The Petal cannot
   query the host wallet policy from inside the sandbox, so this is a
   reminder, not an enforcement.
2. `POST sessions/<wallet>/new.json {id, duration_ms}` — derive the
   session key. The Petal returns `approval required: {...}` with an
   `operation_id` and `scope_digest`.
3. The operator opens the ceremony URL in Chromium and completes the
   passkey flow. The Petal's `derive_key` will then return `Ready` with
   the session address.
4. The operator funds the session address from the wallet that owns the
   `allowed_petal_packages` permission. The amount should equal the
   `max_balance_lamports` declared in the canary authorization, which is
   bounded at 10,000,000 lamports (0.01 SOL).
5. `POST sessions/<wallet>/sessions/<session>/buy.json {operationId,
   mint, amount, slippage, ...}` — stage the bounded buy. The public
   operation projection includes `message_sha256`; the reviewed canary
   authorization must name that exact digest before the retry can broadcast.
   The first canary does not authorize sell, close, or sweep.

## Approval → broadcast continuation

The Petal's `execute()` function is idempotent. When called with an
existing `operationId`:

1. It loads the existing pending transaction from the store.
2. If the staged digest matches, it picks up where it left off —
   signing, simulating, or broadcasting depending on the existing
   pending status.
3. If the existing pending has a different digest, the operation is
   refused as "operationId already bound".

After the passkey ceremony completes, retrying the same `operationId`
continues through signing, simulation, and broadcast. The canary Machine
still refuses the network write until its exact-message authorization is
present; an ordinary Machine always refuses a Petal `sendTransaction`.

The single status the operator must read from the response body is
`status`. The valid values are:

| Status | Meaning |
| --- | --- |
| `approval_pending` | Passkey ceremony still required; `action_id` is in the response |
| `simulation_failed` | The simulated transaction failed; restage with new `operationId` |
| `approval_failed` | The signing ceremony refused the message |
| `broadcast_attempted` | The transaction was sent; reconciliation is in progress |
| `submitted` | The RPC returned the signature we sent |
| `confirmed` / `finalized` | The cluster observed the transaction |
| `chain_failed` | The transaction failed on-chain; reconciliation is in progress |

The session-key ceremony and the independently reviewed per-transaction
canary authorization are separate gates.

## Obsolete destination cleanup

The handoff v1 reported that a previous session address
(`9pcUafcrPCajWf8LD8YqJ13zxKEDbufpsaJAUR2dhPRC`) was added to the
`main` wallet's Solana allowed destinations. To remove it:

1. Read the current policy:
   ```sh
   bloom policy read main
   ```
2. Prepare an updated policy that omits that address.
3. Run `bloom policy update main --file policy.json --assurance user_verified`
   to create a new policy-update ceremony.
4. Complete the passkey ceremony; the new policy lands on commit.
5. Verify with `bloom policy read main` that the address is gone.

This is a separate passkey ceremony and is the only remaining operator
action after the buy → sell → close cycle.
