# Pump.fun Petal

A mainnet Pump.fun integration for Bloom. It reads coin state, creates coins,
buys and sells through Pump's automatic bonding-curve/PumpSwap routing,
collects creator fees or cashback, and creates or updates fee-sharing configs.

Writes use a short-lived Ed25519 key derived and held by Bloom. Fund the public
`address` returned by `session.json`; the owner's root key never reaches Pump.

## How a write is authorized

Deriving the session key provisions one reusable Bloom approval for that key.
Its scope is the routes and operation classes this package declares, and it
expires with the key. Every later write — buy, sell, close, sweep — signs under
that one approval and asks the owner for nothing further. What each individual
transaction is allowed to do is decided by the checks below, by wallet policy,
and by the key's own scope, not by a per-transaction approval.

Wallet policy is a real gate and covers more than the funding address: every
destination a write declares — the Pump protocol program it routes through,
the return address for `close_token_account` and `sweep`, a Jito tip when one
is selected — is checked against the wallet's allowed destinations. `SETUP.md`
lists all of them, and what the owner is actually prompted for.

## Operations and retries

Every write requires a caller-selected `operationId`. Bloom binds that id to the
canonical request, stores unsigned and signed transaction material only in the
secret namespace, simulates the unsigned transaction before signing, and records the intent to broadcast
before broadcasting. Read `operations/<operationId>.json` for durable build,
approval, broadcast, confirmation, failure and finalization status.

Retrying means writing the identical request under the same `operationId`.
The same id with different content — a different amount, mint or destination —
is refused as `operationId already bound`, so a retry can never quietly become
a different payment. What a retry does depends on where the operation stopped:

- `preflight_failed` or `approval_failed` — nothing was signed that anyone
  could still broadcast, so the Petal rebuilds the transaction with a fresh
  blockhash and tries again under the same economic intent.
- `signing_uncertain` — signing returned no answer and may already have
  produced a signature. The Petal keeps that exact message and its approval and
  re-enters signing, so the retry reconciles the same signature rather than
  authorizing a second payment.
- `simulation_failed` — written only by earlier versions, which sent the signed
  transaction to an RPC to simulate it; that transaction may still land. The
  Petal never rebuilds it and only signs the stored message again.
- `approval_pending` — the owner has not answered yet. The Petal refreshes the
  transaction but keeps the same approval, so waiting does not accumulate
  ceremonies.
- `broadcast_attempted`, `submitted`, `confirmed`, `finalized`, `chain_failed` —
  the attempt is already recorded. A retry reports it and never re-broadcasts.

`broadcast_attempted` means the outcome is genuinely unknown: the transaction
was signed and sent, and no acknowledgement came back. Read the recorded
`signature` against the cluster to settle it. The Petal will not rebuild that
operation, because doing so could pay twice.

Pump's builder and the public RPC are treated as untrusted input: only Solana v0 transactions with
the session key as fee payer, the requested mint, valid signer-slot shape, and
an allowlist of official Pump, PumpSwap, Pump Fees, Agent Payments, SPL Token,
Associated Token, System, and Compute Budget programs are eligible to sign.
Address lookup tables are resolved independently through Solana RPC before
their accounts are checked. Swap requests include a caller-selected
`minOutputAmount`; the on-chain instruction must preserve at least that many
raw output units. The token accounts a trade receives into or spends from must
be the session's own associated token accounts, and PumpSwap trades must use the
coin's canonical pool; both are derived locally, not taken from the builder.
Bloom also applies a local base and priority fee floor and requires an explicit
successful simulation result before signing.

Optional request fields follow Pump's official agent API: `mayhemMode`,
`cashback`, `tokenizedAgent`, `buybackBps`, `slippagePct`,
`frontRunningProtection`, and `tipAmount`. Protected writes are sent only to
Jito; ordinary writes use the declared public Solana RPC.

The route tree is:

```text
status.json
coins/<mint>.json
sessions/<wallet>/new.json
sessions/<wallet>/sessions/<session>/session.json
sessions/<wallet>/sessions/<session>/{create,buy,sell,collect_fees,sharing_config,close_token_account,sweep}.json
sessions/<wallet>/sessions/<session>/operations/<operationId>.json
(no local stop leaf: stopping a session is Bloom's core
wallets/<w>/<n>/sessions/pumpfun/<key-slot>/stop write)
```

## Build and test

The route components target WASI Preview 2. Build them with the repository
script, then run the architecture and Rust tests:

```sh
./scripts/build.sh
./scripts/check-route-architecture.sh
cargo test --manifest-path route/Cargo.toml --locked
```

There is no Cargo workspace at the repository root, so a bare `cargo test` here
finds no manifest; the route crate has to be named explicitly.

The route tests run against a recording fake Bloom host (`route/src/fake_host.rs`),
so they exercise the requests a write actually makes — builder quote, signing,
simulation, broadcast — and not just the pure validators.

Install a reviewed package archive into a running Bloom instance:

```sh
bloom petals install ./bloom-petal-pumpfun.petal.tar
```

Pump.fun writes target Solana mainnet. Keep the Petal package, wallet policy,
session key and transaction caps bound to the exact reviewed release before
funding a session.

## Session workflow

Create a session by writing `id`, `duration_ms`, `max_lamports`, and optional
`token_limits` to `new.json`, then fund the `address` exposed by `session.json`.
`max_lamports` is a positive decimal string for cumulative native debits and
fees, including the exit. `token_limits` maps each mint the session may sell
to its cumulative raw-token debit ceiling. See [SETUP.md](SETUP.md) before
choosing these budgets; they are sealed by the reusable approval ceremony.
Create bodies
require `name`, `symbol`, `uri`, positive decimal-string `solLamports`, and a
positive decimal-string `minOutputAmount`. Buy and sell bodies require `mint`,
a positive decimal-string `amount`, and `minOutputAmount` in raw output units.
Fee collection requires `mint` plus `feeKind` set to `cashback`, `creator`, or
`sharing_distribution`; sharing changes also require 1–10 distinct
`shareholders` whose integer `bps` values total 10,000. Every action body also
requires `operationId`.

Stopping a session is Bloom's core control, not a Petal route: writing to
`wallets/<w>/<n>/sessions/pumpfun/<key-slot>/stop` revokes the session's
approvals by key through the Broker, and the local `stop` leaf is gone.
This Petal is `[account] aware`: it also runs under
`wallets/<wallet>/<n>/petals/pumpfun/…`. Sessions are scoped by account
number: the flat mount and account 0 are the same owner and share one set of
sessions, while each numbered account `n > 0` has its own records and hashes
`n` into its derived key slot, so the same session id on accounts 1 and 2
yields two sessions with two keys.
Before stopping a session, sell any remaining token balance. Then write
`{"operationId":"close-1","mint":"<mint>","tokenAccount":"<session token account>","destination":"<owner Solana address>","maxLamports":"2100000"}`
to `close_token_account.json`. The Petal independently verifies through two
RPCs that the account belongs to the session, holds the requested mint, has no
conflicting close authority, contains zero tokens, and holds no more than the
declared `maxLamports`. It then builds one exact SPL Token `CloseAccount`
instruction to return that native balance. Finally write
`{"operationId":"return-1","destination":"<owner Solana address>"}` to
`sweep.json`. The Petal builds one exact System transfer for the full native
SOL balance minus the quoted fee. `close_token_account.json` and `sweep.json`
remain usable after the session is stopped or expired so remaining assets can
be recovered; they sign with an exact owner approval that does not depend on
the session's reusable signing scope.
