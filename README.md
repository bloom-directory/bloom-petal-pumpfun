# Pump.fun Petal

A mainnet Pump.fun integration for Bloom. It reads coin state, buys and sells
existing coins through Pump's automatic bonding-curve/PumpSwap routing,
collects creator fees or cashback, and creates or updates fee-sharing configs.

Writes use a short-lived Ed25519 key derived and held by Bloom. Fund the public
`address` returned by `session.json`; the owner's root key never reaches Pump.

## What this release supports

The supported flow is one session over an existing coin:

`create session → review address and budgets → approve → fund → buy → sell →
stop → close token accounts → sweep remaining SOL`

**Coin creation is not supported in this release.** The `create.json` route and
its recipient and pool checks are present and still enforced, but the route has
never been run against Pump's real create program, so treat it as unverified:
do not use it, and do not rely on it working. Creation acceptance is tracked in
[PM #33](https://github.com/bloom-directory/pm/issues/33). Everything below that
mentions `create` describes the route as built, not as verified.

## How a write is authorized

Trading writes — buy, sell, collect_fees, sharing_config, and the unsupported
create — sign under
one reusable Bloom approval for the session key. The owner approves it once,
with the session's budgets, after admitting the session address to the wallet
policy. It covers only this package's declared routes and operation classes and
ends no later than the key. What each trading transaction may do is decided by
the checks below, the budgets, wallet policy, and the key's scope.

Recovery writes — `close_token_account` and `sweep` — each need the owner's
approval for that exact transaction, separate from the trading budgets. They
still work after the session is stopped or expired.

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

- `approval_failed` or `preflight_failed` — if no signing call could have
  produced a signature for this transaction, the Petal rebuilds it with a fresh
  blockhash under the same economic intent.
- `signing`, `signing_uncertain`, or the earlier versions' `simulation_failed` —
  a signature may exist. From then on the operation is never rebuilt, whatever
  later attempts report: every retry signs the same transaction again, which can
  only reproduce it. If it can no longer land, confirm on the cluster that it did
  not before using a new `operationId`.
- `approval_pending` — the owner has not answered yet. A trading approval does
  not bind the transaction, so the Petal refreshes it while waiting. A close or
  sweep approval binds the exact transaction, so it is kept, even through a failed
  simulation. Only once its blockhash has expired (the finalized block height
  passes its last valid height, about a minute) does a retry drop that approval,
  rebuild, and ask for a new one.
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
`max_lamports` is a positive decimal string for the cumulative native debits and
fees of trading writes. `token_limits` maps each mint the session may sell
to its cumulative raw-token debit ceiling. See [SETUP.md](SETUP.md) before
choosing these budgets; they are sealed into the trading approval, and close and
sweep are approved separately.
Create bodies — for the unsupported `create.json` route —
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
Before calling the builder, a trade asks Bloom whether the session is still
authorized and refuses a stopped, expired, or exhausted session; the Broker
refuses its signature regardless.
Bloom mounts Petals only at `petals/`, so sessions belong to account 0 of the
wallet in the path. The `[account] aware` declaration has no effect on current
Bloom, which no longer mounts Petals under `wallets/<wallet>/<n>/`.
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
be recovered; each transaction asks the owner for its own exact approval.

## Compatibility

This package needs Bloom with `[sign].fee_asset` (bloom#276), bounded session
keys (bloom#302) and Exact signing with the session key (bloom#304). No Bloom
release includes them yet, and Bloom v0.3.0 refuses to install this package.
See `SETUP.md`.
