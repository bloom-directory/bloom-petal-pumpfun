# Pump.fun Petal

A mainnet Pump.fun integration for Bloom. It reads coin state and buys or sells
existing coins through Pump's automatic bonding-curve/PumpSwap routing.

Every write is one transaction the owner approves in Bloom, signed with the key
of the Bloom account they already selected. There is **no session key, no
separate wallet, no funding transfer and no spending budget.** An agent can
propose a trade; only the owner can authorize one, and they authorize the exact
transaction they are shown.

Coin creation, fee collection and fee-sharing configuration are not part of this
release. Their routes are gone, not merely disabled. Creation acceptance is
tracked in [PM #33](https://github.com/bloom-directory/pm/issues/33).

## What a write costs

One Bloom ceremony per transaction. A buy and a later sell are two, because the
amount to sell is only known once the buy settles. Closing an empty token
account is a third.

What the owner sees before approving comes from the transaction itself, read
back out of the bytes that were just validated: the trading account, the token,
the maximum spent (or the amount sold), **the minimum output the instruction
itself guarantees**, the network fee, any rent for new token accounts, any Jito
tip, and for a buy the worst-case total. These figures are the Petal's and are
labelled as such — Bloom does not independently re-derive them.

## Route tree

```text
status.json
coins/<mint>.json
trade/<wallet>/preflight.json
trade/<wallet>/{buy,sell,close_token_account}.json
trade/<wallet>/operations/<operationId>.json
```

Bloom mounts Petals only at `petals/`, so `<wallet>` is the wallet id in the
path and the account is the one Bloom injects — account 0 on current Bloom.
Operation records are scoped by both, so one operation id used on two accounts
is two unrelated operations.

## How a transaction is checked

Pump's builder and the public RPC are treated as untrusted input. Only a Solana
v0 transaction with the trading account as fee payer, the requested mint, valid
signer-slot shape, and an allowlist of the official Pump, PumpSwap, SPL Token,
Token-2022, Associated Token, System and Compute Budget programs is eligible to
sign. Address lookup tables are resolved independently through two Solana RPCs
before their accounts are checked.

Swap requests carry a caller-selected `minOutputAmount`, and the on-chain
instruction must preserve at least that many raw output units. The token
accounts a trade receives into or spends from must be the trading account's own
associated token accounts, and PumpSwap trades must use the coin's canonical
pool; both are derived locally, never taken from the builder. Bloom applies a
local base and priority fee floor and requires an explicit successful simulation
of the unsigned transaction before signing.

Optional request fields follow Pump's official agent API: `slippagePct`,
`frontRunningProtection` and `tipAmount`. Protected writes are sent only to
Jito; ordinary writes use the declared public Solana RPC and fall back to the
second RPC once. Protection is routing, not a guarantee.

## Closing an empty token account

Buying a coin creates an associated token account, and its rent is real money.
Write `{"operationId":"close-1","mint":"<mint>","tokenAccount":"<account>",
"maxLamports":"2100000"}` to `close_token_account.json` after selling the
balance. The Petal verifies through two independent RPCs that the account
belongs to the trading account, holds the requested mint, has no conflicting
close authority, contains zero tokens, and holds no more than the declared
`maxLamports`. It then builds one exact SPL Token `CloseAccount`.

There is no destination parameter. The rent returns to the same account that
owns the token account and signs the transaction, because that account is the
only destination the message can name.

## Operations and retries

Every write requires a caller-selected `operationId`, bound to the canonical
request and the trading account. The same id with different content — a
different amount, mint or account — is refused as `operationId already bound`,
so a retry can never quietly become a different payment.

Unsigned and signed transaction material is stored only in the secret namespace.
The unsigned transaction is simulated before signing, and the intent to
broadcast is recorded before broadcasting. Read
`operations/<operationId>.json` for durable build, approval, broadcast,
confirmation, failure and finalization status, and for the review the owner was
shown.

Retrying means writing the identical request under the same `operationId`. What
it does depends on where the operation stopped:

- `approval_pending` — the owner has not answered. The approval binds these
  exact bytes and this exact review, so the transaction is kept, even through a
  failed simulation. Only once its blockhash has expired — the finalized block
  height passes its last valid height, about a minute — does a retry drop the
  approval, rebuild, and ask for a new one covering the new bytes.
- `approval_failed` or `preflight_failed` — if no signing call could have
  produced a signature, the Petal rebuilds with a fresh blockhash under the same
  economic intent.
- `signing` or `signing_uncertain` — a signature may exist. From then on the
  operation is never rebuilt, whatever later attempts report: every retry signs
  the same transaction again, which can only reproduce it. If it can no longer
  land, confirm on the cluster that it did not before using a new `operationId`.
- `broadcast_attempted`, `submitted`, `confirmed`, `finalized`, `chain_failed` —
  the attempt is recorded. A retry reports it and never re-broadcasts.

`broadcast_attempted` means the outcome is genuinely unknown: the transaction
was signed and sent, and no acknowledgement came back. Read the recorded
`signature` against the cluster to settle it.

## Build and test

The route components target WASI Preview 2. Build them with the repository
script, then run the architecture and Rust checks:

```sh
./scripts/build.sh
./scripts/check-route-architecture.sh
cargo fmt --manifest-path route/Cargo.toml -- --check
cargo clippy --manifest-path route/Cargo.toml --all-targets --locked -- -D warnings
cargo test --manifest-path route/Cargo.toml --locked
```

There is no Cargo workspace at the repository root, so a bare `cargo test` here
finds no manifest; the route crate has to be named explicitly.

The route tests run against a recording fake Bloom host
(`route/src/fake_host.rs`), so they exercise the requests a write actually makes
— builder quote, signing, simulation, broadcast — and not just the pure
validators. The fake host signs with a real Ed25519 key whose public key is the
payer in `route/tests/pump-builder-fixtures.json`, so a test drives a signature
that genuinely belongs to the trading account.

Install a reviewed package archive into a running Bloom instance:

```sh
bloom petals install ./bloom-petal-pumpfun.petal.tar
```

Pump.fun writes target Solana mainnet. Keep the Petal package, wallet policy and
the selected account bound to the exact reviewed release before trading.

## Compatibility

This package needs Bloom with `[sign].fee_asset` (bloom#276) and, for the
ceremony to display the review above rather than an opaque digest, the review
transport described in `SETUP.md`. It does **not** need bounded session keys
(bloom#302) or session-key Exact signing (bloom#304); those cover a delegation
model this Petal no longer uses.
