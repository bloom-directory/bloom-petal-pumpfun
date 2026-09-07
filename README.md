# Pump.fun Petal

A mainnet Pump.fun integration for Bloom. It reads coin state, creates coins,
buys and sells through Pump's automatic bonding-curve/PumpSwap routing,
collects creator fees or cashback, and creates or updates fee-sharing configs.

Writes use a short-lived Ed25519 key derived and held by Bloom. Fund the public
`address` returned by `session.json`; the owner's root key never reaches Pump.
Every write requires a caller-selected `operationId`. Bloom binds that id to the
canonical request, stores unsigned/signed transaction material only in the
secret namespace, simulates before sending, and never retries after recording a
broadcast attempt. Read `operations/<operationId>.json` for durable build,
approval, broadcast, confirmation, failure, and finalization status. A failed
pre-broadcast simulation can be retried with the same request and operation ID;
the Petal rebuilds it with a fresh blockhash. After the user approves an action,
Bloom may reuse that one-shot approval only when the independently parsed
transaction template is unchanged and the recent blockhash is the sole changed
message field. Any other change is rejected. Operation projections publish the
request-intent digest, exact message digest, and blockhash-normalized message
template digest for a canary-capable Machine to verify independently.

Pump's builder and the public RPC are treated as untrusted input: only Solana v0 transactions with
the session key as fee payer, the requested mint, valid signer-slot shape, and
an allowlist of official Pump, PumpSwap, Pump Fees, Agent Payments, SPL Token,
Associated Token, System, and Compute Budget programs are eligible to sign.
Address lookup tables are resolved independently through Solana RPC before
their accounts are checked. Swap requests include a caller-selected
`minOutputAmount`; the on-chain instruction must preserve at least that many
raw output units. Bloom also applies a local base and priority fee floor and
requires an explicit successful simulation result before broadcast.

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
sessions/<wallet>/sessions/<session>/stop
```

## Build and test

The route components target WASI Preview 2. Build them with the repository
script, then run the architecture and Rust tests:

```sh
./scripts/build.sh
./scripts/check-route-architecture.sh
cargo test
```

Install a reviewed package archive into a running Bloom instance:

```sh
bloom petals install ./bloom-petal-pumpfun.petal.tar
```

Pump.fun writes target Solana mainnet. Keep the Petal package, wallet policy,
session key, transaction caps, and Bloom's mainnet-canary authorization bound to
the exact reviewed release before funding a session.

## Session workflow

Create a session by writing `{"id":"agent-1","duration_ms":3600000}` to
`new.json`, then fund the `address` exposed by its `session.json`. Create bodies
require `name`, `symbol`, `uri`, positive decimal-string `solLamports`, and a
positive decimal-string `minOutputAmount`. Buy and sell bodies require `mint`,
a positive decimal-string `amount`, and `minOutputAmount` in raw output units.
Fee collection requires `mint` plus `feeKind` set to `cashback`, `creator`, or
`sharing_distribution`; sharing changes also require 1–10 distinct
`shareholders` whose integer `bps` values total 10,000. Every action body also
requires `operationId`.

Before stopping a session, sell any remaining token balance. Then write
`{"operationId":"close-1","mint":"<mint>","tokenAccount":"<session token account>","destination":"<owner Solana address>","maxLamports":"2100000"}`
to `close_token_account.json`. The Petal independently verifies through two
RPCs that the account belongs to the session, holds the requested mint, has no
conflicting close authority, contains zero tokens, and holds no more than the
declared `maxLamports`. It then builds one exact SPL Token `CloseAccount`
instruction to return that native balance. Finally write
`{"operationId":"return-1","destination":"<owner Solana address>"}` to
`sweep.json`. The Petal builds one exact System transfer for the full native
SOL balance minus the quoted fee. Sweep while the session scope is still
active; expired signing scopes cannot recover assets.
