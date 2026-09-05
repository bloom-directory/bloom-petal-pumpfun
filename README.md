# Pump.fun Petal

A mainnet Pump.fun integration for Bloom. It reads coin state, creates coins,
buys and sells through Pump's automatic bonding-curve/PumpSwap routing,
collects creator fees or cashback, and creates or updates fee-sharing configs.

Writes use a short-lived Ed25519 key derived and held by Bloom. Fund the public
`address` returned by `session.json`; the owner's root key never reaches Pump.
Every write requires a caller-selected `operationId`. Bloom binds that id to the
canonical request, stores unsigned/signed transaction material only in the
secret namespace, simulates before sending, and never retries after recording a
broadcast attempt. Read `operations/<operationId>.json` for public status.

Pump's builder is treated as untrusted input: only Solana v0 transactions with
the session key as fee payer, the requested mint, valid signer-slot shape, and
an allowlist of official Pump, PumpSwap, Pump Fees, Agent Payments, SPL Token,
Associated Token, System, and Compute Budget programs are eligible to sign.

Optional request fields follow Pump's official agent API: `mayhemMode`,
`cashback`, `tokenizedAgent`, `buybackBps`, `slippagePct`,
`frontRunningProtection`, and `tipAmount`. Protected writes are sent only to
Jito; ordinary writes use the declared public Solana RPC.
