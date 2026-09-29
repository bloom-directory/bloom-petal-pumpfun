# Pump.fun Petal

A mainnet Pump.fun integration for Bloom. It reads coin state and risks,
charts coins, buys or sells them through Pump's automatic
bonding-curve/PumpSwap routing, and launches new ones. It trades only coins
priced in SOL; Pump's program refuses to trade a coin whose curve is priced in
another token for SOL, and the coin summary says which token that is.

Every write is one operation the owner approves in Bloom, signed with the key
of the Bloom account they already selected. There is **no session key, no
separate wallet, no funding transfer and no standing budget.** An agent can
propose a trade; only the owner can authorize one. The approval covers one
operation of that kind, capped at the SOL ceiling the ceremony shows: the
requested amount plus slippage, rent for every account the trade creates, tip
and the network fee cap. After
the owner approves, the Petal rebuilds the transaction with a fresh blockhash
and signs it under that approval, because a blockhash lives about a minute and
a ceremony can take most of it. The approval is scoped to this package, route,
account and kind of trade, and capped in SOL; it does not name the coin.

Fee collection and fee-sharing configuration are not part of this release.
Their routes are gone, not merely disabled.

## What a write costs

One Bloom ceremony per transaction. A buy and a later sell are two, because the
amount to sell is only known once the buy settles. Closing an empty token
account is a third.

What the owner sees before approving comes from the transaction itself, read
back out of the bytes that were just validated: the trading account, the token,
**the maximum the trade can spend** (or, for a sell, the amount sold and the
least SOL the instruction may return), the tokens a buy names, the network fee,
rent for every account the trade creates, any Jito tip, and for a buy the
worst-case total. These figures are the Petal's and are labelled as such —
Bloom does not independently re-derive them.

Rent is measured, not estimated. Pump's program creates accounts the builder's
instructions never mention — a first buy also opens a per-user volume-rewards
account, about 0.00135 SOL — so the Petal asks which of the trade's writable
accounts do not exist yet and simulates the transaction to see what each would
hold. The last simulation before signing also reads the trading account's
balance afterwards, and a transaction that would take more SOL than the claim
declares is refused unsigned.

A sell's floor — the least SOL it may return — is the builder's figure, and the
program enforces only that. The Petal prices every sell itself from the
bonding curve's or the pool's reserves on chain and refuses a floor below that
price less 2% for Pump's fees (measured at 1.25% on the curve and 0.85% on
PumpSwap) and the requested slippage.

## Reading it

Every data file has a JSON form for agents, and the files people read have two
more:

- **In a terminal**, `.md` files are laid out to read raw: padded tables, a
  block chart of the market cap, a checklist of risks, the latest trades, and
  the command that trades the coin. `bloom vfs cat /petals/pumpfun/coins/live.md`.
- **In a browser**, `.html` pages open from the mounted folder and link to one
  another: `index.html` (the newest coins) → a coin's page → back. They follow
  the system's light or dark theme, work at phone width, and are
  self-contained: each carries a Content-Security-Policy that allows no network
  access except coin thumbnails from Pump's image service, requested by mint.
  The creator's own image link is never loaded.

```text
index.html                                  newest coins, for a browser
coins/{latest,live}.{md,html,json}          25 coins each
coins/<mint>.{md,html,json}                 price, chart, risks, trades
market/<mint>/{candles,trades}.json         the chart and trades as data
trade/<wallet>/holdings.{md,html,json}      what the account holds, and its worth
trade/<wallet>/{buy,sell,launch,close_token_account}.json
trade/<wallet>/{limit,order_slot,cancel_order,check_orders}.json, orders.json
trade/<wallet>/preflight.json
trade/<wallet>/operations/<operationId>.json
status.json
```

`coins/<mint>.json` is a safety summary rather than Pump's raw record: the
price, market cap and curve progress read from the chain now, whether the coin
has graduated, its age and creator, plain warnings, and a `risk` block. Only
`https://` links are kept, and the creator's description is not passed through.

| `risk` field | Source | Warns when |
|---|---|---|
| `creatorHoldsPct` | the creator's associated token accounts, on chain | 5% or more: tokens they can sell into buyers |
| `creatorBoughtAtLaunchPct` | the creation block's transactions | the creator now holds less than half of it |
| `launchBlockBuyers`, `launchBlockBoughtPct` | other fee payers in the creation block | they bought 10% or more, which is how a bundled launch looks |
| `top10HoldPct`, `holders` | Pump's holder index, less the curve and pool | the ten largest own 30% or more |
| `creatorOtherCoins`, `creatorGraduatedCoins` | Pump's listing filtered by creator | five or more other coins and none graduated |
| `mintAuthority`, `freezeAuthority`, `tokenExtensions` | the mint account, on chain | anyone can mint or freeze, or the mint has an extension Pump coins lack |
| `belowAllTimeHighPct` | Pump's market caps | 50% or more below the high |

Each check is best effort; one that could not be made is named in
`risk.unchecked` and the rest still report. The creation block is read only
while the coin is on its curve and its curve has fewer than 1,000 transactions,
at most six of them; `launchBlockPartial` says the block held more. Pump's own
sniper and bundler flags and third-party risk scores are not used: on a coin
rugged within 20 seconds of launch, both called it clean.

`market/<mint>/candles.json` has up to 120 price candles in SOL per token: one
second each for a coin under two minutes old, one minute each for a coin under
two hours old, five minutes under ten hours, and an hour after that.
`trades.json` lists the latest 50 trades, with the wallet, side, SOL, tokens,
venue and transaction, and tallies buying against selling. Both come from Pump's
trade index at `swap-api.pump.fun`; a coin's `.md` and `.html` pages draw the
candles as its market cap, on a log scale once the range passes twentyfold.

`coins/latest.json` lists the newest launches and `coins/live.json` the coins whose
creator is streaming, up to 25 each, without banned or NSFW coins. Names and
symbols are the creator's own text, not unique, and cleaned of control and
direction-changing characters: trade by mint, after reading `coins/<mint>.json`.

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
instruction must preserve at least that many raw output units. That is a check
on the builder, not a control: the builder sets the amount the instruction
names. The token accounts a trade receives into or spends from must be the
trading account's own
associated token accounts, and PumpSwap trades must use the coin's canonical
pool; both are derived locally, never taken from the builder. Bloom applies a
local base and priority fee floor and requires an explicit successful simulation
of the unsigned transaction before signing.

Optional request fields follow Pump's official agent API: `slippagePct`,
`frontRunningProtection` and `tipAmount`. A Pump buy instruction names a token
amount and a ceiling on the SOL in, and in every measured case `slippagePct`
raised only that ceiling: the tolerance is on what the trade spends.
`slippagePct` defaults to 1 and may not exceed 5. Slippage is what a sandwich
or a sudden move can take. Measured on 27 September 2026 over 2-second
windows, about how long a trade waits once approved, a wider tolerance buys
few fills: on young coins the price either held or jumped 20% or more, so 1%
failed 18% of the time and 10% still failed 15%; on larger curve coins 2%
failed 20% and 5% failed 11%. A failed trade costs about 0.00013 SOL and a
retry rebuilds at the new price.

Swaps are protected by default. The builder adds Jito's don't-front account
and a 0.00001 SOL tip (above the median landed tip), and the transaction is
sent through Jito's block engine, which rejects any bundle that places a
transaction ahead of it — how most sandwiches are built. It does not stop a
validator outside Jito from reordering. `"frontRunningProtection":false` sends
through the public RPC instead. `minOutputAmount` is optional: the Petal
prices every sell against the chain and caps every buy's spend, and a floor
the caller names is still enforced.

Pump's builder always asks for about 0.001 SOL of priority, whatever the trade
size. Unless the request sets `"priorityFee":"builder"`, the Petal lowers the
compute-unit price to the 90th percentile of what recent slots charged for the
trade's own writable accounts, never below 100,000 micro-lamports per unit and
never above the builder's price. Only those price bytes change. The approval
and review still cap the fee at the builder's price, so a rebuild after the
ceremony that meets a busier market stays inside what the owner approved.
`SETUP.md` has the measurements, and their limits.

Protected writes are sent only to Jito; ordinary writes use the declared public
Solana RPC and fall back to the second RPC once. Protection is routing, not a
guarantee.

## Holdings and selling everything

`trade/<wallet>/holdings.json` lists every token account the trading account
holds under both token programs: mint, raw and display amount, rent, whether
it is empty, and for a Pump coin what selling the whole position returns at
the current curve or pool price, before Pump's fee and slippage.

A sell may name `"amount":"all"`, or a whole percentage such as `"50%"`,
which sells that share of the balance rounded down and leaves the account
open. When the transaction is built, the Petal
reads the balance of the trading account's own associated token account for
the mint, asks the builder to sell exactly that, and appends a `CloseAccount`
for the emptied account, so its rent returns in the same transaction and the
same approval. The operation id binds `"all"`; the resolved amount is what
the claim declares and the review shows.

## Launching a coin

Write to `trade/<wallet>/launch.json`:

```json
{"operationId":"launch-1","name":"My Coin","symbol":"MYC","amount":"10000000",
 "image":"<base64 PNG, JPEG, GIF or WebP, at most 512 KiB>",
 "description":"optional","twitter":"https://…","telegram":"https://…","website":"https://…"}
```

or name metadata you already host with `"uri":"https://…"` in place of the
image, description and links. The selected account pays and becomes the
coin's creator, so Pump's creator fees go to it. `amount` is the first buy in
lamports; Pump requires one, and it happens in the same transaction the curve
is created in, at the opening price, so nothing can trade ahead of it.

An image is pinned to IPFS with the metadata through Pump's own upload, the
way pump.fun does it, when the launch is first built and before the owner
approves; the rebuild after approval names the same metadata. That upload is
public even if the launch is never approved.

Pump's builder makes the transaction and signs it with a mint key it draws for
the new coin. The Petal checks it as built: two signers, the trading account
paying, the mint's signature valid over the exact message, and only
`create_v2` for the requested name, symbol and metadata with the trading
account as creator and Mayhem mode, cashback, creator fee and holder rewards
off, the creator's token account, and one buy of the new coin within 1% of
`amount`. Any change to the bytes would void the mint's signature, so a launch
pays the builder's priority fee (about 0.001 SOL) and goes through the public
RPC; Jito protects nothing here. The mint key has no power once the coin
exists, because the mint is created with no mint or freeze authority.

The review shows the name, symbol, metadata, first buy, network fee, measured
rent (0.0087 SOL for the mint, curve and accounts, simulated on 29 September
2026) and total; a launch with a 0.001 SOL first buy came to 0.0097 SOL. Each rebuild
draws a new mint, so the coin's address is the one in the signed transaction:
read `operations/<operationId>.json`, `api.mintPublicKey`.

## Limit orders

A limit buy fills only while the market cap is at or below a level; a limit
sell (take-profit) only once it is at or above one. You approve an order once,
when you place it, and it stays valid until it fills or you cancel it.

```sh
# once: an order slot, a nonce account the trading account owns (0.00106 SOL rent)
echo '{"operationId":"slot-0","slot":0}' > trade/<wallet>/order_slot.json
# place: buy 0.05 SOL of a coin once its market cap is at or below 30 SOL
echo '{"operationId":"dip-1","mint":"<mint>","side":"buy","amount":"50000000","marketCapSol":30}' > trade/<wallet>/limit.json
# check, from an agent or a timer: sends any order whose price has arrived
echo '{}' > trade/<wallet>/check_orders.json
cat trade/<wallet>/orders.json
# cancel
echo '{"operationId":"cancel-1","order":"dip-1"}' > trade/<wallet>/cancel_order.json
```

An order is an ordinary Pump buy or sell from the builder, validated as any
trade is, with two changes. Its amounts are set to the limit, so Pump's own
program refuses it until the price is there: a buy names the tokens its SOL
buys at the limit, and a sell names the least SOL its tokens fetch at the
limit, both with 1.5% left for Pump's fee so the fill is at the limit or
better. And its recent blockhash is the slot's durable nonce, with the
nonce's advance as its first instruction, so the signed transaction does not
expire. The Petal stores it and a check simulates it, sending it only when the
simulation succeeds; Pump's "price not reached" errors leave it waiting, and
a coin that graduated off its curve retires a curve order. Cancelling
advances the nonce, which voids the stored transaction. When the order is
signed, the Petal simulates it at today's price to hold what it can spend to
the approval, as for any trade.

One slot holds one open order, because landing or cancelling anything on a
nonce advances it; there are four slots. Each slot's address must be an
allowed destination in the wallet policy, since its rent moves into it; the
Petal names it before asking for approval. Nothing fills unless something
writes to `check_orders.json`: an agent, or a timer such as
`watch -n 10 "echo '{}' > …/check_orders.json"`. A stop-loss cannot be
expressed: a sell's floor keeps it from filling below a price, never above
one.

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

- `approval_pending`, `approval_failed` or `preflight_failed` — if no signing
  call could have produced a signature, the Petal rebuilds with a fresh
  blockhash under the same economic intent and the same approval. A rebuild
  whose debits and network fee exceed the approved ceiling is refused by the
  Broker before anything is signed.
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
