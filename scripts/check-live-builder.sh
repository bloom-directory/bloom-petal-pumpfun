#!/usr/bin/env bash
# Put today's real Pump.fun builder output through this Petal's validation and
# review, and simulate the unsigned result on mainnet.
#
# Nothing here signs, submits, or spends. It builds transactions for an account
# it does not hold a key for, runs the Petal's own validators over what the
# builder returned, prints the review the owner would read, and asks an RPC
# whether the unsigned transaction would execute.
#
# This covers what the local-validator run cannot: Pump instruction shapes,
# account resolution against real pools, the builder's quotes, and trade
# economics against real reserves.
#
#   scripts/check-live-builder.sh <account> <out-dir>
#
# <account> is any existing Solana address. Its balance decides whether a buy
# can simulate; a sell needs a token balance and is reported as unsimulatable
# without one.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
ACCOUNT="${1:?usage: check-live-builder.sh <account> <out-dir>}"
OUT="${2:?usage: check-live-builder.sh <account> <out-dir>}"
mkdir -p "$OUT"

BUILDER=https://fun-block.pump.fun/agents/swap
COINS=https://frontend-api-v3.pump.fun/coins-v2
RPC=https://api.mainnet-beta.solana.com
RPC_VERIFY=https://rpc.solanatracker.io/public
SOL=So11111111111111111111111111111111111111112

say() { printf '%s\n' "$*"; }

build_one() {
  # build_one <label> <side: buy|sell> <mint> <amount> <slippage>
  local label="$1" side="$2" mint="$3" amount="$4" slip="$5"
  local input output
  if [ "$side" = buy ]; then input="$SOL"; output="$mint"; else input="$mint"; output="$SOL"; fi
  jq -nc --arg i "$input" --arg o "$output" --arg a "$amount" --arg u "$ACCOUNT" \
     --argjson s "$slip" \
    '{inputMint:$i, outputMint:$o, amount:$a, user:$u, feePayer:$u,
      slippagePct:$s, frontRunningProtection:false, tipAmount:0, encoding:"base64"}' \
    > "${OUT}/${label}-request.json"
  curl -s -m 30 -X POST -H 'content-type: application/json' \
    --data @"${OUT}/${label}-request.json" "$BUILDER" > "${OUT}/${label}-response.json" || true
  if ! jq -e '.transaction | type == "string"' "${OUT}/${label}-response.json" >/dev/null 2>&1; then
    say "  ${label}: builder returned no transaction: $(head -c 200 "${OUT}/${label}-response.json")"
    return 1
  fi
  say "  ${label}: builder returned a transaction ($(jq -r '.transaction | length' "${OUT}/${label}-response.json") base64 chars)"
}

# The mint's decimal scale, taken only when both RPCs agree — the same rule the
# route applies in verified_mint_decimals. Written where the review test reads
# it; absent means the review falls back to raw units, which is the point.
decimals_of() {
  local mint="$1" a b
  read_one() {
    curl -s -m 20 -X POST -H 'content-type: application/json' \
      --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getAccountInfo\",\"params\":[\"${mint}\",{\"encoding\":\"jsonParsed\",\"commitment\":\"finalized\"}]}" \
      "$1" | jq -r '.result.value | select(.data.parsed.type == "mint") | .data.parsed.info.decimals // empty' 2>/dev/null
  }
  a="$(read_one "$RPC")"; b="$(read_one "$RPC_VERIFY")"
  if [ -n "$a" ] && [ "$a" = "$b" ]; then
    printf '%s' "$a" > "${OUT}/${mint}-decimals.txt"
    say "  ${mint}: decimals ${a}, agreed by both RPCs"
  else
    say "  ${mint}: decimals unverified (${a:-none} vs ${b:-none}); review will use raw units"
  fi
}

simulate_one() {
  # simulate_one <label>: simulate the unsigned transaction, signatures unchecked.
  local label="$1" tx
  tx="$(jq -r .transaction "${OUT}/${label}-response.json")"
  jq -nc --arg tx "$tx" \
    '{jsonrpc:"2.0", id:1, method:"simulateTransaction",
      params:[$tx, {encoding:"base64", sigVerify:false, replaceRecentBlockhash:true,
                    commitment:"confirmed"}]}' > "${OUT}/${label}-sim-request.json"
  curl -s -m 30 -X POST -H 'content-type: application/json' \
    --data @"${OUT}/${label}-sim-request.json" "$RPC" > "${OUT}/${label}-sim.json" || true
  python3 - "${OUT}/${label}-sim.json" "$label" <<'PY'
import json, sys
path, label = sys.argv[1], sys.argv[2]
try:
    d = json.load(open(path))
except Exception as error:
    print(f"  {label}: simulation response unreadable: {error}"); raise SystemExit
value = (d.get("result") or {}).get("value")
if value is None:
    print(f"  {label}: simulation returned no value: {json.dumps(d)[:200]}"); raise SystemExit
if value.get("err") is None:
    units = value.get("unitsConsumed")
    print(f"  {label}: simulation SUCCEEDED, {units} compute units")
else:
    logs = value.get("logs") or []
    tail = [line for line in logs if "Error" in line or "failed" in line][-2:] or logs[-2:]
    print(f"  {label}: simulation failed: {json.dumps(value['err'])[:120]}")
    for line in tail:
        print(f"      {line[:160]}")
PY
}

say "account: $ACCOUNT"
say "balance: $(curl -s -m 20 -X POST -H 'content-type: application/json' \
  --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getBalance\",\"params\":[\"$ACCOUNT\",{\"commitment\":\"finalized\"}]}" \
  "$RPC" | jq -r '.result.value') lamports"
say ""

# One graduated coin (PumpSwap AMM) and one still on the bonding curve.
BOND_MINT="${PUMPFUN_BOND_MINT:-vRseBFqTy9QLmmo5qGiwo74AVpdqqMTnxPqWoWMpump}"
AMM_MINT="${PUMPFUN_AMM_MINT:-21La252xiAfugNfaa7B7MTRaR2AQ97wvzmvixznMpump}"
for pair in "bond:${BOND_MINT}" "amm:${AMM_MINT}"; do
  label="${pair%%:*}"; mint="${pair#*:}"
  complete="$(curl -s -m 20 "${COINS}/${mint}" | jq -r '.complete')"
  say "${label} mint ${mint} (complete=${complete})"
done
say ""

say "building:"
build_one buy_bond buy "$BOND_MINT" 1000000 2 || true
build_one buy_amm buy "$AMM_MINT" 1000000 2 || true
say ""

say "simulating the unsigned transactions (sigVerify off, blockhash replaced):"
for label in buy_bond buy_amm; do
  [ -f "${OUT}/${label}-response.json" ] && simulate_one "$label" || true
done
say ""

say "verifying each mint's decimal scale across two independent RPCs:"
for mint in "$BOND_MINT" "$AMM_MINT"; do decimals_of "$mint"; done
say ""

say "running this Petal's validation and review over the captured output:"
PUMPFUN_LIVE_BUILDER_DIR="$OUT" cargo test --manifest-path "${ROOT}/route/Cargo.toml" --locked \
  -- --ignored --nocapture live_builder 2>&1 | sed -n '/running /,$p'
