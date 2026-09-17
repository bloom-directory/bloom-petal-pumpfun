#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PETAL_REV="f493f9ba442b3cc41021595ada0317cdf3b54058"
if [[ -n "${PETAL_BIN:-}" ]]; then
  "$PETAL_BIN" build --root "$ROOT"
else
  tool_root="$ROOT/target/petal-tool"
  cargo install --git https://github.com/bloom-directory/petal --rev "$PETAL_REV" --locked --root "$tool_root" bloom-petal-cli
  "$tool_root/bin/petal" build --root "$ROOT"
fi
