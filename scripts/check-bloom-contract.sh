#!/usr/bin/env bash
# Install the built package into Bloom's own Petal router and check that every
# trade runs only under the wallet/index Bloom selected. Build first
# (scripts/build.sh), then:
#   BLOOM_ROOT=/path/to/bloom scripts/check-bloom-contract.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# bloom#276 (`[sign].fee_asset`) on top of bloom#328 (explicit wallet/index
# routes). Move to master once #276 lands.
BLOOM_CONTRACT_REV="d033f2b17cbe21ff8e38716fcaecbe7540ce52c1"
BLOOM_ROOT="${BLOOM_ROOT:?set BLOOM_ROOT to a checkout of bloom-directory/bloom at $BLOOM_CONTRACT_REV}"

actual_rev="$(git -C "$BLOOM_ROOT" rev-parse HEAD)"
if [[ "$actual_rev" != "$BLOOM_CONTRACT_REV" ]]; then
  echo "Bloom contract checkout must be exactly $BLOOM_CONTRACT_REV (found $actual_rev)" >&2
  exit 1
fi

test_name="pumpfun_explicit_account"
test_path="$BLOOM_ROOT/crates/bloom-petals/tests/$test_name.rs"
if [[ -e "$test_path" ]]; then
  echo "refusing to overwrite existing Bloom test: $test_path" >&2
  exit 1
fi
trap 'rm -f "$test_path"' EXIT
cp "$ROOT/tests/bloom_explicit_account.rs" "$test_path"

PUMPFUN_PACKAGE_ROOT="$ROOT" \
  cargo test \
    --locked \
    --manifest-path "$BLOOM_ROOT/Cargo.toml" \
    -p bloom-petals \
    --test "$test_name" \
    -- --ignored --nocapture
