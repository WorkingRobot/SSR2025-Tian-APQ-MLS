#!/bin/bash

# Allocation profiling benchmark runner for APQ-MLS
# Builds two flex_sim binaries (total and peak allocation tracking)
# then runs them across all ciphersuite configurations in ciphersuites.txt.

set -e
set -u
set -o pipefail
set -x

# Build both hotpath variants
echo "Building hotpath-alloc-bytes-total variant..."
cargo bench --bench flex_sim -p app --features "hotpath,hotpath-alloc-bytes-total" --no-run 2>&1
TOTAL_BIN=$(find target/release/deps -name 'flex_sim-*' -executable ! -name '*.d' -newer Cargo.toml | head -1)

echo "Building hotpath-alloc-bytes-max variant..."
cargo bench --bench flex_sim -p app --features "hotpath,hotpath-alloc-bytes-max" --no-run 2>&1
# The max binary is the newest one (just built)
MAX_BIN=$(find target/release/deps -name 'flex_sim-*' -executable ! -name '*.d' | sort -t- -k2 | tail -1)

if [ -z "$TOTAL_BIN" ] || [ -z "$MAX_BIN" ]; then
  echo "Error: Could not find flex_sim binaries in target/release/deps/" >&2
  exit 1
fi

# If both binaries resolve to the same file, we need a different strategy:
# build total first, rename it, then build max
if [ "$TOTAL_BIN" = "$MAX_BIN" ]; then
  echo "Binaries collided, using staged build..."
  cp "$TOTAL_BIN" target/release/deps/flex_sim_total
  cargo bench --bench flex_sim -p app --features "hotpath,hotpath-alloc-bytes-max" --no-run 2>&1
  MAX_BIN=$(find target/release/deps -name 'flex_sim-*' -executable ! -name '*.d' -newer target/release/deps/flex_sim_total | head -1)
  TOTAL_BIN=target/release/deps/flex_sim_total
fi

echo "Total allocations binary: $TOTAL_BIN"
echo "Peak allocations binary:  $MAX_BIN"

run_ciphersuite() {
  local bin=$1
  local output_file=$2
  local cs1=$3
  local cs2=$4

  FLEX_SIM_CS1=$cs1 FLEX_SIM_CS2=$cs2 "$bin" 2>&1 | tee -a "$output_file"
  if [ -n "$cs2" ]; then
    for ratio in 2 5 10 50 100; do
      FLEX_SIM_CS1=$cs1 FLEX_SIM_CS2=$cs2 FLEX_SIM_CS2_TO_CS1_RATIO=$ratio "$bin" 2>&1 | tee -a "$output_file"
    done
  fi
}

# Total allocations
for line in $(cat ciphersuites.txt); do
  cs1=$(echo "$line" | cut -f1 -d'/')
  cs2=$(echo "$line" | cut -s -f2 -d'/')
  echo "Total allocations for $cs1 $cs2"
  run_ciphersuite "$TOTAL_BIN" hotpath-total.txt "$cs1" "$cs2"
  echo
done

# Peak allocations
for line in $(cat ciphersuites.txt); do
  cs1=$(echo "$line" | cut -f1 -d'/')
  cs2=$(echo "$line" | cut -s -f2 -d'/')
  echo "Peak allocations for $cs1 $cs2"
  run_ciphersuite "$MAX_BIN" hotpath-max.txt "$cs1" "$cs2"
  echo
done
