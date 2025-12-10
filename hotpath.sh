#!/bin/bash

# fail fast
set -e
set -u
set -o pipefail
set -x

# total allocations
for line in $(cat ciphersuites.txt)
do
  cs1=$(echo $line | cut -f1 -d'/')
  cs2=$(echo $line | cut -s -f2 -d'/')
  echo Total allocations for $cs1 $cs2
  FLEX_SIM_CS1=$cs1 FLEX_SIM_CS2=$cs2 target/release/deps/flex_sim-301114124f909df6 2>&1 | tee -a hotpath-total.txt
  if [ -n "$cs2" ]
  then
    FLEX_SIM_CS1=$cs1 FLEX_SIM_CS2=$cs2 FLEX_SIM_CS2_TO_CS1_RATIO=2 target/release/deps/flex_sim-301114124f909df6 2>&1 | tee -a hotpath-total.txt
    FLEX_SIM_CS1=$cs1 FLEX_SIM_CS2=$cs2 FLEX_SIM_CS2_TO_CS1_RATIO=5 target/release/deps/flex_sim-301114124f909df6 2>&1 | tee -a hotpath-total.txt
    FLEX_SIM_CS1=$cs1 FLEX_SIM_CS2=$cs2 FLEX_SIM_CS2_TO_CS1_RATIO=10 target/release/deps/flex_sim-301114124f909df6 2>&1 | tee -a hotpath-total.txt
    FLEX_SIM_CS1=$cs1 FLEX_SIM_CS2=$cs2 FLEX_SIM_CS2_TO_CS1_RATIO=50 target/release/deps/flex_sim-301114124f909df6 2>&1 | tee -a hotpath-total.txt
    FLEX_SIM_CS1=$cs1 FLEX_SIM_CS2=$cs2 FLEX_SIM_CS2_TO_CS1_RATIO=100 target/release/deps/flex_sim-301114124f909df6 2>&1 | tee -a hotpath-total.txt
  fi
  echo
done

# peak allocations
for line in $(cat ciphersuites.txt)
do
  cs1=$(echo $line | cut -f1 -d'/')
  cs2=$(echo $line | cut -s -f2 -d'/')
  echo Peak allocations for $cs1 $cs2
  FLEX_SIM_CS1=$cs1 FLEX_SIM_CS2=$cs2 target/release/deps/flex_sim-1ba957d846e186ab 2>&1 | tee -a hotpath-max.txt
  if [ -n "$cs2" ]
  then
    FLEX_SIM_CS1=$cs1 FLEX_SIM_CS2=$cs2 FLEX_SIM_CS2_TO_CS1_RATIO=2 target/release/deps/flex_sim-1ba957d846e186ab 2>&1 | tee -a hotpath-max.txt
    FLEX_SIM_CS1=$cs1 FLEX_SIM_CS2=$cs2 FLEX_SIM_CS2_TO_CS1_RATIO=5 target/release/deps/flex_sim-1ba957d846e186ab 2>&1 | tee -a hotpath-max.txt
    FLEX_SIM_CS1=$cs1 FLEX_SIM_CS2=$cs2 FLEX_SIM_CS2_TO_CS1_RATIO=10 target/release/deps/flex_sim-1ba957d846e186ab 2>&1 | tee -a hotpath-max.txt
    FLEX_SIM_CS1=$cs1 FLEX_SIM_CS2=$cs2 FLEX_SIM_CS2_TO_CS1_RATIO=50 target/release/deps/flex_sim-1ba957d846e186ab 2>&1 | tee -a hotpath-max.txt
    FLEX_SIM_CS1=$cs1 FLEX_SIM_CS2=$cs2 FLEX_SIM_CS2_TO_CS1_RATIO=100 target/release/deps/flex_sim-1ba957d846e186ab 2>&1 | tee -a hotpath-max.txt
  fi
  echo
done
