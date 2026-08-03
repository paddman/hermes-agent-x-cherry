#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${CHERRY_PCAP_BUILD_DIR:-$ROOT/build}"
BUILD_TYPE="${CHERRY_PCAP_BUILD_TYPE:-Release}"

cmake -S "$ROOT" -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE="$BUILD_TYPE" "$@"
cmake --build "$BUILD_DIR" --parallel
ctest --test-dir "$BUILD_DIR" --output-on-failure

echo "Built: $BUILD_DIR/cherry-pcap"
