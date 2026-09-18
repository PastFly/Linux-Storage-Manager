#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd -- "${ROOT}"
MODE=${1:-all}
if [[ $# -gt 1 || (${MODE} != all && ${MODE} != --source-only) ]]; then
  echo 'Usage: bash tools/validate.sh [--source-only]' >&2
  exit 2
fi

command -v python3 >/dev/null || { echo 'Python 3.10+ is required for harness tests' >&2; exit 2; }
python3 -I -c 'import sys; assert sys.version_info >= (3, 10), "Python 3.10+ required"'
bash -n tools/validate.sh tests/integration/loop-matrix.sh
python3 -I tests/integration/test_loop_matrix.py -v

if [[ ${MODE} == --source-only ]]; then
  echo 'HARNESS_CHECKS_OK rust=not-run real-storage-integration=not-run'
  exit 0
fi

for tool in cargo rustc; do
  command -v "${tool}" >/dev/null || {
    echo "VALIDATION_INCOMPLETE: ${tool} is missing; harness tests are not Rust build evidence" >&2
    exit 2
  }
done
VERSION=$(rustc --version)
if [[ ${VERSION} != 'rustc 1.88.0 '* ]]; then
  echo "Expected the repository Rust 1.88.0 toolchain, got: ${VERSION}" >&2
  exit 2
fi

cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
cargo build --locked --workspace
printf '%s\n' 'RUST_VALIDATION_OK real-storage-integration=not-run'
