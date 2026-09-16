#!/usr/bin/env bash
set -euo pipefail
# Compatibility entry point; no storage commands are implemented in this wrapper.
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
exec python3 -I "${SCRIPT_DIR}/loop_matrix.py" "$@"
