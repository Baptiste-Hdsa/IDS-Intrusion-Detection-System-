#!/usr/bin/env bash
set -eo pipefail

# ^Make sure to run the script from its own directory
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_PYTHON="$ROOT_DIR/.venv/bin/python"

# Check if the venv's python executable exists and is executable
if [[ -x "$VENV_PYTHON" ]]; then
  PYTHON_BIN="$VENV_PYTHON"
else
  PYTHON_BIN="python3"
fi

# Check if the python executable is available
if [[ "$EUID" -ne 0 ]]; then
  echo "[INFO] Raw packet sending often needs root privileges."
  echo "[INFO] If you get permission errors, run: sudo ./run_attack_lab.sh"
fi

exec "$PYTHON_BIN" "$ROOT_DIR/attack_lab.py"
