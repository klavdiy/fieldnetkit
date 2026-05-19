#!/bin/bash
# FieldNet Kit (FNkit) — macOS/Linux launcher

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_SCRIPT="$SCRIPT_DIR/fnkit.py"

if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is not installed. Please install Python 3 first."
    echo "Install via: brew install python3"
    exit 1
fi

if [ ! -f "$PYTHON_SCRIPT" ]; then
    echo "Error: fnkit.py not found in $SCRIPT_DIR"
    exit 1
fi

# Optional: ./fnkit.sh --check-deps  or  INSTALL_DEPS=1 ./fnkit.sh
if [[ "${INSTALL_DEPS:-}" == "1" ]]; then
    "$SCRIPT_DIR/scripts/install-deps.sh" "${INSTALL_PROFILE:-minimal}"
fi

python3 "$PYTHON_SCRIPT" "$@"
