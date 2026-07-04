#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if [ ! -f "$SCRIPT_DIR/app.py" ]; then
    echo "ERROR: app.py not found in $SCRIPT_DIR"
    exit 1
fi

echo "Installing dependencies..."
pip3 install -r "$SCRIPT_DIR/requirements.txt" --quiet

echo "Starting vulnerable web app on http://0.0.0.0:5555"
echo "Press Ctrl+C to stop."

python3 "$SCRIPT_DIR/app.py"
