#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "Usage: $0 <start> <stop>    # e.g. $0 0 49"
  exit 1
fi

START="$1"
STOP="$2"

# repo root (where this script and combined.py live)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# activate ./env
if [[ ! -d "$SCRIPT_DIR/env" ]]; then
  echo "ERROR: venv not found at $SCRIPT_DIR/env"
  echo "Create it with:  python3 -m venv \"$SCRIPT_DIR/env\" && \"$SCRIPT_DIR/env/bin/pip\" install -r requirements.txt"
  exit 2
fi
# shellcheck disable=SC1090
source "$SCRIPT_DIR/env/bin/activate"
echo "Activated venv: $SCRIPT_DIR/env (python: $(python -V))"

COMBINED="$SCRIPT_DIR/combined.py"
if [[ ! -f "$COMBINED" ]]; then
  echo "ERROR: combined.py not found at $COMBINED"
  exit 3
fi

# sanity: start <= stop
if (( START > STOP )); then
  echo "ERROR: start ($START) is greater than stop ($STOP)"
  exit 4
fi

for i in $(seq "$START" "$STOP"); do
  ID=$(printf "%03d" "$i")
  echo "==> Building nrid${ID}"
  python "$COMBINED" "$ID"
done

echo "All done: ${START}..${STOP}"
