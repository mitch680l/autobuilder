#!/usr/bin/env bash
set -euo pipefail

VENV_DIR="env"

# External modules from your imports
REQUIREMENTS_CONTENT="pycryptodome
intelhex
"

# Detect Python
find_python() {
  if command -v python3 >/dev/null 2>&1; then echo "python3"
  elif command -v python >/dev/null 2>&1; then echo "python"
  elif command -v py >/dev/null 2>&1; then echo "py -3"
  else
    echo "ERROR: Could not find Python 3 on PATH." >&2
    exit 1
  fi
}

PYBIN=$(find_python)

# Create venv if missing
if [ ! -d "$VENV_DIR" ]; then
  echo "Creating virtual environment '$VENV_DIR'..."
  $PYBIN -m venv "$VENV_DIR"
else
  echo "Virtual environment '$VENV_DIR' already exists."
fi

# Figure out venv pip path
if [ -f "$VENV_DIR/bin/pip" ]; then
  VENV_PIP="$VENV_DIR/bin/pip"
else
  VENV_PIP="$VENV_DIR/Scripts/pip.exe"
fi

# Upgrade pip & wheel
"$VENV_PIP" install --upgrade pip wheel

# Generate requirements.txt
echo "Generating requirements.txt..."
echo "$REQUIREMENTS_CONTENT" > requirements.txt

# Install requirements
"$VENV_PIP" install -r requirements.txt

echo "Setup complete."
echo "To activate the environment:"
if [ -f "$VENV_DIR/bin/activate" ]; then
  echo "source $VENV_DIR/bin/activate"
else
  echo "$VENV_DIR\\Scripts\\activate"
fi
