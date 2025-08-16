#!/usr/bin/env bash
set -euo pipefail

PROJECT_PATH="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
UNAME="$(uname -s 2>/dev/null || echo unknown)"

if [[ "$UNAME" == "Linux" || "$UNAME" == "Darwin" ]]; then
  VENV_ACTIVATE="$PROJECT_PATH/env/bin/activate"
  [[ -f "$VENV_ACTIVATE" ]] || { echo "venv not found: $VENV_ACTIVATE"; exit 1; }
  cd "$PROJECT_PATH"
  # Start an interactive shell whose RC file activates the venv (so PS1 shows (env))
  exec bash --rcfile <(printf 'source "%s"\n[[ -f ~/.bashrc ]] && source ~/.bashrc\n' "$VENV_ACTIVATE") -i
else
  VENV_ACTIVATE="$PROJECT_PATH/env/Scripts/activate"
  [[ -f "$VENV_ACTIVATE" ]] || { echo "venv not found: $VENV_ACTIVATE"; exit 1; }

  GIT_BASH_EXE="C:\\Program Files\\Git\\bin\\bash.exe"
  [[ -x "$GIT_BASH_EXE" ]] || GIT_BASH_EXE="C:\\Program Files\\Git\\git-bash.exe"
  [[ -x "$GIT_BASH_EXE" ]] || { echo "Git Bash not found"; exit 2; }

  "$GIT_BASH_EXE" --login -i -c "
    cd \"$PROJECT_PATH\" &&
    exec bash --rcfile <(echo 'source \"$VENV_ACTIVATE\"; [[ -f ~/.bashrc ]] && source ~/.bashrc') -i
  "
fi
