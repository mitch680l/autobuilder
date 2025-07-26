#!/bin/bash

# Absolute path to your project (adjust this!)
PROJECT_PATH="$(pwd)"
VENV_PATH="$PROJECT_PATH/env/Scripts/activate"

# Launch Git Bash with virtual environment activated
"C:\Program Files\Git\bin\bash.exe" --login -i -c "
    cd \"$PROJECT_PATH\"
    source \"$VENV_PATH\"
    echo '✅ Python environment activated in: $PROJECT_PATH'
    exec bash
"
