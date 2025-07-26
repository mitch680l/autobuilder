#!/bin/bash
set -e

echo "🔄 Cleaning and updating submodules..."

# Clean submodules first
git submodule foreach --recursive '
  echo "🧹 Resetting $name..."
  git reset --hard
  git clean -fdx
'

# Now update to latest remote commits
git submodule update --init --recursive --remote

echo "✅ Submodules reset and updated."
