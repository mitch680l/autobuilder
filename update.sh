#!/bin/bash

set -e

echo "🔄 Updating submodules..."

# Make sure submodules are initialized and updated to latest remote commit
git submodule update --init --recursive --remote

echo "✅ Submodules updated."
sleep 1
