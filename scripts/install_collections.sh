#!/usr/bin/env bash
set -euo pipefail
mkdir -p .collections
ansible-galaxy collection install -r requirements.yml -p .collections || true
echo "Collections installed (or already present)."
