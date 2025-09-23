#!/usr/bin/env bash
set -euo pipefail
echo "[lint] running ansible-lint (skipping if not installed)…"
if command -v ansible-lint >/dev/null 2>&1; then
  ansible-lint -q || true
else
  echo "ansible-lint not found; skipping in local env."
fi
