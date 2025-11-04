#!/usr/bin/env bash
set -euo pipefail

echo "[lint] Running ansible-lint on playbooks..."
if command -v ansible-lint >/dev/null 2>&1; then
  ansible-lint -v playbooks/ || {
    echo "ERROR: ansible-lint found issues"
    exit 1
  }
  echo "✓ ansible-lint passed"
else
  echo "WARNING: ansible-lint not found; install with: pip install ansible-lint"
  echo "Skipping lint check in local environment"
fi

echo "[lint] Running yamllint..."
if command -v yamllint >/dev/null 2>&1; then
  yamllint -c .yamllint playbooks/ policies/ docker/ || {
    echo "ERROR: yamllint found issues"
    exit 1
  }
  echo "✓ yamllint passed"
else
  echo "WARNING: yamllint not found; install with: pip install yamllint"
fi

echo "[lint] All lint checks passed!"
