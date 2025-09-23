#!/usr/bin/env bash
set -euo pipefail
echo "[opa] evaluating sample input against policy…"
cat > /tmp/opa_input.json <<'JSON'
{
  "meta": {
    "severity": "medium",
    "check_mode": true,
    "cab_approved": false,
    "dual_control": false,
    "inventory": "inventories/lab"
  }
}
JSON
if command -v opa >/dev/null 2>&1; then
  opa eval -I -d policies/opa/policy.rego -i /tmp/opa_input.json "data.seim_ai.allow"
else
  echo "opa not found; skipping in local env."
fi
