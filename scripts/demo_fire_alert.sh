#!/usr/bin/env bash
set -euo pipefail
echo "[demo] sending a sample alert to webhook…"
curl -s -X POST http://localhost:5000/ingest/webhook   -H 'Content-Type: application/json'   -d @services/event_bridge/samples/alert_examples.json
echo
echo "Open http://localhost:8088 to review/approve the generated draft."
