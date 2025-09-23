#!/usr/bin/env bash
set -euo pipefail
./scripts/install_collections.sh
cp -n docker/.env.sample docker/.env || true
docker compose -f docker/docker-compose.yml up -d
./scripts/demo_fire_alert.sh
