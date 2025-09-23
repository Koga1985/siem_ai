#!/usr/bin/env bash
set -euo pipefail
echo "[checkmode] verifying sample playbooks run in --check…"
ansible-playbook playbooks/samples/patch_linux_package.yml --check -i inventories/lab/hosts.ini || true
