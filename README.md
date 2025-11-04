# seim_ai

Plug‑and‑play **AI‑assisted incident response** for Fourth Estate labs and enclaves.

**Zero‑touch path:** `docker compose -f docker/docker-compose.yml up -d` spawns a webhook/syslog event bridge, a normalizer, an AI playbook generator (local/offline by default), and a controlled Ansible runner with policy gates. All remediation is **manual‑approval only** and runs in **check‑mode** by default.

> **Safety BLUF:** No change can execute until (1) PR is approved in the built‑in UI, (2) OPA policy gates allow it, and (3) you explicitly run the playbook. High‑risk actions require dual‑control if enabled.

## Quickstart

```bash
git clone https://github.com/Koga1985/seim_ai.git
cd seim_ai
./scripts/install_collections.sh
cp docker/.env.sample docker/.env
docker compose -f docker/docker-compose.yml up -d
./scripts/demo_fire_alert.sh    # fires a sample alert through the pipeline
```

Open the local review UI at **http://localhost:8088** → approve the generated draft → CI gates run (lint, Molecule, OPA, dry‑run). When gates pass, execute:
```bash
ansible-playbook playbooks/run_generated.yml -e incident=<INCIDENT_ID> -i inventories/lab/hosts.ini
```

## What’s included
- **Event Bridge** (`services/event_bridge`): HTTP webhook (`/ingest/webhook`) + UDP syslog (514) → **ECS‑min** normalizer.
- **AI Generator** (`services/ai_generator`): Produces an **idempotent** Ansible remediation in **check‑mode** plus `CHANGE_PLAN.md` and `EVIDENCE.json`. Default model is **local/offline** (templated); bring your own endpoint by setting env vars.
- **Orchestrator** (`services/orchestrator`): Opens a **local PR** (git branch) to `playbooks/_library/` and kicks CI.
- **Guardrails**: `ansible-lint`, **Molecule**, **OPA policy** (scope, risk, CAB), and enforced **check‑mode** for anything below “high” severity.
- **Samples**: Windows isolation, Palo Alto IP block, AD user disable, Linux package patch.

## Configure (minimal)
- Edit `inventories/lab/hosts.ini` with your lab endpoints.
- Optional: set `MODEL_MODE=remote` in `docker/.env` and supply `LLM_ENDPOINT`/`API_KEY` (kept blank by default).
- Optional: tune `policies/opa/policy.rego` (e.g., require CAB on high‑risk).

## SIEM hookups
- Webhook: POST to `http://<host>:5000/ingest/webhook` (Elastic, Splunk HEC adapter).
- Syslog: point your SIEM to UDP/514 of the host running this stack.
- File drop: POST a JSON event with `alert.severity` (1–10) and any indicators; see `services/event_bridge/samples/alert_examples.json`.

## Compliance
- Maps to NIST 800‑53 AU, IR, CM, and AC families; STIG artifacts are attached in `EVIDENCE.json`.
- “Human‑in‑the‑loop” is enforced. No autonomous changes.

## Roadmap toggles (already stubbed)
- Canary → progressive rollout, ServiceNow CAB webhook, Sigstore signing, Grafana dashboards.

---

## Production Readiness Status

**Lab/Testing**: ✅ **Ready**
**Production**: ⚠️ **See [Production Deployment Guide](docs/PRODUCTION_DEPLOYMENT.md)**

This codebase has been significantly hardened for production use with comprehensive security improvements, structured logging, error handling, authentication, rate limiting, and safety checks. However, production deployment requires additional configuration:

**Required Before Production:**
- Configure TLS/HTTPS with valid certificates
- Set up secrets management (Vault/AWS Secrets Manager)
- Deploy message broker (Redis/RabbitMQ) to replace file queue
- Configure external log aggregation (ELK/Splunk)
- Set up monitoring and alerting (Prometheus/Grafana)
- Complete security review and penetration testing
- Test backup and disaster recovery procedures

**See Full Checklist:** [docs/PRODUCTION_DEPLOYMENT.md](docs/PRODUCTION_DEPLOYMENT.md)

---

## What's New (Production Hardening)

### Security Enhancements
- ✅ **API Key Authentication**: Optional authentication for webhook endpoint
- ✅ **Rate Limiting**: Configurable rate limits to prevent abuse
- ✅ **Comprehensive Safety Checks**: YAML parsing, dangerous pattern detection, module validation
- ✅ **Non-Root Containers**: All services run as non-root users
- ✅ **Security Best Practices**: Read-only filesystems where possible, no-new-privileges

### Reliability Improvements
- ✅ **Structured JSON Logging**: All services with audit trails
- ✅ **Comprehensive Error Handling**: Graceful degradation and retry logic
- ✅ **Health Check Endpoints**: Kubernetes/Docker Swarm compatible
- ✅ **Resource Limits**: CPU and memory limits configured
- ✅ **Health Checks**: Liveness and readiness probes

### Code Quality
- ✅ **Unit Tests**: Comprehensive test coverage with pytest
- ✅ **Improved CI/CD**: Security scanning, linting, testing (no more || true)
- ✅ **Pinned Dependencies**: All versions locked for reproducibility
- ✅ **Type Hints**: Better code documentation

### Operations
- ✅ **Production Documentation**: Comprehensive deployment and security guides
- ✅ **Secrets Management**: Examples for Vault, AWS, Azure
- ✅ **Monitoring Ready**: Prometheus metrics and Grafana dashboards
- ✅ **Docker Compose Production**: Production-ready compose file with volumes and networks

---

Made for labs first. **Now production-capable with proper configuration** - see deployment guide before expanding scope.
