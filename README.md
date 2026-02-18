# siem_ai

Plug-and-play **AI-assisted incident triage** for Fourth Estate labs and enclaves.
Point any SIEM or syslog server at it and get severity-classified, human-reviewed,
Ansible-backed remediation playbooks — no LLM required by default.

> **Safety BLUF:** No change executes until (1) you review it in the built-in UI,
> (2) OPA policy gates allow it, and (3) you explicitly run the playbook.
> All state-changing tasks run in **check-mode** (dry-run) until approved.

---

## Quickstart (two commands)

```bash
git clone https://github.com/Koga1985/seim_ai.git
cd siem_ai
cp docker/.env.sample docker/.env        # defaults work out of the box
docker compose -f docker/docker-compose.yml up -d
```

Open **http://localhost:8088** — the incident review queue.
Then point your SIEM at the tool using any of the methods below.

Fire a sample alert to verify the pipeline is running:

```bash
./scripts/demo_fire_alert.sh
```

---

## SIEM Integration — Pick Your Method

### Any syslog source (zero config — just redirect your syslog)

RFC 3164, RFC 5424, CEF, and LEEF are **auto-detected per message**.
No configuration needed on this side.

| Protocol | Default Port | Use when |
|----------|-------------|----------|
| UDP | **514** | Network devices, rsyslog, syslog-ng default |
| TCP | **601** | Reliable delivery; rsyslog `@@`, syslog-ng `tcp()` |

**rsyslog** (`/etc/rsyslog.conf`):
```
# UDP
*.* @<host>:514

# TCP (more reliable)
*.* @@<host>:601
```

**syslog-ng**:
```
destination d_siem_ai {
    syslog("<host>" port(601) transport("tcp"));
};
log { source(s_src); destination(d_siem_ai); };
```

---

### Splunk

**Option A — Splunk HEC** (recommended):
Configure a Splunk alert action or forwarder to POST to:
```
http://<host>:5000/ingest/splunk
```
Standard HEC JSON format. Set `SIEM_TYPE=splunk` in `docker/.env` if you also
want the generic `/ingest/webhook` to use the Splunk normaliser.

**Option B — Splunk alert webhook**:
Settings → Alerts → Add Action → Webhook → URL:
```
http://<host>:5000/ingest/splunk
```

**Option C — Splunk syslog forwarding**:
```ini
# outputs.conf
[syslog]
server = <host>:514
```

---

### Elastic / ELK Stack

**Logstash HTTP output**:
```ruby
output {
  http {
    url => "http://<host>:5000/ingest/elastic"
    http_method => "post"
    format => "json"
  }
}
```

**Kibana Watcher action**:
```json
{
  "actions": {
    "notify_siem_ai": {
      "webhook": {
        "method": "POST",
        "url": "http://<host>:5000/ingest/elastic",
        "body": "{{#toJson}}ctx{{/toJson}}",
        "headers": { "Content-Type": "application/json" }
      }
    }
  }
}
```

**Elastic SIEM Detection Engine**: Use the built-in webhook action and point it
at `http://<host>:5000/ingest/elastic`.

Set `SIEM_TYPE=elastic` in `docker/.env` if all events come from Elastic/ECS.

---

### Microsoft Sentinel / ArcSight / QRadar (CEF / LEEF)

These platforms all support CEF syslog output.
Point CEF syslog at **UDP/514 or TCP/601** — CEF and LEEF are auto-detected.

- **Microsoft Sentinel**: Data connector → CEF via syslog → this host
- **ArcSight**: SmartConnector → Syslog NG Daemon → forward here
- **IBM QRadar**: Log source → Syslog (LEEF also auto-detected)

---

### Wazuh

```xml
<!-- /var/ossec/etc/ossec.conf -->
<integration>
  <name>custom-webhook</name>
  <hook_url>http://<host>:5000/ingest/webhook</hook_url>
  <alert_format>json</alert_format>
  <level>3</level>
</integration>
```

---

### Generic JSON webhook (Graylog, Grafana, etc.)

```
POST http://<host>:5000/ingest/webhook
Content-Type: application/json
```

Any JSON is accepted. The tool extracts `severity`, `rule`, `src_ip`, `host`,
and `techniques` from common field names and wraps into ECS-min format.

---

### CEF over HTTP

```bash
curl -X POST http://<host>:5000/ingest/cef \
     -H "Content-Type: text/plain" \
     -d 'CEF:0|Vendor|Product|1.0|100|Brute Force|7|src=1.2.3.4 dst=10.0.0.1'
```

---

## How Severity Is Determined (no LLM needed)

Default mode (`MODEL_MODE=local`) classifies threats without any external API:

1. **Syslog priority bits** (RFC 3164/5424):
   Emergency=10, Alert=9, Critical=8, Error=7, Warning=6, Notice=4, Info=2, Debug=1
2. **Keyword scanning** of message text:
   - malware / ransomware / rootkit / shellcode → CRITICAL (9-10)
   - exploit / RCE / privilege escalation / pass-the-hash → HIGH (7-8)
   - brute force / credential stuffing / failed password → HIGH/MEDIUM (6-7)
   - user compromise / account locked / new admin → MEDIUM (5-6)
   - firewall block / IDS alert / port scan → LOW/MEDIUM (4-6)
3. **CEF severity** (0-10 from vendor field, mapped directly)
4. **Splunk/Elastic severity strings** (critical/high/medium/low → 10/8/5/3)

Set `MODEL_MODE=remote` and `LLM_ENDPOINT` to use an Ollama or OpenAI-compatible
endpoint for richer, context-aware analysis.

---

## Minimal Configuration Checklist

| Step | Action |
|------|--------|
| 1 | `cp docker/.env.sample docker/.env` |
| 2 | Edit `inventories/lab/hosts.ini` with your target hosts |
| 3 | Point your SIEM syslog to this host on port 514/UDP or 601/TCP |
| 4 | `docker compose -f docker/docker-compose.yml up -d` |
| 5 | Open http://localhost:8088 to review incidents |
| 6 | Approve → copy the generated command → run on your Ansible control node |

Everything else has working defaults.

---

## What's Included

| Component | Description |
|-----------|-------------|
| **Event Bridge** | UDP 514 + TCP 601 syslog, `/ingest/webhook`, `/ingest/splunk`, `/ingest/elastic`, `/ingest/cef` |
| **Syslog Parser** | RFC 3164, RFC 5424, CEF, LEEF, raw — auto-detected, keyword-classified |
| **Normalizers** | Splunk HEC, Elastic/ECS (ECS 7 + 8), generic JSON wrap |
| **AI Generator** | Template-based playbook selection by severity/category; safety checked |
| **Orchestrator UI** | Dark-theme queue showing severity badge, category, rule, host, indicator IP, MITRE, source format |
| **JSON API** | `GET /api/incidents` for programmatic queue polling |
| **Safety Checks** | Banned modules, dangerous patterns, check_mode enforcement, approval gate validation |
| **OPA Policy** | Scope, risk, and CAB gates |
| **Sample Playbooks** | Windows isolation, Palo Alto IP block, AD user disable, Linux patch |

---

## Optional Configuration

```env
# docker/.env

# Lock to a specific SIEM format (skips auto-detect overhead)
SIEM_TYPE=splunk      # or: elastic | generic | auto

# Change ports if needed (use >1023 for rootless containers)
SYSLOG_UDP_PORT=1514
SYSLOG_TCP_PORT=1601

# Enable auth on the webhook
API_KEY=your-secret-key   # send as: X-API-Key: your-secret-key

# Bring your own LLM
MODEL_MODE=remote
LLM_ENDPOINT=http://ollama:11434/api/generate
```

---

## Compliance

Maps to NIST 800-53 AU, IR, CM, and AC families; STIG artifacts in `EVIDENCE.json`.
Human-in-the-loop is enforced. No autonomous changes.

---

## Production Notes

Lab mode is ready immediately. Production additionally requires:
- TLS termination in front of the webhook port (nginx / traefik)
- Strong `API_KEY` set in `docker/.env`
- Message broker (Redis/RabbitMQ) to replace the file queue
- External log aggregation for immutable audit trails

See [docs/PRODUCTION_DEPLOYMENT.md](docs/PRODUCTION_DEPLOYMENT.md).

---

## Roadmap (stubbed, not yet active)

Canary rollout, ServiceNow CAB webhook, Sigstore signing, Grafana dashboards.
