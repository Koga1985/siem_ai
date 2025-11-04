# Production Deployment Guide

## ⚠️ Production Readiness Checklist

Before deploying to production, ensure you have completed ALL items below:

### Security Requirements
- [ ] **API Key Authentication**: Set strong API key for webhook endpoint
- [ ] **TLS/SSL**: Configure HTTPS with valid certificates
- [ ] **Secrets Management**: Use HashiCorp Vault, AWS Secrets Manager, or Azure Key Vault
- [ ] **Ansible Vault**: Encrypt all sensitive inventory variables
- [ ] **Host Key Checking**: Enable in ansible.cfg (disabled in lab mode)
- [ ] **Network Segmentation**: Deploy services in isolated network
- [ ] **Firewall Rules**: Restrict access to management ports

### Reliability Requirements
- [ ] **Message Broker**: Replace file-based queue with Redis/RabbitMQ
- [ ] **Database**: Add PostgreSQL/MongoDB for persistent state
- [ ] **Backup Strategy**: Implement automated backups
- [ ] **High Availability**: Deploy multiple instances behind load balancer
- [ ] **Monitoring**: Configure Prometheus + Grafana
- [ ] **Alerting**: Set up PagerDuty/Opsgenie integration
- [ ] **Log Aggregation**: Forward logs to ELK/Splunk

### Operational Requirements
- [ ] **Runbooks**: Create incident response procedures
- [ ] **Disaster Recovery**: Document and test DR procedures
- [ ] **Change Management**: Integrate with ServiceNow/Jira
- [ ] **Audit Trail**: Enable immutable audit logging
- [ ] **Compliance**: Complete NIST 800-53 control mapping

---

## Architecture Overview

```
                                  ┌─────────────┐
                                  │   SIEM      │
                                  │ (Splunk/ELK)│
                                  └──────┬──────┘
                                         │
                            ┌────────────┴────────────┐
                            │                         │
                      Webhook/Syslog            Alert Rules
                            │                         │
                   ┌────────▼────────┐               │
                   │  Event Bridge   │◄──────────────┘
                   │  (Flask + Auth) │
                   └────────┬────────┘
                            │
                   ┌────────▼────────┐
                   │ Message Queue   │
                   │ (Redis/RabbitMQ)│
                   └────────┬────────┘
                            │
                   ┌────────▼────────┐
                   │  AI Generator   │
                   │ (Playbook Gen)  │
                   └────────┬────────┘
                            │
                     Safety Checks
                            │
                   ┌────────▼────────┐
                   │  Orchestrator   │
                   │  (Review UI)    │
                   └────────┬────────┘
                            │
                   Manual Approval
                            │
                   ┌────────▼────────┐
                   │ Ansible Runner  │
                   │  (Check Mode)   │
                   └─────────────────┘
```

---

## Environment Configuration

### 1. Production Environment Variables

Create `docker/.env.production`:

```bash
# Service Ports
WEBHOOK_PORT=5000
REVIEW_UI_PORT=8088
SYSLOG_UDP_PORT=514

# Security
API_KEY=<generate-strong-random-key-32-chars>
TLS_CERT_PATH=/etc/ssl/certs/siem-ai.crt
TLS_KEY_PATH=/etc/ssl/private/siem-ai.key

# Rate Limiting
RATE_LIMIT=100 per minute

# Logging
LOG_LEVEL=INFO
LOG_FILE=/var/log/siem/service.log

# Message Broker (replace file queue)
REDIS_HOST=redis.internal
REDIS_PORT=6379
REDIS_PASSWORD=<vault-reference>
REDIS_DB=0

# Database
DB_HOST=postgres.internal
DB_PORT=5432
DB_NAME=siem_ai
DB_USER=siem_app
DB_PASSWORD=<vault-reference>

# AI Model (if using remote)
MODEL_MODE=remote
LLM_ENDPOINT=https://llm.internal/v1/completions
LLM_API_KEY=<vault-reference>

# Monitoring
PROMETHEUS_PORT=9090
METRICS_ENABLED=true

# Feature Flags
DUAL_CONTROL_ENABLED=true
CAB_WEBHOOK=https://servicenow.internal/api/cab/request
```

### 2. Generate Strong API Key

```bash
openssl rand -base64 32 > api_key.txt
chmod 600 api_key.txt
# Store in secrets manager, not in repo!
```

### 3. TLS Certificate Setup

```bash
# For production, use Let's Encrypt or your CA
# Example with self-signed (testing only):
openssl req -x509 -newkey rsa:4096 \
  -keyout key.pem -out cert.pem \
  -days 365 -nodes \
  -subj "/CN=siem-ai.yourdomain.com"
```

---

## Deployment Steps

### Option A: Docker Compose (Small Scale)

```bash
# 1. Clone repository
git clone https://github.com/Koga1985/seim_ai.git
cd seim_ai

# 2. Configure secrets (see Secrets Management section)
./scripts/setup_secrets.sh

# 3. Configure environment
cp docker/.env.sample docker/.env.production
# Edit docker/.env.production with production values

# 4. Build images
docker compose -f docker/docker-compose.production.yml build

# 5. Run database migrations (if applicable)
docker compose -f docker/docker-compose.production.yml run --rm orchestrator python migrate.py

# 6. Start services
docker compose -f docker/docker-compose.production.yml up -d

# 7. Verify health
curl https://localhost:5000/health
curl https://localhost:8088/
```

### Option B: Kubernetes (Enterprise Scale)

```bash
# 1. Create namespace
kubectl create namespace siem-ai

# 2. Deploy secrets
kubectl apply -f k8s/secrets/

# 3. Deploy PostgreSQL (or use managed RDS)
kubectl apply -f k8s/postgres/

# 4. Deploy Redis
kubectl apply -f k8s/redis/

# 5. Deploy SIEM AI services
kubectl apply -f k8s/services/

# 6. Deploy ingress
kubectl apply -f k8s/ingress/

# 7. Verify
kubectl get pods -n siem-ai
kubectl logs -n siem-ai deployment/event-bridge
```

---

## Secrets Management

### Using Ansible Vault

```bash
# 1. Create vault password file
echo "your-vault-password" > ~/.ansible_vault_pass
chmod 600 ~/.ansible_vault_pass

# 2. Encrypt sensitive inventory variables
ansible-vault encrypt_string 'your_password' --name 'vault_windows_password'

# 3. Store in group_vars/production/vault.yml
cat > inventories/production/group_vars/all/vault.yml <<EOF
vault_api_key: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          ...encrypted...
vault_db_password: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          ...encrypted...
EOF

ansible-vault encrypt inventories/production/group_vars/all/vault.yml
```

### Using HashiCorp Vault

```bash
# 1. Install Vault
# See: https://www.vaultproject.io/downloads

# 2. Initialize Vault
vault server -dev  # For testing only!

# 3. Store secrets
vault kv put secret/siem-ai/api-key value="your-api-key"
vault kv put secret/siem-ai/db-password value="your-db-pass"

# 4. Configure service to read from Vault
export VAULT_ADDR='https://vault.internal:8200'
export VAULT_TOKEN='s.xxxxxxxxxxxxx'
```

### Environment-Specific Secrets

Never commit secrets to git. Use:
- AWS Secrets Manager (AWS)
- Azure Key Vault (Azure)
- Google Secret Manager (GCP)
- HashiCorp Vault (On-prem)

---

## Monitoring and Observability

### Prometheus Metrics

Add to `docker-compose.production.yml`:

```yaml
  prometheus:
    image: prom/prometheus:latest
    ports:
      - "9090:9090"
    volumes:
      - ./monitoring/prometheus.yml:/etc/prometheus/prometheus.yml
      - prometheus_data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'

  grafana:
    image: grafana/grafana:latest
    ports:
      - "3000:3000"
    volumes:
      - grafana_data:/var/lib/grafana
      - ./monitoring/grafana/dashboards:/etc/grafana/provisioning/dashboards
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=<vault-reference>
```

### Log Aggregation

```yaml
  filebeat:
    image: docker.elastic.co/beats/filebeat:8.11.0
    volumes:
      - logs:/var/log/siem:ro
      - ./monitoring/filebeat.yml:/usr/share/filebeat/filebeat.yml:ro
```

### Alerting Rules

Create `monitoring/alerts.yml`:

```yaml
groups:
  - name: siem_ai_alerts
    rules:
      - alert: ServiceDown
        expr: up{job="siem-ai"} == 0
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "SIEM AI service is down"

      - alert: HighErrorRate
        expr: rate(errors_total[5m]) > 0.05
        for: 10m
        labels:
          severity: warning
```

---

## Backup and Recovery

### Automated Backups

```bash
#!/bin/bash
# backup.sh - Run daily via cron

DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/backups/siem-ai/$DATE"

# Backup PostgreSQL
pg_dump -h $DB_HOST -U $DB_USER siem_ai | gzip > "$BACKUP_DIR/db.sql.gz"

# Backup playbooks and evidence
tar -czf "$BACKUP_DIR/playbooks.tar.gz" /repo/playbooks/_library/

# Backup logs (last 7 days)
find /var/log/siem -mtime -7 | tar -czf "$BACKUP_DIR/logs.tar.gz" -T -

# Upload to S3/Azure Blob
aws s3 cp "$BACKUP_DIR" s3://backups/siem-ai/ --recursive

# Retain last 30 days
find /backups/siem-ai -type d -mtime +30 -exec rm -rf {} \;
```

### Disaster Recovery

```bash
# 1. Restore database
gunzip < db.sql.gz | psql -h $DB_HOST -U $DB_USER siem_ai

# 2. Restore playbooks
tar -xzf playbooks.tar.gz -C /repo/playbooks/

# 3. Restart services
docker compose -f docker/docker-compose.production.yml restart
```

---

## Performance Tuning

### Database Indexing

```sql
-- Add indexes for common queries
CREATE INDEX idx_events_timestamp ON events(timestamp DESC);
CREATE INDEX idx_incidents_status ON incidents(status);
CREATE INDEX idx_audit_log_event_type ON audit_log(event_type);
```

### Redis Configuration

```conf
# /etc/redis/redis.conf
maxmemory 2gb
maxmemory-policy allkeys-lru
appendonly yes
appendfsync everysec
```

### Gunicorn Tuning

```python
# gunicorn_config.py
workers = (2 * cpu_count()) + 1
worker_class = 'gevent'
worker_connections = 1000
max_requests = 10000
max_requests_jitter = 1000
timeout = 30
keepalive = 5
```

---

## Compliance and Auditing

### NIST 800-53 Controls

| Control | Implementation |
|---------|---------------|
| AU-2 | Structured JSON logging with audit events |
| AU-3 | Log content includes timestamp, user, action, result |
| AU-6 | Grafana dashboards for log review |
| AU-9 | Immutable append-only logs |
| CM-3 | Manual approval required for all changes |
| CM-7 | Minimal Docker images, no unnecessary services |
| IA-2 | API key authentication |
| SC-7 | Network segmentation, firewall rules |

### Audit Log Queries

```bash
# Find all playbook executions
jq 'select(.event_type == "playbook_generated")' /var/log/siem/audit.log

# Find all approval events
jq 'select(.event_type == "playbook_approved")' /var/log/siem/audit.log

# Find failed safety checks
jq 'select(.event_type == "playbook_rejected")' /var/log/siem/audit.log
```

---

## Troubleshooting

### Service Won't Start

```bash
# Check logs
docker compose -f docker/docker-compose.production.yml logs event_bridge

# Check health
docker compose -f docker/docker-compose.production.yml ps
curl http://localhost:5000/health

# Restart service
docker compose -f docker/docker-compose.production.yml restart event_bridge
```

### Webhook Not Receiving Events

```bash
# Test webhook manually
curl -X POST http://localhost:5000/ingest/webhook \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d @test_event.json

# Check firewall
sudo iptables -L -n | grep 5000

# Check logs
tail -f /var/log/siem/event_bridge.log | jq .
```

### Playbook Generation Stuck

```bash
# Check queue
ls -la /repo/services/event_bridge/queue/

# Check AI generator logs
docker logs siem_ai_generator

# Check for failed events
ls -la /repo/services/event_bridge/queue/failed/
```

---

## Support and Escalation

### Internal Runbook

1. **Service Degradation**: Check monitoring dashboards
2. **Critical Incident**: Page on-call engineer
3. **Security Event**: Notify SOC immediately
4. **Data Loss**: Initiate backup restore procedure

### Contact

- **Primary**: siem-ai-oncall@yourdomain.com
- **Slack**: #siem-ai-alerts
- **Emergency**: PagerDuty escalation policy

---

## Additional Resources

- [Architecture Decision Records](./ADR/)
- [API Documentation](./API.md)
- [Security Best Practices](./SECURITY.md)
- [Runbook Templates](./runbooks/)
