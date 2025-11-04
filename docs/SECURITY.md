# Security Hardening Guide

## Overview

This document outlines security best practices for deploying SIEM AI in Fourth Estate production environments.

---

## Threat Model

### Assets
- **Security event data**: Contains sensitive incident information
- **Generated playbooks**: May reveal infrastructure details
- **Credentials**: Ansible vault passwords, API keys, SSH keys
- **Audit logs**: Compliance and forensic evidence

### Threats
- **T1**: Unauthorized access to webhook endpoint
- **T2**: Malicious event injection
- **T3**: Playbook tampering
- **T4**: Credential theft
- **T5**: Audit log tampering
- **T6**: Denial of Service

### Mitigations
| Threat | Mitigation | Status |
|--------|-----------|--------|
| T1 | API key authentication | ✅ Implemented |
| T1 | Rate limiting | ✅ Implemented |
| T1 | TLS/HTTPS | ⚠️ Required in production |
| T2 | Input validation | ✅ Implemented |
| T2 | JSON schema validation | ✅ Implemented |
| T3 | Comprehensive safety checks | ✅ Implemented |
| T3 | Manual approval required | ✅ Implemented |
| T4 | Secrets management | ⚠️ Configure vault |
| T4 | Non-root containers | ✅ Implemented |
| T5 | Immutable append-only logs | ⚠️ Configure external logging |
| T6 | Resource limits | ✅ Implemented |
| T6 | Health checks | ✅ Implemented |

---

## Authentication & Authorization

### API Key Authentication

**Generate Strong Keys:**
```bash
# Generate 32-byte random key
openssl rand -base64 32

# Or use Python
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

**Set in Environment:**
```bash
# docker/.env.production
API_KEY=<your-generated-key>
```

**Use in Requests:**
```bash
curl -X POST https://siem-ai.yourdomain.com/ingest/webhook \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d @event.json
```

### mTLS (Mutual TLS) - Recommended

For maximum security, implement mTLS:

```yaml
# nginx.conf
server {
    listen 443 ssl;
    server_name siem-ai.yourdomain.com;

    ssl_certificate /etc/ssl/certs/server.crt;
    ssl_certificate_key /etc/ssl/private/server.key;

    # Require client certificates
    ssl_client_certificate /etc/ssl/certs/ca.crt;
    ssl_verify_client on;

    location / {
        proxy_pass http://event_bridge:5000;
        proxy_set_header X-SSL-Client-Cert $ssl_client_cert;
    }
}
```

---

## Secrets Management

### Option 1: Ansible Vault (Basic)

```bash
# Create vault file
ansible-vault create inventories/production/group_vars/all/vault.yml

# Add secrets
vault_api_key: "your-api-key"
vault_db_password: "your-db-password"
vault_redis_password: "your-redis-password"

# Reference in playbooks
- name: Use secret
  debug:
    msg: "{{ vault_api_key }}"
```

### Option 2: HashiCorp Vault (Recommended)

```hcl
# vault-policy.hcl
path "secret/data/siem-ai/*" {
  capabilities = ["read"]
}

# Store secrets
vault kv put secret/siem-ai/api-key value="your-key"

# Read in application
import hvac
client = hvac.Client(url='https://vault.internal:8200')
secret = client.secrets.kv.v2.read_secret_version(path='siem-ai/api-key')
```

### Option 3: Cloud Secrets Manager

**AWS Secrets Manager:**
```python
import boto3
client = boto3.client('secretsmanager', region_name='us-east-1')
response = client.get_secret_value(SecretId='siem-ai/api-key')
api_key = response['SecretString']
```

**Azure Key Vault:**
```python
from azure.keyvault.secrets import SecretClient
from azure.identity import DefaultAzureCredential

client = SecretClient(vault_url="https://siemvault.vault.azure.net/",
                     credential=DefaultAzureCredential())
api_key = client.get_secret("api-key").value
```

---

## Network Security

### Firewall Rules

```bash
# Allow only necessary ports
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow from 10.0.0.0/8 to any port 5000 proto tcp  # Webhook from internal
sudo ufw allow from 10.0.0.0/8 to any port 8088 proto tcp  # Review UI
sudo ufw allow from 10.0.0.0/8 to any port 514 proto udp   # Syslog
sudo ufw enable
```

### Network Segmentation

```
┌─────────────────┐
│   DMZ Network   │  (Public-facing SIEM)
│   10.1.0.0/24   │
└────────┬────────┘
         │ Firewall
┌────────▼────────┐
│ App Network     │  (SIEM AI Services)
│  10.2.0.0/24    │
└────────┬────────┘
         │ Firewall
┌────────▼────────┐
│ Data Network    │  (Database, Redis)
│  10.3.0.0/24    │
└─────────────────┘
```

### TLS Configuration

```yaml
# docker-compose.production.yml
services:
  event_bridge:
    environment:
      - TLS_ENABLED=true
      - TLS_CERT=/etc/ssl/certs/siem-ai.crt
      - TLS_KEY=/etc/ssl/private/siem-ai.key
      - TLS_MIN_VERSION=1.2
    volumes:
      - /etc/ssl/certs:/etc/ssl/certs:ro
      - /etc/ssl/private:/etc/ssl/private:ro
```

---

## Container Security

### Non-Root User

All Dockerfiles already configured with non-root user:

```dockerfile
RUN groupadd -r siem && useradd -r -g siem -u 1000 siem
USER siem
```

### Read-Only Root Filesystem

```yaml
# docker-compose.production.yml
services:
  event_bridge:
    read_only: true
    tmpfs:
      - /tmp:noexec,nosuid,size=100M
```

### Security Scanning

```bash
# Scan images with Trivy
trivy image siem-ai/event-bridge:latest

# Scan images with Snyk
snyk container test siem-ai/event-bridge:latest
```

### Security Options

```yaml
services:
  event_bridge:
    security_opt:
      - no-new-privileges:true
      - seccomp:unconfined  # Adjust based on needs
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE  # If binding to port < 1024
```

---

## Input Validation

### JSON Schema Validation

Already implemented in `services/event_bridge/app.py`:

```python
from jsonschema import validate, ValidationError

try:
    validate(evt, ECS_MIN)
except ValidationError:
    # Reject or wrap event
```

### Content Security

```python
# Additional validation
def validate_event_content(evt: dict) -> bool:
    """Validate event content for security"""

    # Check for suspicious patterns
    dangerous_patterns = [
        r'<script>',  # XSS
        r'\.\./',     # Path traversal
        r'\x00',      # Null bytes
        r'eval\(',    # Code injection
    ]

    content = json.dumps(evt)
    for pattern in dangerous_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            logger.warning(f"Dangerous pattern detected: {pattern}")
            return False

    return True
```

---

## Audit Logging

### Immutable Audit Trail

```yaml
# docker-compose.production.yml
services:
  audit_logger:
    image: chronograf:latest  # Or InfluxDB
    volumes:
      - audit_data:/var/lib/influxdb
    environment:
      - INFLUXDB_HTTP_AUTH_ENABLED=true
```

### Log Forwarding

```yaml
# filebeat.yml
filebeat.inputs:
  - type: log
    enabled: true
    paths:
      - /var/log/siem/*.log
    fields:
      service: siem-ai
      environment: production
    json.keys_under_root: true

output.elasticsearch:
  hosts: ["elasticsearch.internal:9200"]
  username: "filebeat"
  password: "${ELASTICSEARCH_PASSWORD}"
```

### Audit Event Examples

```python
# services/common/logging_config.py
log_audit_event(logger, 'webhook_received',
               event_id=eid,
               source_ip=request.remote_addr,
               user='system',
               valid_schema=True)

log_audit_event(logger, 'playbook_approved',
               incident_id=inc_id,
               approver='admin@example.com',
               timestamp=datetime.utcnow().isoformat())

log_audit_event(logger, 'playbook_executed',
               incident_id=inc_id,
               success=True,
               changes_made=3)
```

---

## Incident Response

### Security Event Handling

1. **Detection**: Monitor for security events
   ```bash
   # Alert on multiple failed auth attempts
   jq 'select(.level == "WARNING" and .message == "Invalid API key attempt")' /var/log/siem/*.log | wc -l
   ```

2. **Containment**: Block malicious IPs
   ```bash
   sudo ufw deny from <malicious-ip>
   ```

3. **Investigation**: Review audit logs
   ```bash
   # Find all events from suspicious IP
   jq --arg ip "10.1.2.3" 'select(.ip == $ip)' /var/log/siem/audit.log
   ```

4. **Recovery**: Rotate compromised credentials
   ```bash
   # Rotate API key
   openssl rand -base64 32 > new_api_key.txt
   # Update in secrets manager
   vault kv put secret/siem-ai/api-key value="$(cat new_api_key.txt)"
   # Restart services
   docker compose -f docker/docker-compose.production.yml restart
   ```

---

## Compliance

### GDPR Considerations

If processing EU personal data:

- **Data Minimization**: Only collect necessary event data
- **Retention**: Implement log rotation (90 days default)
- **Right to Erasure**: Provide mechanism to delete user data
- **Data Encryption**: Encrypt logs at rest and in transit

### SOC 2 Requirements

- **Access Controls**: Implement RBAC for review UI
- **Audit Logging**: Comprehensive logging implemented
- **Encryption**: TLS for data in transit
- **Monitoring**: Health checks and alerting
- **Incident Response**: Documented procedures

---

## Security Checklist

Before production deployment:

- [ ] Strong API key generated and stored in secrets manager
- [ ] TLS/HTTPS configured with valid certificates
- [ ] mTLS enabled for service-to-service communication
- [ ] Firewall rules configured (allow only necessary ports)
- [ ] Network segmentation implemented
- [ ] Ansible Vault encrypted for all secrets
- [ ] Container images scanned for vulnerabilities
- [ ] Non-root containers verified
- [ ] Read-only root filesystem where possible
- [ ] Resource limits configured
- [ ] Health checks enabled
- [ ] Audit logging to external system
- [ ] Log retention policy configured
- [ ] Incident response runbook created
- [ ] Security monitoring alerts configured
- [ ] Backup and recovery tested
- [ ] Penetration testing completed
- [ ] Security review approved

---

## Additional Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [Ansible Security Automation](https://www.ansible.com/use-cases/security-automation)
