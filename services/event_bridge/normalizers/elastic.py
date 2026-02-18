"""
Elastic / ECS normaliser.

Handles events from:
  - Elastic SIEM / Security Detection Engine alerts
  - Kibana Watcher actions
  - Logstash http output plugin
  - Elastic Agent / Fleet alerts (ECS 8.x)
  - Wazuh (which outputs ECS-compatible JSON)

Typical Elastic SIEM alert payload (ECS 8.x):
    {
        "@timestamp": "2024-01-15T12:00:00Z",
        "event": { "kind": "alert", "category": ["intrusion_detection"], "id": "abc" },
        "rule": { "name": "Suspicious Process", "id": "rule-001", "severity": "high" },
        "host": { "name": "webserver", "ip": ["10.0.0.1"] },
        "source": { "ip": "1.2.3.4" },
        "destination": { "ip": "10.0.0.1" },
        "kibana.alert.risk_score": 75,
        "kibana.alert.severity": "high",
        "threat.technique.id": ["T1059.001"],
        ...
    }
"""

from datetime import datetime

# Elastic severity strings → int (1-10)
_ELASTIC_SEV = {
    "critical": 10,
    "high": 8,
    "medium": 5,
    "low": 3,
    "informational": 2,
    "info": 2,
}


def map_elastic(payload: dict) -> dict:  # noqa: C901
    """
    Normalise an Elastic/ECS alert payload into ECS-min format.
    """
    if not isinstance(payload, dict):
        return _empty_event()

    # ------------------------------------------------------------------
    # Timestamp
    # ------------------------------------------------------------------
    ts = (
        payload.get("@timestamp")
        or payload.get("timestamp")
        or datetime.utcnow().isoformat() + "Z"
    )

    # ------------------------------------------------------------------
    # Event metadata
    # ------------------------------------------------------------------
    evt_block = payload.get("event", {})
    event_id = (
        evt_block.get("id")
        or payload.get("kibana.alert.uuid")
        or "es-" + str(abs(hash(str(payload))))
    )

    # category can be a list (ECS 8) or a string
    raw_cat = evt_block.get("category", "unknown")
    if isinstance(raw_cat, list):
        category = raw_cat[0] if raw_cat else "unknown"
    else:
        category = raw_cat or "unknown"

    # ------------------------------------------------------------------
    # Rule / alert name
    # ------------------------------------------------------------------
    rule_block = payload.get("rule", {})
    rule_name = (
        rule_block.get("name")
        or payload.get("kibana.alert.rule.name")
        or payload.get("signal", {}).get("rule", {}).get("name")
        or "elastic_alert"
    )

    # ------------------------------------------------------------------
    # Severity
    # ------------------------------------------------------------------
    # Priority: kibana.alert.severity > rule.severity > event.severity > numeric
    raw_sev = (
        payload.get("kibana.alert.severity")
        or rule_block.get("severity")
        or evt_block.get("severity")
        or payload.get("signal", {}).get("rule", {}).get("severity")
    )

    if isinstance(raw_sev, str):
        severity = _ELASTIC_SEV.get(raw_sev.lower().strip(), 5)
    elif isinstance(raw_sev, (int, float)):
        severity = max(1, min(10, int(raw_sev)))
    else:
        severity = 5

    # ------------------------------------------------------------------
    # Risk score
    # ------------------------------------------------------------------
    raw_risk = (
        payload.get("kibana.alert.risk_score")
        or rule_block.get("risk_score")
        or payload.get("signal", {}).get("rule", {}).get("risk_score")
    )
    try:
        risk_score = float(raw_risk) if raw_risk is not None else float(severity * 10)
    except (ValueError, TypeError):
        risk_score = float(severity * 10)

    # ------------------------------------------------------------------
    # MITRE techniques
    # ------------------------------------------------------------------
    techniques = []
    # ECS 8 stores them under threat.technique.id
    threat = payload.get("threat", {})
    if isinstance(threat, dict):
        tech_ids = threat.get("technique", {}).get("id", [])
        if isinstance(tech_ids, list):
            techniques = tech_ids
        elif isinstance(tech_ids, str):
            techniques = [tech_ids]
    # Fallback: signal.rule.threat in older Elastic SIEM
    if not techniques:
        signal_threats = payload.get("signal", {}).get("rule", {}).get("threat", [])
        for t in signal_threats:
            for tech in t.get("technique", []):
                if tech.get("id"):
                    techniques.append(tech["id"])

    # ------------------------------------------------------------------
    # Host
    # ------------------------------------------------------------------
    host_block = payload.get("host", {})
    hostname = host_block.get("name") or host_block.get("hostname") or "unknown"
    # host.ip can be a list in ECS 8
    raw_host_ip = host_block.get("ip", "0.0.0.0")
    if isinstance(raw_host_ip, list):
        host_ip = raw_host_ip[0] if raw_host_ip else "0.0.0.0"
    else:
        host_ip = str(raw_host_ip) if raw_host_ip else "0.0.0.0"

    # ------------------------------------------------------------------
    # Source / indicator IP
    # ------------------------------------------------------------------
    src_block = payload.get("source", {})
    src_ip = src_block.get("ip") or host_ip

    dst_block = payload.get("destination", {})
    dst_ip = dst_block.get("ip")

    # ------------------------------------------------------------------
    # Message
    # ------------------------------------------------------------------
    message = payload.get("message") or payload.get("kibana.alert.reason") or ""

    return {
        "@timestamp": ts,
        "event": {
            "id": str(event_id),
            "category": category,
            "dataset": "elastic.siem",
        },
        "alert": {
            "severity": severity,
            "rule": str(rule_name),
            "risk_score": risk_score,
            "techniques": techniques,
        },
        "host": {
            "hostname": str(hostname),
            "ip": str(src_ip),
        },
        "indicator": {
            "ip": dst_ip,
        },
        "message": str(message),
    }


def _empty_event() -> dict:
    return {
        "@timestamp": datetime.utcnow().isoformat() + "Z",
        "event": {"id": "es-empty", "category": "unknown", "dataset": "elastic.siem"},
        "alert": {"severity": 1, "rule": "empty", "risk_score": 10.0, "techniques": []},
        "host": {"hostname": "unknown", "ip": "0.0.0.0"},
        "indicator": {},
        "message": "",
    }
