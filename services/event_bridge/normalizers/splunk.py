"""
Splunk HEC (HTTP Event Collector) normaliser.

Handles both single-event and batch HEC payloads.

Typical Splunk HEC payload:
    {
        "time": 1516654932.0,
        "host": "webserver1",
        "source": "syslog",
        "sourcetype": "linux_secure",
        "index": "main",
        "event": {
            "message": "Failed password for root from 1.2.3.4",
            "severity": 7,
            "rule_name": "Brute Force",
            "src_ip": "1.2.3.4",
            ...
        },
        "fields": { ... }
    }

The 'event' field can also be a plain string for raw log lines.
"""

from datetime import datetime


def map_splunk_hec(payload: dict) -> dict:  # noqa: C901
    """
    Normalise a Splunk HEC JSON payload into ECS-min format.

    Handles both dict and string 'event' values.
    """
    # Splunk batch: array of events
    if isinstance(payload, list):
        # Return the first event; caller can loop for batches
        if payload:
            return map_splunk_hec(payload[0])
        return _empty_event()

    raw_event = payload.get("event", {})

    # 'event' may be a plain string (raw log line)
    if isinstance(raw_event, str):
        from .syslog_parser import parse as parse_syslog

        src_ip = payload.get("host", "0.0.0.0")
        evt = parse_syslog(raw_event, source_ip=src_ip)
        # Override timestamp from HEC 'time' field if present (use is not None — 0.0 is valid)
        if payload.get("time") is not None:
            try:
                ts = datetime.utcfromtimestamp(float(payload["time"])).isoformat() + "Z"
                evt["@timestamp"] = ts
            except (ValueError, TypeError):
                pass
        return evt

    # Merge top-level HEC fields with nested event fields
    fields = payload.get("fields", {})
    merged = {**raw_event, **fields}

    # Resolve timestamp: HEC 'time' (epoch) takes priority (use is not None — 0.0 is valid)
    ts = None
    if payload.get("time") is not None:
        try:
            ts = datetime.utcfromtimestamp(float(payload["time"])).isoformat() + "Z"
        except (ValueError, TypeError):
            pass
    if not ts:
        ts = (
            merged.get("@timestamp")
            or merged.get("timestamp")
            or datetime.utcnow().isoformat() + "Z"
        )

    # Resolve severity (accepts int, float, or string like "high"/"medium"/"low")
    raw_sev = merged.get("severity", merged.get("sev", 5))
    severity = _coerce_severity(raw_sev)

    # Resolve source IP
    src_ip = (
        merged.get("src_ip")
        or merged.get("sourceAddress")
        or merged.get("src")
        or payload.get("host", "0.0.0.0")
    )

    # Resolve event ID
    event_id = (
        merged.get("event_id")
        or merged.get("id")
        or "splunk-" + str(abs(hash(str(payload))))
    )

    # Resolve category
    category = (
        merged.get("category")
        or merged.get("type")
        or merged.get("sourcetype")
        or payload.get("sourcetype", "unknown")
    )

    # Resolve rule / alert name
    rule = (
        merged.get("rule_name")
        or merged.get("rule")
        or merged.get("alert_name")
        or merged.get("name")
        or "splunk_alert"
    )

    # Resolve risk score
    try:
        risk_score = float(
            merged.get("risk_score") or merged.get("risk") or severity * 10
        )
    except (ValueError, TypeError):
        risk_score = float(severity * 10)

    # Resolve MITRE techniques
    techniques = merged.get("techniques") or merged.get("mitre_techniques") or []
    if isinstance(techniques, str):
        techniques = [t.strip() for t in techniques.split(",") if t.strip()]

    return {
        "@timestamp": ts,
        "event": {
            "id": str(event_id),
            "category": str(category),
            "dataset": "splunk.hec",
        },
        "alert": {
            "severity": severity,
            "rule": str(rule),
            "risk_score": risk_score,
            "techniques": techniques,
        },
        "host": {
            "hostname": str(payload.get("host") or merged.get("hostname") or src_ip),
            "ip": str(src_ip),
        },
        "indicator": {
            "ip": merged.get("dest_ip")
            or merged.get("dst_ip")
            or merged.get("indicator_ip"),
        },
        "message": str(merged.get("message") or merged.get("msg") or ""),
    }


def _coerce_severity(raw) -> int:
    """Convert a severity value of any type to an int in [1, 10]."""
    if isinstance(raw, (int, float)):
        return max(1, min(10, int(raw)))
    if isinstance(raw, str):
        mapping = {
            "critical": 10,
            "high": 8,
            "medium": 5,
            "low": 3,
            "informational": 2,
            "info": 2,
            "unknown": 4,
        }
        return mapping.get(raw.lower().strip(), 5)
    return 5


def _empty_event() -> dict:
    return {
        "@timestamp": datetime.utcnow().isoformat() + "Z",
        "event": {"id": "splunk-empty", "category": "unknown", "dataset": "splunk.hec"},
        "alert": {"severity": 1, "rule": "empty", "risk_score": 10.0, "techniques": []},
        "host": {"hostname": "unknown", "ip": "0.0.0.0"},
        "indicator": {},
        "message": "",
    }
