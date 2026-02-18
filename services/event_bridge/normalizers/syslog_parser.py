"""
Universal syslog parser supporting RFC 3164, RFC 5424, CEF, and LEEF formats.
Includes keyword-based threat classification for LLM-free operation.
"""
import re
from datetime import datetime
from typing import Optional

# ---------------------------------------------------------------------------
# Severity / facility mappings
# ---------------------------------------------------------------------------

# RFC 3164/5424 severity (0-7) → tool severity (1-10)
SYSLOG_SEV_MAP = {0: 10, 1: 9, 2: 8, 3: 7, 4: 6, 5: 4, 6: 2, 7: 1}

# Syslog facility codes → human label
FACILITY_NAMES = {
    0: "kernel", 1: "user", 2: "mail", 3: "daemon", 4: "auth",
    5: "syslog", 6: "lpr", 7: "news", 8: "uucp", 9: "cron",
    10: "authpriv", 11: "ftp", 16: "local0", 17: "local1",
    18: "local2", 19: "local3", 20: "local4", 21: "local5",
    22: "local6", 23: "local7",
}

# ---------------------------------------------------------------------------
# Keyword-based threat classification
# ---------------------------------------------------------------------------

# Ordered by priority (first match wins).  Each entry: (category, sev_floor, [keywords])
THREAT_RULES = [
    ("malware",             9, ["malware", "ransomware", "trojan", "virus", "worm",
                                "cryptominer", "rootkit", "spyware", "botnet"]),
    ("malware",             8, ["suspicious process", "process injection", "hollowing",
                                "reflective dll", "shellcode", "cobalt strike", "meterpreter"]),
    ("intrusion_detection", 8, ["exploit", "remote code execution", "rce", "buffer overflow",
                                "sql injection", "command injection", "privilege escalation",
                                "lateral movement", "pass-the-hash", "pass the hash",
                                "kerberoasting", "golden ticket", "silver ticket"]),
    ("intrusion_detection", 7, ["brute force", "brute-force", "password spray",
                                "credential stuffing", "authentication failure",
                                "failed password", "login failure", "logon failure",
                                "too many authentication failures"]),
    ("user_compromise",     8, ["account compromised", "unauthorized access",
                                "impossible travel", "anomalous login"]),
    ("user_compromise",     6, ["user disabled", "account locked", "account disabled",
                                "password change", "permission change", "privilege granted",
                                "added to group", "new admin"]),
    ("intrusion_detection", 6, ["port scan", "network scan", "nmap", "reconnaissance",
                                "blocked", "denied access", "firewall drop",
                                "ids alert", "ips alert", "snort", "suricata",
                                "connection refused", "invalid user"]),
    ("intrusion_detection", 5, ["failed", "failure", "error", "refused", "rejected",
                                "forbidden", "unauthorized"]),
    ("configuration_change", 4, ["config change", "policy change", "rule added",
                                 "rule removed", "settings modified", "sudo",
                                 "setuid", "chmod 777"]),
]

# Severity boost keywords (applied on top of syslog priority)
SEVERITY_BOOST = [
    (3, ["emergency", "critical", "fatal", "panic"]),
    (2, ["alert", "high severity", "high risk", "severity: high"]),
    (1, ["warning", "warn", "medium severity", "severity: medium"]),
]


def _classify(message: str) -> tuple[str, int]:
    """
    Return (category, severity_floor) based on keyword matching.
    Falls back to ("unknown", 0).
    """
    lower = message.lower()
    for category, sev_floor, keywords in THREAT_RULES:
        if any(kw in lower for kw in keywords):
            return category, sev_floor
    return "unknown", 0


def _severity_boost(message: str) -> int:
    """Return additional severity points from high-signal keywords."""
    lower = message.lower()
    for boost, keywords in SEVERITY_BOOST:
        if any(kw in lower for kw in keywords):
            return boost
    return 0


def _clamp(value: int, lo: int = 1, hi: int = 10) -> int:
    return max(lo, min(hi, value))


# ---------------------------------------------------------------------------
# Format detectors & parsers
# ---------------------------------------------------------------------------

_RFC5424_RE = re.compile(
    r"^<(\d{1,3})>(\d+)\s+"          # priority, version
    r"(\S+)\s+"                        # timestamp
    r"(\S+)\s+"                        # hostname
    r"(\S+)\s+"                        # app-name
    r"(\S+)\s+"                        # procid
    r"(\S+)\s+"                        # msgid
    r"(\S+)\s*"                        # structured-data
    r"(.*)$",                          # message
    re.DOTALL,
)

_RFC3164_RE = re.compile(
    r"^<(\d{1,3})>"                    # priority
    r"(\w{3}\s+\d{1,2}\s+[\d:]+)\s+"  # timestamp (Mmm DD HH:MM:SS)
    r"(\S+)\s+"                        # hostname
    r"(.+)$",                          # tag + message
    re.DOTALL,
)

_CEF_RE = re.compile(
    r"^(?:<\d+>)?(?:\w{3}\s+\d{1,2}\s+[\d:]+\s+\S+\s+)?"  # optional syslog header
    r"CEF:(\d+)\|"                     # CEF version
    r"([^|]*)\|"                       # device vendor
    r"([^|]*)\|"                       # device product
    r"([^|]*)\|"                       # device version
    r"([^|]*)\|"                       # signature id
    r"([^|]*)\|"                       # name
    r"(\d+)\|"                         # severity (0-10)
    r"(.*)",                           # extensions
    re.DOTALL,
)

_LEEF_RE = re.compile(
    r"^(?:<\d+>)?(?:\w{3}\s+\d{1,2}\s+[\d:]+\s+\S+\s+)?"  # optional syslog header
    r"LEEF:(\d+\.\d+|\d+)\|"          # LEEF version
    r"([^|]*)\|"                       # vendor
    r"([^|]*)\|"                       # product
    r"([^|]*)\|"                       # version
    r"([^|]*)\|?"                      # event id
    r"(.*)",                           # attributes
    re.DOTALL,
)


def _parse_cef_extensions(ext_str: str) -> dict:
    """Parse CEF key=value extension string into a dict."""
    result = {}
    # CEF extensions can have quoted values or spaces in values before next key
    tokens = re.findall(r"(\w+)=((?:[^=\\]|\\.)*?)(?=\s+\w+=|$)", ext_str.strip())
    for key, val in tokens:
        result[key] = val.strip()
    return result


def _parse_leef_attrs(attr_str: str, delimiter: str = "\t") -> dict:
    """Parse LEEF attribute string into a dict."""
    result = {}
    # LEEF 2.0 may start with a custom delimiter line
    for pair in attr_str.split(delimiter):
        pair = pair.strip()
        if "=" in pair:
            k, _, v = pair.partition("=")
            result[k.strip()] = v.strip()
    return result


def _ts_now() -> str:
    return datetime.utcnow().isoformat() + "Z"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def detect_format(raw: str) -> str:
    """Return detected format: 'cef', 'leef', 'rfc5424', 'rfc3164', or 'raw'."""
    s = raw.lstrip()
    # Strip optional syslog header before checking CEF/LEEF
    stripped = re.sub(r"^<\d+>[\w:\s]+\S+\s+", "", s)
    if stripped.upper().startswith("CEF:"):
        return "cef"
    if stripped.upper().startswith("LEEF:"):
        return "leef"
    if _RFC5424_RE.match(s):
        return "rfc5424"
    if _RFC3164_RE.match(s):
        return "rfc3164"
    return "raw"


def parse(raw: str, source_ip: str = "0.0.0.0") -> dict:
    """
    Parse a syslog/CEF/LEEF message into a normalised ECS-min event dict.

    Args:
        raw:       Raw message string (UDP datagram or TCP line).
        source_ip: IP address of the sending host.

    Returns:
        ECS-min compatible event dict ready for enqueue().
    """
    fmt = detect_format(raw)
    if fmt == "cef":
        return _parse_cef(raw, source_ip)
    if fmt == "leef":
        return _parse_leef(raw, source_ip)
    if fmt == "rfc5424":
        return _parse_rfc5424(raw, source_ip)
    if fmt == "rfc3164":
        return _parse_rfc3164(raw, source_ip)
    return _parse_raw(raw, source_ip)


# ---------------------------------------------------------------------------
# Format-specific parsers
# ---------------------------------------------------------------------------

def _parse_rfc3164(raw: str, source_ip: str) -> dict:
    m = _RFC3164_RE.match(raw.strip())
    if not m:
        return _parse_raw(raw, source_ip)

    priority = int(m.group(1))
    facility = priority >> 3
    syslog_sev = priority & 0x07
    timestamp_str = m.group(2)
    hostname = m.group(3)
    rest = m.group(4)

    # Split tag from message: "sshd[1234]: message"
    tag_match = re.match(r"^(\S+?)(?:\[\d+\])?:\s*(.*)", rest, re.DOTALL)
    if tag_match:
        tag = tag_match.group(1)
        message = tag_match.group(2)
    else:
        tag = "syslog"
        message = rest

    # Build severity
    base_sev = SYSLOG_SEV_MAP.get(syslog_sev, 4)
    category, cat_floor = _classify(message)
    boost = _severity_boost(message)
    severity = _clamp(max(base_sev, cat_floor) + boost)
    risk_score = _clamp(severity * 10, lo=10, hi=100)

    return {
        "@timestamp": _ts_now(),
        "event": {
            "id": str(abs(hash(raw + _ts_now()))),
            "category": category,
            "dataset": "syslog.rfc3164",
        },
        "alert": {
            "severity": severity,
            "rule": tag,
            "risk_score": float(risk_score),
            "techniques": [],
        },
        "host": {"hostname": hostname or source_ip, "ip": source_ip},
        "indicator": {},
        "message": message[:2000],
        "log": {
            "syslog": {
                "facility": {"code": facility, "name": FACILITY_NAMES.get(facility, str(facility))},
                "severity": {"code": syslog_sev},
            }
        },
    }


def _parse_rfc5424(raw: str, source_ip: str) -> dict:
    m = _RFC5424_RE.match(raw.strip())
    if not m:
        return _parse_raw(raw, source_ip)

    priority = int(m.group(1))
    facility = priority >> 3
    syslog_sev = priority & 0x07
    timestamp_str = m.group(3)
    hostname = m.group(4)
    app_name = m.group(5)
    message = m.group(9).strip()

    base_sev = SYSLOG_SEV_MAP.get(syslog_sev, 4)
    category, cat_floor = _classify(message)
    boost = _severity_boost(message)
    severity = _clamp(max(base_sev, cat_floor) + boost)
    risk_score = _clamp(severity * 10, lo=10, hi=100)

    return {
        "@timestamp": timestamp_str if timestamp_str != "-" else _ts_now(),
        "event": {
            "id": str(abs(hash(raw + _ts_now()))),
            "category": category,
            "dataset": "syslog.rfc5424",
        },
        "alert": {
            "severity": severity,
            "rule": app_name if app_name != "-" else "syslog",
            "risk_score": float(risk_score),
            "techniques": [],
        },
        "host": {"hostname": hostname if hostname != "-" else source_ip, "ip": source_ip},
        "indicator": {},
        "message": message[:2000],
        "log": {
            "syslog": {
                "facility": {"code": facility, "name": FACILITY_NAMES.get(facility, str(facility))},
                "severity": {"code": syslog_sev},
            }
        },
    }


def _parse_cef(raw: str, source_ip: str) -> dict:
    m = _CEF_RE.match(raw.strip())
    if not m:
        return _parse_raw(raw, source_ip)

    vendor = m.group(2).strip()
    product = m.group(3).strip()
    sig_id = m.group(5).strip()
    name = m.group(6).strip()
    cef_sev = int(m.group(7))
    ext_str = m.group(8)

    ext = _parse_cef_extensions(ext_str)

    # Map CEF severity (0-10) to tool severity (1-10)
    severity = _clamp(cef_sev if cef_sev > 0 else 1)

    # Enrich with keyword classification from name + message
    message = ext.get("msg", ext.get("message", name))
    category, cat_floor = _classify(name + " " + message)
    boost = _severity_boost(name + " " + message)
    severity = _clamp(max(severity, cat_floor) + boost)
    risk_score = _clamp(severity * 10, lo=10, hi=100)

    # Extract common extension fields
    src_ip = ext.get("src", ext.get("sourceAddress", source_ip))
    dst_ip = ext.get("dst", ext.get("destinationAddress", ""))
    src_host = ext.get("shost", ext.get("sourceHostName", src_ip))

    return {
        "@timestamp": ext.get("rt", _ts_now()),
        "event": {
            "id": ext.get("externalId", str(abs(hash(raw + _ts_now())))),
            "category": category,
            "dataset": "cef",
        },
        "alert": {
            "severity": severity,
            "rule": f"{vendor}/{product}: {name}",
            "risk_score": float(risk_score),
            "techniques": [],
        },
        "host": {"hostname": src_host, "ip": src_ip},
        "indicator": {"ip": dst_ip or None},
        "message": message[:2000],
        "cef": {"vendor": vendor, "product": product, "sig_id": sig_id},
    }


def _parse_leef(raw: str, source_ip: str) -> dict:
    m = _LEEF_RE.match(raw.strip())
    if not m:
        return _parse_raw(raw, source_ip)

    vendor = m.group(2).strip()
    product = m.group(3).strip()
    event_id = m.group(5).strip()
    attr_str = m.group(6)

    # LEEF 2.0 allows custom delimiter as first char after event id
    delimiter = "\t"
    if m.group(1) in ("2", "2.0") and attr_str and attr_str[0] not in ("s", "d", "\t"):
        delimiter = attr_str[0]
        attr_str = attr_str[1:]

    attrs = _parse_leef_attrs(attr_str, delimiter)

    # Severity: usrName, severity, cat, devTime are common LEEF fields
    raw_sev = attrs.get("severity", attrs.get("sev", "5"))
    try:
        sev_int = int(float(raw_sev))
    except (ValueError, TypeError):
        sev_int = 5

    # LEEF severity is typically 1-10 already
    severity = _clamp(sev_int if sev_int > 0 else 1)

    name = attrs.get("cat", attrs.get("eventName", event_id))
    message = attrs.get("msg", name)
    category, cat_floor = _classify(name + " " + message)
    boost = _severity_boost(name + " " + message)
    severity = _clamp(max(severity, cat_floor) + boost)
    risk_score = _clamp(severity * 10, lo=10, hi=100)

    src_ip = attrs.get("src", attrs.get("srcIP", source_ip))
    src_host = attrs.get("srcHost", attrs.get("sname", src_ip))
    dst_ip = attrs.get("dst", attrs.get("dstIP", ""))

    return {
        "@timestamp": attrs.get("devTime", _ts_now()),
        "event": {
            "id": attrs.get("identSrc", str(abs(hash(raw + _ts_now())))),
            "category": category,
            "dataset": "leef",
        },
        "alert": {
            "severity": severity,
            "rule": f"{vendor}/{product}: {event_id}",
            "risk_score": float(risk_score),
            "techniques": [],
        },
        "host": {"hostname": src_host, "ip": src_ip},
        "indicator": {"ip": dst_ip or None},
        "message": message[:2000],
        "leef": {"vendor": vendor, "product": product, "event_id": event_id},
    }


def _parse_raw(raw: str, source_ip: str) -> dict:
    """Fallback: treat the entire string as an unstructured message."""
    message = raw.strip()[:2000]
    category, cat_floor = _classify(message)
    boost = _severity_boost(message)
    severity = _clamp(max(4, cat_floor) + boost)
    risk_score = _clamp(severity * 10, lo=10, hi=100)

    return {
        "@timestamp": _ts_now(),
        "event": {
            "id": str(abs(hash(raw + _ts_now()))),
            "category": category,
            "dataset": "syslog.raw",
        },
        "alert": {
            "severity": severity,
            "rule": "syslog_ingest",
            "risk_score": float(risk_score),
            "techniques": [],
        },
        "host": {"hostname": source_ip, "ip": source_ip},
        "indicator": {},
        "message": message,
    }
