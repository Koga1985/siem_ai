import os
import json
import threading
import socket
import sys
from datetime import datetime
from flask import Flask, request, jsonify, g
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from jsonschema import validate, ValidationError
from functools import wraps

# Add parent directory to path for common imports
sys.path.insert(0, '/repo/services')
from common.logging_config import setup_logging, log_audit_event

# Import normalizers
sys.path.insert(0, '/repo/services/event_bridge')
from normalizers.syslog_parser import parse as parse_syslog
from normalizers.splunk import map_splunk_hec
from normalizers.elastic import map_elastic

# Initialize Flask app
app = Flask(__name__)

# Setup structured logging
logger = setup_logging('event_bridge')

# Configuration
QUEUE_DIR = os.getenv("QUEUE_DIR", "/repo/services/event_bridge/queue")
API_KEY = os.getenv("API_KEY", "")          # Empty = lab mode (auth disabled)
RATE_LIMIT = os.getenv("RATE_LIMIT", "100 per minute")
SYSLOG_TCP_PORT = int(os.getenv("SYSLOG_TCP_PORT", "601"))
SIEM_TYPE = os.getenv("SIEM_TYPE", "auto")  # auto | splunk | elastic | generic

# Initialize rate limiter
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[RATE_LIMIT],
    storage_uri="memory://"
)

# Create queue directory
try:
    os.makedirs(QUEUE_DIR, exist_ok=True)
    logger.info("Queue directory initialized", extra={'path': QUEUE_DIR})
except Exception as e:
    logger.error("Failed to create queue directory", extra={'path': QUEUE_DIR, 'error': str(e)})
    sys.exit(1)

# Load ECS schema
try:
    with open("/repo/schemas/ecs_min.json", "r") as f:
        ECS_MIN = json.load(f)
    logger.info("ECS schema loaded successfully")
except Exception as e:
    logger.error("Failed to load ECS schema", extra={'error': str(e)})
    sys.exit(1)


# ---------------------------------------------------------------------------
# Auth helper
# ---------------------------------------------------------------------------

def require_api_key(f):
    """Decorator to require API key authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not API_KEY:
            logger.debug("API key authentication disabled (lab mode)")
            return f(*args, **kwargs)

        provided_key = request.headers.get('X-API-Key')
        if not provided_key:
            logger.warning("Missing API key in request", extra={
                'ip': request.remote_addr, 'path': request.path
            })
            return jsonify({"error": "Missing X-API-Key header"}), 401

        if provided_key != API_KEY:
            logger.warning("Invalid API key attempt", extra={
                'ip': request.remote_addr, 'path': request.path
            })
            return jsonify({"error": "Invalid API key"}), 403

        return f(*args, **kwargs)
    return decorated_function


# ---------------------------------------------------------------------------
# Queue helper
# ---------------------------------------------------------------------------

def enqueue(evt: dict) -> str:
    """Write event JSON to disk queue. Returns event ID."""
    try:
        eid = evt.get("event", {}).get("id") or str(abs(hash(json.dumps(evt, sort_keys=True))))
        path = os.path.join(QUEUE_DIR, f"{eid}.json")

        with open(path, "w") as w:
            json.dump(evt, w, indent=2)

        logger.info("Event enqueued", extra={
            'event_id': eid,
            'severity': evt.get('alert', {}).get('severity'),
            'category': evt.get('event', {}).get('category'),
            'queue_file': path
        })

        log_audit_event(logger, 'event_enqueued', event_id=eid, path=path)
        return eid

    except Exception as e:
        logger.error("Failed to enqueue event", extra={
            'error': str(e),
            'event_id': eid if 'eid' in locals() else 'unknown'
        })
        raise


# ---------------------------------------------------------------------------
# Normalisation helper
# ---------------------------------------------------------------------------

def _wrap_generic(evt: dict) -> dict:
    """Wrap a non-ECS-compliant JSON event into ECS-min format."""
    return {
        "@timestamp": (evt.get("@timestamp") or evt.get("time")
                       or datetime.utcnow().isoformat()),
        "event": {
            "id": str(abs(hash(json.dumps(evt, sort_keys=True)))),
            "category": evt.get("event", {}).get("category", "unknown"),
        },
        "alert": {
            "severity": int(evt.get("severity", evt.get("alert", {}).get("severity", 5))),
            "rule": evt.get("rule", evt.get("alert", {}).get("rule", "unknown")),
            "risk_score": float(evt.get("risk", evt.get("alert", {}).get("risk_score", 50))),
            "techniques": evt.get("techniques", evt.get("alert", {}).get("techniques", [])),
        },
        "host": {
            "hostname": evt.get("host", "unknown"),
            "ip": evt.get("src_ip", "0.0.0.0"),
        },
        "indicator": {"ip": evt.get("src_ip") or evt.get("indicator", {}).get("ip")},
        "raw": evt,
    }


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/health", methods=["GET"])
def health():
    """Health check endpoint"""
    try:
        test_file = os.path.join(QUEUE_DIR, ".health_check")
        with open(test_file, "w") as f:
            f.write("ok")
        os.remove(test_file)
        return jsonify({
            "status": "healthy",
            "service": "event_bridge",
            "timestamp": datetime.utcnow().isoformat(),
        }), 200
    except Exception as e:
        logger.error("Health check failed", extra={'error': str(e)})
        return jsonify({"status": "unhealthy", "error": str(e)}), 503


@app.route("/ingest/webhook", methods=["POST"])
@require_api_key
@limiter.limit(RATE_LIMIT)
def webhook():
    """
    Generic webhook endpoint.  Accepts:
      - Native ECS-min JSON
      - Splunk HEC JSON  (auto-detected when SIEM_TYPE=splunk or body has 'event'+'fields')
      - Elastic/ECS JSON (auto-detected when SIEM_TYPE=elastic)
      - Any other JSON  (wrapped into ECS-min)
    """
    try:
        evt = request.get_json(force=True, silent=True)
        if evt is None:
            logger.warning("Invalid JSON received", extra={'ip': request.remote_addr})
            return jsonify({"error": "Invalid JSON"}), 400

        logger.debug("Webhook received", extra={
            'ip': request.remote_addr,
            'content_length': request.content_length,
            'siem_type': SIEM_TYPE,
        })

        # Route to the right normalizer
        if SIEM_TYPE == "splunk" or _looks_like_splunk_hec(evt):
            normalised = map_splunk_hec(evt)
        elif SIEM_TYPE == "elastic" or _looks_like_elastic(evt):
            normalised = map_elastic(evt)
        else:
            # Try native ECS-min first
            try:
                validate(evt, ECS_MIN)
                normalised = evt
            except ValidationError:
                normalised = _wrap_generic(evt)

        eid = enqueue(normalised)
        log_audit_event(logger, 'webhook_received',
                        event_id=eid, source_ip=request.remote_addr)
        return jsonify({"status": "queued", "id": eid}), 202

    except Exception as e:
        logger.error("Webhook processing failed", extra={
            'error': str(e), 'ip': request.remote_addr
        }, exc_info=True)
        return jsonify({"error": "Internal server error"}), 500


@app.route("/ingest/splunk", methods=["POST"])
@require_api_key
@limiter.limit(RATE_LIMIT)
def ingest_splunk():
    """
    Dedicated Splunk HEC endpoint.
    Configure your Splunk forwarder to POST to http://<host>:5000/ingest/splunk
    with the standard HEC JSON format.
    """
    try:
        body = request.get_json(force=True, silent=True)
        if body is None:
            return jsonify({"error": "Invalid JSON"}), 400

        normalised = map_splunk_hec(body)
        eid = enqueue(normalised)
        log_audit_event(logger, 'splunk_hec_received',
                        event_id=eid, source_ip=request.remote_addr)
        return jsonify({"text": "Success", "code": 0, "id": eid}), 200

    except Exception as e:
        logger.error("Splunk HEC processing failed", extra={'error': str(e)}, exc_info=True)
        return jsonify({"text": "Internal error", "code": 8}), 500


@app.route("/ingest/elastic", methods=["POST"])
@require_api_key
@limiter.limit(RATE_LIMIT)
def ingest_elastic():
    """
    Dedicated Elastic/ECS endpoint.
    Configure a Logstash http output or Elastic Watcher action to POST here.
    """
    try:
        body = request.get_json(force=True, silent=True)
        if body is None:
            return jsonify({"error": "Invalid JSON"}), 400

        normalised = map_elastic(body)
        eid = enqueue(normalised)
        log_audit_event(logger, 'elastic_received',
                        event_id=eid, source_ip=request.remote_addr)
        return jsonify({"status": "queued", "id": eid}), 202

    except Exception as e:
        logger.error("Elastic ingest failed", extra={'error': str(e)}, exc_info=True)
        return jsonify({"error": "Internal server error"}), 500


@app.route("/ingest/cef", methods=["POST"])
@require_api_key
@limiter.limit(RATE_LIMIT)
def ingest_cef():
    """
    CEF over HTTP endpoint.
    Send a raw CEF string in the request body (Content-Type: text/plain).
    Compatible with ArcSight, Microsoft Sentinel, CrowdStrike, and others.
    """
    try:
        raw = request.get_data(as_text=True)
        if not raw:
            return jsonify({"error": "Empty body"}), 400

        normalised = parse_syslog(raw, source_ip=request.remote_addr)
        eid = enqueue(normalised)
        log_audit_event(logger, 'cef_received',
                        event_id=eid, source_ip=request.remote_addr)
        return jsonify({"status": "queued", "id": eid}), 202

    except Exception as e:
        logger.error("CEF ingest failed", extra={'error': str(e)}, exc_info=True)
        return jsonify({"error": "Internal server error"}), 500


# ---------------------------------------------------------------------------
# Syslog listeners (UDP + TCP)
# ---------------------------------------------------------------------------

def _handle_syslog_message(raw: str, source_ip: str):
    """Parse and enqueue a single syslog message."""
    try:
        evt = parse_syslog(raw, source_ip)
        eid = enqueue(evt)
        logger.debug("Syslog message received", extra={
            'event_id': eid,
            'source_ip': source_ip,
            'format': evt.get('event', {}).get('dataset', 'unknown'),
            'severity': evt.get('alert', {}).get('severity'),
            'category': evt.get('event', {}).get('category'),
        })
    except Exception as e:
        logger.error("Syslog processing error", extra={
            'error': str(e), 'source': source_ip
        })


def start_syslog_udp(port: int):
    """Start UDP syslog listener (RFC 3164/5424/CEF/LEEF auto-detected)."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("0.0.0.0", port))
        logger.info("Syslog UDP listener started", extra={'port': port})

        while True:
            try:
                data, addr = sock.recvfrom(65535)
                raw = data.decode(errors="ignore")
                _handle_syslog_message(raw, addr[0])
            except Exception as e:
                logger.error("Syslog UDP recv error", extra={'error': str(e)})

    except Exception as e:
        logger.error("Syslog UDP listener failed to start",
                     extra={'port': port, 'error': str(e)})
        sys.exit(1)


def start_syslog_tcp(port: int):
    """
    Start TCP syslog listener.
    Supports RFC 3164/5424/CEF/LEEF delivered over TCP (port 601 by default,
    but also commonly 514/TCP as used by rsyslog, syslog-ng, and most SIEMs).
    """
    try:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", port))
        srv.listen(64)
        logger.info("Syslog TCP listener started", extra={'port': port})

        while True:
            try:
                conn, addr = srv.accept()
                t = threading.Thread(
                    target=_handle_tcp_connection,
                    args=(conn, addr[0]),
                    daemon=True,
                )
                t.start()
            except Exception as e:
                logger.error("TCP accept error", extra={'error': str(e)})

    except Exception as e:
        logger.error("Syslog TCP listener failed to start",
                     extra={'port': port, 'error': str(e)})
        # TCP failure is not fatal; UDP syslog can still operate
        logger.warning("Continuing without TCP syslog listener")


def _handle_tcp_connection(conn: socket.socket, source_ip: str):
    """Handle a single TCP syslog connection, reading newline-delimited messages."""
    try:
        conn.settimeout(30)
        buf = ""
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            buf += chunk.decode(errors="ignore")
            # Process complete lines
            while "\n" in buf:
                line, buf = buf.split("\n", 1)
                line = line.strip()
                if line:
                    _handle_syslog_message(line, source_ip)
        # Handle any remaining data in buffer (no trailing newline)
        if buf.strip():
            _handle_syslog_message(buf.strip(), source_ip)
    except socket.timeout:
        pass
    except Exception as e:
        logger.error("TCP connection error", extra={'error': str(e), 'source': source_ip})
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Auto-detection helpers
# ---------------------------------------------------------------------------

def _looks_like_splunk_hec(body: dict) -> bool:
    """Heuristic: Splunk HEC payloads have 'event' and optionally 'time'/'host'/'fields'."""
    return isinstance(body, dict) and "event" in body and isinstance(body["event"], (dict, str))


def _looks_like_elastic(body: dict) -> bool:
    """Heuristic: Elastic ECS payloads have '@timestamp' and nested 'event' or 'rule' objects."""
    return (isinstance(body, dict)
            and "@timestamp" in body
            and ("rule" in body or ("event" in body and "kind" in body.get("event", {}))))


# ---------------------------------------------------------------------------
# Error handlers
# ---------------------------------------------------------------------------

@app.errorhandler(429)
def ratelimit_handler(e):
    logger.warning("Rate limit exceeded", extra={
        'ip': request.remote_addr, 'path': request.path
    })
    return jsonify({"error": "Rate limit exceeded"}), 429


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    udp_port = int(os.getenv("SYSLOG_UDP_PORT", "514"))
    tcp_port = int(os.getenv("SYSLOG_TCP_PORT", "601"))
    webhook_port = int(os.getenv("WEBHOOK_PORT", "5000"))

    logger.info("Starting event bridge service", extra={
        'webhook_port': webhook_port,
        'syslog_udp_port': udp_port,
        'syslog_tcp_port': tcp_port,
        'auth_enabled': bool(API_KEY),
        'rate_limit': RATE_LIMIT,
        'siem_type': SIEM_TYPE,
    })

    # Start syslog listeners in background threads
    threading.Thread(target=start_syslog_udp, args=(udp_port,), daemon=True).start()
    threading.Thread(target=start_syslog_tcp, args=(tcp_port,), daemon=True).start()

    # Start Flask app
    app.run(host="0.0.0.0", port=webhook_port)
