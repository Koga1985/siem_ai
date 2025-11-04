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

# Initialize Flask app
app = Flask(__name__)

# Setup structured logging
logger = setup_logging('event_bridge')

# Configuration
QUEUE_DIR = os.getenv("QUEUE_DIR", "/repo/services/event_bridge/queue")
API_KEY = os.getenv("API_KEY", "")  # Empty means auth disabled (lab mode)
RATE_LIMIT = os.getenv("RATE_LIMIT", "100 per minute")

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
    logger.info(f"Queue directory initialized", extra={'path': QUEUE_DIR})
except Exception as e:
    logger.error(f"Failed to create queue directory", extra={'path': QUEUE_DIR, 'error': str(e)})
    sys.exit(1)

# Load ECS schema
try:
    with open("/repo/schemas/ecs_min.json", "r") as f:
        ECS_MIN = json.load(f)
    logger.info("ECS schema loaded successfully")
except Exception as e:
    logger.error(f"Failed to load ECS schema", extra={'error': str(e)})
    sys.exit(1)


def require_api_key(f):
    """Decorator to require API key authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Skip auth check if API_KEY not configured (lab mode)
        if not API_KEY:
            logger.debug("API key authentication disabled (lab mode)")
            return f(*args, **kwargs)

        # Check for API key in header
        provided_key = request.headers.get('X-API-Key')
        if not provided_key:
            logger.warning("Missing API key in request", extra={
                'ip': request.remote_addr,
                'path': request.path
            })
            return jsonify({"error": "Missing X-API-Key header"}), 401

        if provided_key != API_KEY:
            logger.warning("Invalid API key attempt", extra={
                'ip': request.remote_addr,
                'path': request.path
            })
            return jsonify({"error": "Invalid API key"}), 403

        return f(*args, **kwargs)
    return decorated_function


def enqueue(evt: dict) -> str:
    """
    Enqueue an event to the processing queue

    Args:
        evt: Event dictionary to enqueue

    Returns:
        Event ID

    Raises:
        Exception: If file write fails
    """
    try:
        eid = evt.get("event", {}).get("id") or str(abs(hash(json.dumps(evt))))
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


@app.route("/health", methods=["GET"])
def health():
    """Health check endpoint"""
    try:
        # Check queue directory is writable
        test_file = os.path.join(QUEUE_DIR, ".health_check")
        with open(test_file, "w") as f:
            f.write("ok")
        os.remove(test_file)

        return jsonify({
            "status": "healthy",
            "service": "event_bridge",
            "timestamp": datetime.utcnow().isoformat()
        }), 200
    except Exception as e:
        logger.error("Health check failed", extra={'error': str(e)})
        return jsonify({
            "status": "unhealthy",
            "error": str(e)
        }), 503


@app.route("/ingest/webhook", methods=["POST"])
@require_api_key
@limiter.limit(RATE_LIMIT)
def webhook():
    """Webhook endpoint for receiving security events"""
    try:
        # Parse JSON with error handling
        evt = request.get_json(force=True, silent=True)
        if evt is None:
            logger.warning("Invalid JSON received", extra={'ip': request.remote_addr})
            return jsonify({"error": "Invalid JSON"}), 400

        # Log the ingest attempt
        logger.debug("Webhook received", extra={
            'ip': request.remote_addr,
            'content_length': request.content_length
        })

        # Validate against ECS schema
        try:
            validate(evt, ECS_MIN)
            eid = enqueue(evt)

            log_audit_event(logger, 'webhook_received',
                          event_id=eid,
                          source_ip=request.remote_addr,
                          valid_schema=True)

            return jsonify({"status": "queued", "id": eid}), 202

        except ValidationError as ve:
            # Accept non-compliant events but wrap them
            logger.info("Non-ECS compliant event, wrapping", extra={
                'ip': request.remote_addr,
                'validation_error': str(ve)
            })

            wrapped = {
                "@timestamp": evt.get("@timestamp") or evt.get("time") or datetime.utcnow().isoformat(),
                "event": {
                    "id": str(abs(hash(json.dumps(evt)))),
                    "category": evt.get("event", {}).get("category", "unknown")
                },
                "alert": {
                    "severity": int(evt.get("severity", 5)),
                    "rule": evt.get("rule", "unknown"),
                    "risk_score": float(evt.get("risk", 50)),
                    "techniques": evt.get("techniques", [])
                },
                "host": {
                    "hostname": evt.get("host", "unknown"),
                    "ip": evt.get("src_ip", "0.0.0.0")
                },
                "indicator": {"ip": evt.get("src_ip")},
                "raw": evt
            }

            eid = enqueue(wrapped)

            log_audit_event(logger, 'webhook_received',
                          event_id=eid,
                          source_ip=request.remote_addr,
                          valid_schema=False,
                          wrapped=True)

            return jsonify({"status": "queued", "id": eid, "note": "wrapped"}), 202

    except Exception as e:
        logger.error("Webhook processing failed", extra={
            'error': str(e),
            'ip': request.remote_addr
        }, exc_info=True)
        return jsonify({"error": "Internal server error"}), 500


def start_syslog_udp(port: int):
    """Start UDP syslog listener"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("0.0.0.0", port))
        logger.info(f"Syslog UDP listener started", extra={'port': port})

        while True:
            try:
                data, addr = sock.recvfrom(65535)
                msg = data.decode(errors="ignore")

                evt = {
                    "@timestamp": datetime.utcnow().isoformat(),
                    "event": {"id": str(abs(hash(msg))), "category": "syslog"},
                    "alert": {
                        "severity": 4,
                        "rule": "syslog_ingest",
                        "risk_score": 40,
                        "techniques": []
                    },
                    "host": {"hostname": addr[0], "ip": addr[0]},
                    "indicator": {},
                    "message": msg[:1000]  # Truncate long messages
                }

                eid = enqueue(evt)
                logger.debug("Syslog message received", extra={
                    'event_id': eid,
                    'source_ip': addr[0]
                })

            except Exception as e:
                logger.error("Syslog processing error", extra={
                    'error': str(e),
                    'source': addr[0] if 'addr' in locals() else 'unknown'
                })

    except Exception as e:
        logger.error("Syslog listener failed to start", extra={
            'port': port,
            'error': str(e)
        })
        sys.exit(1)


@app.errorhandler(429)
def ratelimit_handler(e):
    """Handle rate limit errors"""
    logger.warning("Rate limit exceeded", extra={
        'ip': request.remote_addr,
        'path': request.path
    })
    return jsonify({"error": "Rate limit exceeded"}), 429


if __name__ == "__main__":
    logger.info("Starting event bridge service", extra={
        'webhook_port': int(os.getenv("WEBHOOK_PORT", "5000")),
        'syslog_port': int(os.getenv("SYSLOG_UDP_PORT", "514")),
        'auth_enabled': bool(API_KEY),
        'rate_limit': RATE_LIMIT
    })

    port = int(os.getenv("WEBHOOK_PORT", "5000"))
    udp = int(os.getenv("SYSLOG_UDP_PORT", "514"))

    # Start syslog listener in background thread
    t = threading.Thread(target=start_syslog_udp, args=(udp,), daemon=True)
    t.start()

    # Start Flask app
    app.run(host="0.0.0.0", port=port)
