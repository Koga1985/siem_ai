import os, json, threading, socket
from flask import Flask, request, jsonify
from jsonschema import validate, ValidationError

app = Flask(__name__)
QUEUE_DIR = "/repo/services/event_bridge/queue"
os.makedirs(QUEUE_DIR, exist_ok=True)

with open("/repo/schemas/ecs_min.json","r") as f:
    ECS_MIN = json.load(f)

def enqueue(evt):
    eid = evt.get("event",{}).get("id") or str(abs(hash(json.dumps(evt))))
    path = os.path.join(QUEUE_DIR, f"{eid}.json")
    with open(path, "w") as w:
        json.dump(evt, w, indent=2)

@app.route("/ingest/webhook", methods=["POST"])
def webhook():
    evt = request.get_json(force=True, silent=True) or {}
    # If already ECS-ish, accept; else pass through untouched (demo simplicity)
    try:
        validate(evt, ECS_MIN)
        enqueue(evt)
        return jsonify({"status":"queued","id":evt["event"]["id"]}), 202
    except ValidationError:
        # Accept non-compliant for demo, wrap minimally
        wrapped = {
            "@timestamp": evt.get("@timestamp") or evt.get("time"),
            "event": {"id": str(abs(hash(json.dumps(evt)))), "category": evt.get("event",{}).get("category","unknown")},
            "alert": {"severity": int(evt.get("severity",5)), "rule": evt.get("rule","unknown"), "risk_score": float(evt.get("risk",50)), "techniques": evt.get("techniques", [])},
            "host": {"hostname": evt.get("host","unknown"), "ip": evt.get("src_ip","0.0.0.0")},
            "indicator": {"ip": evt.get("src_ip")},
            "raw": evt
        }
        enqueue(wrapped)
        return jsonify({"status":"queued","id":wrapped["event"]["id"],"note":"wrapped"}), 202

def start_syslog_udp(port:int):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", port))
    print(f"[syslog] listening on udp/{port}")
    while True:
        data, addr = sock.recvfrom(65535)
        msg = data.decode(errors="ignore")
        evt = {
            "@timestamp": None,
            "event": {"id": str(abs(hash(msg))), "category": "syslog"},
            "alert": {"severity": 4, "rule": "syslog_ingest", "risk_score": 40, "techniques": []},
            "host": {"hostname": addr[0], "ip": addr[0]},
            "indicator": {}
        }
        enqueue(evt)

if __name__ == "__main__":
    port = int(os.getenv("WEBHOOK_PORT", "5000"))
    udp = int(os.getenv("SYSLOG_UDP_PORT", "514"))
    t = threading.Thread(target=start_syslog_udp, args=(udp,), daemon=True)
    t.start()
    app.run(host="0.0.0.0", port=port)
