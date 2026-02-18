import os
import glob
import json
from flask import Flask, render_template_string, send_file, jsonify

app = Flask(__name__)
LIB = os.getenv("LIB_DIR", "/repo/playbooks/_library")

# Severity → label + CSS colour
_SEV_BANDS = [
    (9, "CRITICAL", "#c0392b"),
    (7, "HIGH",     "#e74c3c"),
    (5, "MEDIUM",   "#e67e22"),
    (3, "LOW",      "#f1c40f"),
    (0, "INFO",     "#27ae60"),
]

def _sev_label_color(sev: int):
    for floor, label, color in _SEV_BANDS:
        if sev >= floor:
            return label, color
    return "INFO", "#27ae60"


def _load_incident_meta(inc_id: str) -> dict:
    """Read EVIDENCE.json and extract display metadata."""
    path = os.path.join(LIB, f"{inc_id}_EVIDENCE.json")
    try:
        with open(path) as f:
            ev = json.load(f)
        sev = int(ev.get("alert", {}).get("severity", 0))
        label, color = _sev_label_color(sev)
        return {
            "id": inc_id,
            "severity": sev,
            "sev_label": label,
            "sev_color": color,
            "category": ev.get("event", {}).get("category", "unknown"),
            "rule": ev.get("alert", {}).get("rule", "unknown"),
            "host": ev.get("host", {}).get("hostname", "unknown"),
            "src_ip": ev.get("host", {}).get("ip", ""),
            "indicator_ip": ev.get("indicator", {}).get("ip", "") or "",
            "techniques": ", ".join(ev.get("alert", {}).get("techniques", [])),
            "timestamp": ev.get("@timestamp", ""),
            "message": (ev.get("message", "") or "")[:120],
            "dataset": ev.get("event", {}).get("dataset", ""),
        }
    except Exception:
        return {
            "id": inc_id, "severity": 0, "sev_label": "?", "sev_color": "#95a5a6",
            "category": "unknown", "rule": "unknown", "host": "unknown",
            "src_ip": "", "indicator_ip": "", "techniques": "",
            "timestamp": "", "message": "", "dataset": "",
        }


T = '''<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>siem_ai -- Incident Review</title>
  <style>
    body { font-family: -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
           background:#1a1a2e; color:#e0e0e0; margin:0; padding:20px; }
    h1   { color:#00d4ff; border-bottom:1px solid #333; padding-bottom:8px; }
    .summary { color:#aaa; margin-bottom:20px; font-size:.9em; }
    table { width:100%; border-collapse:collapse; font-size:.88em; }
    th    { background:#16213e; color:#00d4ff; padding:8px 10px; text-align:left;
            position:sticky; top:0; }
    tr:nth-child(even) { background:#0f3460; }
    tr:nth-child(odd)  { background:#16213e; }
    tr:hover { background:#1a4a7a; }
    td { padding:7px 10px; vertical-align:middle; }
    .badge { display:inline-block; padding:2px 8px; border-radius:4px;
             font-weight:bold; font-size:.8em; color:#fff; }
    .mono { font-family:monospace; font-size:.85em; }
    .actions a { margin-right:6px; color:#00d4ff; text-decoration:none; font-size:.85em; }
    .actions a:hover { text-decoration:underline; }
    form.approve { display:inline; }
    button.approve-btn {
      background:#27ae60; color:#fff; border:none; border-radius:4px;
      padding:4px 12px; cursor:pointer; font-size:.85em; }
    button.approve-btn:hover { background:#2ecc71; }
    .msg { color:#aaa; font-size:.8em; max-width:280px;
           overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
    .empty { text-align:center; padding:60px; color:#555; }
  </style>
</head>
<body>
<h1>siem_ai -- Incident Review Queue</h1>
<div class="summary">
  {{ incidents|length }} incident(s) awaiting review &nbsp;|&nbsp;
  All playbooks run in <strong>check-mode</strong> until you explicitly approve and execute.
</div>

{% if incidents %}
<table>
  <thead>
    <tr>
      <th>Severity</th>
      <th>Category</th>
      <th>Rule / Alert</th>
      <th>Host</th>
      <th>Indicator IP</th>
      <th>MITRE</th>
      <th>Source</th>
      <th>Timestamp (UTC)</th>
      <th>Summary</th>
      <th>Actions</th>
    </tr>
  </thead>
  <tbody>
  {% for inc in incidents %}
    <tr>
      <td>
        <span class="badge" style="background:{{ inc.sev_color }}">
          {{ inc.sev_label }} ({{ inc.severity }})
        </span>
      </td>
      <td>{{ inc.category }}</td>
      <td class="mono">{{ inc.rule }}</td>
      <td class="mono">{{ inc.host }}<br><small style="color:#888">{{ inc.src_ip }}</small></td>
      <td class="mono">{{ inc.indicator_ip or "---" }}</td>
      <td class="mono">{{ inc.techniques or "---" }}</td>
      <td><small style="color:#aaa">{{ inc.dataset }}</small></td>
      <td><small>{{ inc.timestamp }}</small></td>
      <td><div class="msg" title="{{ inc.message }}">{{ inc.message or "---" }}</div></td>
      <td class="actions">
        <a href="/download/{{ inc.id }}/yml" title="Download playbook">playbook</a>
        <a href="/download/{{ inc.id }}/evidence" title="Download evidence">evidence</a>
        <a href="/download/{{ inc.id }}/plan" title="Download change plan">plan</a>
        <form class="approve" method="post" action="/approve/{{ inc.id }}">
          <button class="approve-btn" type="submit">Approve</button>
        </form>
      </td>
    </tr>
  {% endfor %}
  </tbody>
</table>
{% else %}
<div class="empty">No incidents in queue. Waiting for events from your SIEM...</div>
{% endif %}

<p style="margin-top:30px;font-size:.75em;color:#555">
  Approval generates the ansible-playbook command with <code>approve_change=true</code>.
  All state-changing tasks still run in <strong>check-mode</strong> unless you explicitly
  remove that flag. Review the change plan before executing.
</p>
</body>
</html>
'''


@app.route("/")
def index():
    yml_files = sorted(glob.glob(os.path.join(LIB, "*.yml")))
    incident_ids = [os.path.basename(f).replace(".yml", "") for f in yml_files]
    incidents = [_load_incident_meta(inc_id) for inc_id in incident_ids]
    # Sort: highest severity first
    incidents.sort(key=lambda x: x["severity"], reverse=True)
    return render_template_string(T, incidents=incidents)


@app.route("/download/<inc>/<kind>")
def download(inc, kind):
    # Sanitise to prevent path traversal
    inc = os.path.basename(inc)
    if kind == "yml":
        path = os.path.join(LIB, f"{inc}.yml")
    elif kind == "evidence":
        path = os.path.join(LIB, f"{inc}_EVIDENCE.json")
    else:
        path = os.path.join(LIB, f"{inc}_CHANGE_PLAN.md")
    if not os.path.isfile(path):
        return jsonify({"error": "not found"}), 404
    return send_file(path, as_attachment=True)


@app.post("/approve/<inc>")
def approve(inc):
    inc = os.path.basename(inc)
    cmd = (f"ansible-playbook playbooks/run_generated.yml "
           f"-e incident={inc} -e approve_change=true "
           f"-i inventories/lab/hosts.ini")
    return (
        f"<html><body style='font-family:sans-serif;background:#1a1a2e;color:#e0e0e0;padding:20px'>"
        f"<h2 style='color:#27ae60'>Approved: {inc}</h2>"
        f"<p>Execute the following command on your Ansible control node:</p>"
        f"<pre style='background:#16213e;padding:15px;border-radius:6px;color:#00d4ff'>{cmd}</pre>"
        f"<p><a href='/' style='color:#00d4ff'>&larr; Back to queue</a></p>"
        f"</body></html>",
        200,
    )


@app.route("/api/incidents")
def api_incidents():
    """JSON API for programmatic polling of the incident queue."""
    yml_files = sorted(glob.glob(os.path.join(LIB, "*.yml")))
    incident_ids = [os.path.basename(f).replace(".yml", "") for f in yml_files]
    incidents = [_load_incident_meta(inc_id) for inc_id in incident_ids]
    incidents.sort(key=lambda x: x["severity"], reverse=True)
    return jsonify(incidents)


if __name__ == "__main__":
    port = int(os.getenv("REVIEW_UI_PORT", "8088"))
    app.run(host="0.0.0.0", port=port)
