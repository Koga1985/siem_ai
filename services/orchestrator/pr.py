from flask import Flask, render_template_string, send_file
import os, glob

app = Flask(__name__)
LIB = "/repo/playbooks/_library"

T = '''
<!doctype html>
<title>seim_ai Approvals</title>
<h1>Generated Drafts</h1>
<ul>
{% for inc in incidents %}
  <li>
    <strong>{{inc}}</strong> —
    <a href="/download/{{inc}}/yml">playbook</a> |
    <a href="/download/{{inc}}/evidence">evidence</a> |
    <a href="/download/{{inc}}/plan">change plan</a>
    <form method="post" action="/approve/{{inc}}" style="display:inline">
      <button>Approve</button>
    </form>
  </li>
{% endfor %}
</ul>
<p>Approval toggles the 'approve_change' variable at execution time; actual CI gates run in your GH PRs.</p>
'''
@app.route("/")
def index():
    files = glob.glob(os.path.join(LIB, "*.yml"))
    incidents = [os.path.basename(f).replace(".yml","") for f in files]
    return render_template_string(T, incidents=incidents)

@app.route("/download/<inc>/<kind>")
def download(inc, kind):
    if kind == "yml":
        path = os.path.join(LIB, f"{inc}.yml")
    elif kind == "evidence":
        path = os.path.join(LIB, f"{inc}_EVIDENCE.json")
    else:
        path = os.path.join(LIB, f"{inc}_CHANGE_PLAN.md")
    return send_file(path, as_attachment=True)

@app.post("/approve/<inc>")
def approve(inc):
    # No stateful backend; approval is human signal used when executing with -e approve_change=true
    return ("Approved. Execute with: ansible-playbook playbooks/run_generated.yml "
            f"-e incident={inc} -e approve_change=true -i inventories/lab/hosts.ini", 200)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8088)
