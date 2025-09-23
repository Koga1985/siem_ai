import os, json, glob, time, yaml
from jinja2 import Template
from safety_checks import approve

QUEUE_DIR = "/repo/services/event_bridge/queue"
LIB_DIR = "/repo/playbooks/_library"
PROMPT_TMPL = "/repo/prompts/remediation_user.j2"

os.makedirs(LIB_DIR, exist_ok=True)

def synthesize(evt):
    # naive synthesis: choose a sample based on category/severity
    sev = int(evt.get("alert",{}).get("severity",5))
    cat = evt.get("event",{}).get("category","unknown")
    if cat == "malware" or sev >= 7:
        base = "/repo/playbooks/samples/isolate_host_windows.yml"
    else:
        base = "/repo/playbooks/samples/patch_linux_package.yml"
    with open(base,"r") as f:
        play = f.read()
    # inject incident id and approval gate remains
    return play

def write_artifacts(evt, play_yaml):
    inc = evt["event"]["id"]
    pb_path = os.path.join(LIB_DIR, f"{inc}.yml")
    with open(pb_path,"w") as f:
        f.write(play_yaml)
    with open(os.path.join(LIB_DIR, f"{inc}_EVIDENCE.json"),"w") as f:
        json.dump(evt, f, indent=2)
    with open(os.path.join(LIB_DIR, f"{inc}_CHANGE_PLAN.md"),"w") as f:
        f.write(f"# Change Plan for {inc}\n\n- Review evidence\n- Run in --check\n- Approve change\n- Execute\n- Validate\n- Rollback if needed\n")

def loop():
    print("[ai-generator] watching queue…")
    while True:
        for path in glob.glob(QUEUE_DIR + "/*.json"):
            with open(path,"r") as f:
                evt = json.load(f)
            play = synthesize(evt)
            if approve(play):
                write_artifacts(evt, play)
                os.remove(path)
                print(f"[ai-generator] generated for {evt['event']['id']}")
        time.sleep(2)

if __name__ == "__main__":
    loop()
