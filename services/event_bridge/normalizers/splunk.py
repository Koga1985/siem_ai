def map_splunk_hec(evt):
    # Minimal mapper stub
    f = evt.get('fields', {})
    return {
        "@timestamp": evt.get("time"),
        "event": {"id": f.get("event_id","hec-"+str(hash(str(evt)))), "category": f.get("category","unknown")},
        "alert": {"severity": int(f.get("severity",5)), "rule": f.get("rule_name","unknown"), "risk_score": float(f.get("risk",50)), "techniques": f.get("techniques", [])},
        "host": {"hostname": evt.get("host","unknown"), "ip": f.get("src_ip","0.0.0.0")},
        "indicator": {"ip": f.get("src_ip")}
    }
