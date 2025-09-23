def map_elastic(evt):
    # Minimal mapper stub
    src = evt
    return {
        "@timestamp": src.get("@timestamp"),
        "event": {"id": src.get("event",{}).get("id","es-"+str(hash(str(evt)))), "category": src.get("event",{}).get("category","unknown")},
        "alert": {"severity": int(src.get("event",{}).get("severity",5)), "rule": src.get("rule",{}).get("name","unknown"), "risk_score": float(src.get("risk",50)), "techniques": src.get("techniques", [])},
        "host": {"hostname": src.get("host",{}).get("name","unknown"), "ip": src.get("source",{}).get("ip","0.0.0.0")},
        "indicator": {"ip": src.get("source",{}).get("ip")}
    }
