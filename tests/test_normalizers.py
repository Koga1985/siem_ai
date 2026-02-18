"""
Unit tests for the syslog parser and SIEM normalizers.
Covers RFC 3164, RFC 5424, CEF, LEEF, and Splunk/Elastic normalisers.
"""

import os
import sys

sys.path.insert(
    0, os.path.join(os.path.dirname(__file__), "../services/event_bridge")
)  # noqa: E402

from normalizers.elastic import map_elastic  # noqa: E402
from normalizers.splunk import map_splunk_hec  # noqa: E402
from normalizers.syslog_parser import detect_format, parse  # noqa: E402

# ---------------------------------------------------------------------------
# detect_format
# ---------------------------------------------------------------------------


class TestDetectFormat:
    def test_cef_detected(self):
        raw = "CEF:0|Vendor|Product|1.0|100|Login Failure|7|src=1.2.3.4"
        assert detect_format(raw) == "cef"

    def test_cef_with_syslog_header_detected(self):
        raw = "<134>Feb 18 12:00:00 host CEF:0|V|P|1|1|Name|5|src=1.2.3.4"
        assert detect_format(raw) == "cef"

    def test_leef_detected(self):
        raw = "LEEF:2.0|IBM|QRadar|1.0|Login|\tsrc=1.2.3.4\tsev=7"
        assert detect_format(raw) == "leef"

    def test_rfc5424_detected(self):
        raw = "<134>1 2024-02-18T12:00:00Z host sshd 1234 - - Failed password"
        assert detect_format(raw) == "rfc5424"

    def test_rfc3164_detected(self):
        raw = "<134>Feb 18 12:00:00 myhost sshd[1234]: Failed password for root"
        assert detect_format(raw) == "rfc3164"

    def test_raw_fallback(self):
        raw = "This is just a plain string"
        assert detect_format(raw) == "raw"


# ---------------------------------------------------------------------------
# parse — RFC 3164
# ---------------------------------------------------------------------------


class TestParseRfc3164:
    def test_basic_parse(self):
        raw = "<134>Feb 18 12:00:00 myhost sshd[1234]: Failed password for root from 1.2.3.4"
        evt = parse(raw, "10.0.0.1")
        assert evt["event"]["dataset"] == "syslog.rfc3164"
        assert evt["host"]["ip"] == "10.0.0.1"
        assert "Failed password" in evt["message"]

    def test_severity_mapping(self):
        # priority 0 = facility 0, severity 0 (Emergency) → tool severity 10
        raw = "<0>Feb 18 12:00:00 host app: emergency message"
        evt = parse(raw, "127.0.0.1")
        assert evt["alert"]["severity"] == 10

    def test_keyword_boost_malware(self):
        raw = "<150>Feb 18 12:00:00 host av: malware detected in /tmp/evil.exe"
        evt = parse(raw, "10.0.0.1")
        assert evt["event"]["category"] == "malware"
        assert evt["alert"]["severity"] >= 9

    def test_brute_force_classification(self):
        raw = "<134>Feb 18 12:00:00 host sshd: Failed password for root from 1.2.3.4"
        evt = parse(raw, "10.0.0.1")
        assert evt["event"]["category"] == "intrusion_detection"

    def test_tag_extracted_as_rule(self):
        raw = "<134>Feb 18 12:00:00 myhost sshd[22]: Connection refused"
        evt = parse(raw, "10.0.0.1")
        assert evt["alert"]["rule"] == "sshd"

    def test_hostname_extracted(self):
        raw = "<134>Feb 18 12:00:00 webserver nginx[80]: 404 Not Found"
        evt = parse(raw, "192.168.1.5")
        assert evt["host"]["hostname"] == "webserver"


# ---------------------------------------------------------------------------
# parse — RFC 5424
# ---------------------------------------------------------------------------


class TestParseRfc5424:
    def test_basic_parse(self):
        raw = "<134>1 2024-02-18T12:00:00Z myhost sshd 1234 - - Failed password"
        evt = parse(raw, "10.0.0.1")
        assert evt["event"]["dataset"] == "syslog.rfc5424"
        assert evt["alert"]["rule"] == "sshd"

    def test_timestamp_preserved(self):
        raw = "<134>1 2024-02-18T12:34:56Z host app 123 - - msg"
        evt = parse(raw, "10.0.0.1")
        assert evt["@timestamp"] == "2024-02-18T12:34:56Z"

    def test_hostname_extracted(self):
        raw = "<134>1 2024-02-18T12:00:00Z fileserver smbd 0 - - Access denied"
        evt = parse(raw, "10.0.0.2")
        assert evt["host"]["hostname"] == "fileserver"


# ---------------------------------------------------------------------------
# parse — CEF
# ---------------------------------------------------------------------------


class TestParseCef:
    def test_basic_cef(self):
        raw = "CEF:0|ArcSight|SIEM|7.0|100|Login Brute Force|8|src=1.2.3.4 dst=10.0.0.1 msg=Too many failures"
        evt = parse(raw, "10.0.0.1")
        assert evt["event"]["dataset"] == "cef"
        assert evt["alert"]["severity"] == 8
        assert "ArcSight" in evt["alert"]["rule"]

    def test_cef_source_ip_extracted(self):
        raw = "CEF:0|V|P|1|1|Test|5|src=9.9.9.9"
        evt = parse(raw, "0.0.0.0")
        assert evt["host"]["ip"] == "9.9.9.9"

    def test_cef_keyword_boost(self):
        raw = "CEF:0|V|P|1|1|Malware Detected|3|src=1.1.1.1"
        evt = parse(raw, "0.0.0.0")
        # keyword 'malware' should override low CEF severity
        assert evt["event"]["category"] == "malware"
        assert evt["alert"]["severity"] >= 9

    def test_cef_risk_score_scaled(self):
        raw = "CEF:0|V|P|1|1|Test|6|src=1.1.1.1"
        evt = parse(raw, "0.0.0.0")
        assert evt["alert"]["risk_score"] >= 60


# ---------------------------------------------------------------------------
# parse — LEEF
# ---------------------------------------------------------------------------


class TestParseLeef:
    def test_basic_leef(self):
        raw = "LEEF:2.0|IBM|QRadar|1.0|Login|\tsrc=1.2.3.4\tsev=7\tcat=auth"
        evt = parse(raw, "10.0.0.1")
        assert evt["event"]["dataset"] == "leef"
        assert evt["alert"]["severity"] == 7

    def test_leef_vendor_product_in_rule(self):
        raw = "LEEF:1.0|Cisco|ASA|9.0|AUTH_FAIL|\tsev=5"
        evt = parse(raw, "10.0.0.1")
        assert "Cisco" in evt["alert"]["rule"]
        assert "ASA" in evt["alert"]["rule"]


# ---------------------------------------------------------------------------
# parse — raw fallback
# ---------------------------------------------------------------------------


class TestParseRaw:
    def test_plain_message(self):
        evt = parse("System reboot initiated", "127.0.0.1")
        assert evt["event"]["dataset"] == "syslog.raw"
        assert evt["host"]["ip"] == "127.0.0.1"

    def test_brute_force_keyword(self):
        evt = parse("Multiple authentication failure from 1.2.3.4", "10.0.0.1")
        assert evt["event"]["category"] == "intrusion_detection"
        assert evt["alert"]["severity"] >= 6


# ---------------------------------------------------------------------------
# Splunk HEC normaliser
# ---------------------------------------------------------------------------


class TestSplunkNormaliser:
    def test_dict_event(self):
        payload = {
            "time": 1516654932.0,
            "host": "webserver",
            "sourcetype": "linux_secure",
            "event": {
                "message": "Failed password for root",
                "severity": 7,
                "rule_name": "Brute Force",
                "src_ip": "1.2.3.4",
            },
        }
        evt = map_splunk_hec(payload)
        assert evt["alert"]["severity"] == 7
        assert evt["alert"]["rule"] == "Brute Force"
        assert evt["host"]["ip"] == "1.2.3.4"
        assert evt["event"]["dataset"] == "splunk.hec"

    def test_string_event_parsed_as_syslog(self):
        payload = {
            "host": "10.0.0.5",
            "event": "<134>Feb 18 12:00:00 host sshd: Failed password for root",
        }
        evt = map_splunk_hec(payload)
        # String event is routed through syslog parser
        assert (
            "failed password" in evt["message"].lower() or evt["alert"]["severity"] >= 5
        )

    def test_severity_string_coercion(self):
        payload = {
            "event": {"severity": "high", "rule_name": "Alert", "src_ip": "1.2.3.4"},
            "host": "h1",
        }
        evt = map_splunk_hec(payload)
        assert evt["alert"]["severity"] == 8

    def test_severity_critical_string(self):
        payload = {"event": {"severity": "critical"}, "host": "h1"}
        evt = map_splunk_hec(payload)
        assert evt["alert"]["severity"] == 10

    def test_batch_array_first_item(self):
        batch = [
            {"event": {"severity": 5}, "host": "h1"},
            {"event": {"severity": 8}, "host": "h2"},
        ]
        evt = map_splunk_hec(batch)
        assert evt["alert"]["severity"] == 5

    def test_empty_batch(self):
        evt = map_splunk_hec([])
        assert evt["event"]["id"] == "splunk-empty"

    def test_epoch_timestamp_converted(self):
        payload = {"time": 0.0, "event": {"severity": 3}, "host": "h"}
        evt = map_splunk_hec(payload)
        assert "1970" in evt["@timestamp"]

    def test_mitre_techniques_list(self):
        payload = {
            "event": {"techniques": ["T1059", "T1078"], "severity": 5},
            "host": "h",
        }
        evt = map_splunk_hec(payload)
        assert "T1059" in evt["alert"]["techniques"]

    def test_mitre_techniques_csv_string(self):
        payload = {
            "event": {"techniques": "T1059,T1078", "severity": 5},
            "host": "h",
        }
        evt = map_splunk_hec(payload)
        assert len(evt["alert"]["techniques"]) == 2


# ---------------------------------------------------------------------------
# Elastic / ECS normaliser
# ---------------------------------------------------------------------------


class TestElasticNormaliser:
    def test_basic_ecs8_alert(self):
        payload = {
            "@timestamp": "2024-02-18T12:00:00Z",
            "event": {
                "id": "evt-001",
                "category": ["intrusion_detection"],
                "kind": "alert",
            },
            "rule": {"name": "SSH Brute Force", "severity": "high", "risk_score": 75},
            "host": {"name": "webserver", "ip": ["10.0.0.1"]},
            "source": {"ip": "1.2.3.4"},
        }
        evt = map_elastic(payload)
        assert evt["event"]["id"] == "evt-001"
        assert evt["event"]["category"] == "intrusion_detection"
        assert evt["alert"]["severity"] == 8
        assert evt["alert"]["risk_score"] == 75.0
        assert evt["alert"]["rule"] == "SSH Brute Force"
        assert evt["host"]["hostname"] == "webserver"
        assert evt["host"]["ip"] == "1.2.3.4"
        assert evt["event"]["dataset"] == "elastic.siem"

    def test_kibana_alert_fields(self):
        payload = {
            "@timestamp": "2024-02-18T12:00:00Z",
            "event": {"id": "k-001"},
            "kibana.alert.severity": "critical",
            "kibana.alert.risk_score": 99,
            "kibana.alert.rule.name": "Ransomware Detected",
            "host": {"name": "host1", "ip": "10.0.0.1"},
        }
        evt = map_elastic(payload)
        assert evt["alert"]["severity"] == 10
        assert evt["alert"]["risk_score"] == 99.0
        assert evt["alert"]["rule"] == "Ransomware Detected"

    def test_mitre_techniques_extracted(self):
        payload = {
            "@timestamp": "2024-02-18T12:00:00Z",
            "event": {"id": "t-001"},
            "rule": {"name": "Test"},
            "threat": {"technique": {"id": ["T1059.001", "T1078"]}},
            "host": {"name": "h", "ip": "10.0.0.1"},
        }
        evt = map_elastic(payload)
        assert "T1059.001" in evt["alert"]["techniques"]
        assert "T1078" in evt["alert"]["techniques"]

    def test_string_category_ecs7(self):
        payload = {
            "@timestamp": "2024-02-18T12:00:00Z",
            "event": {"id": "e7-001", "category": "malware"},
            "rule": {"name": "Malware Alert", "severity": "high"},
            "host": {"name": "h", "ip": "10.0.0.1"},
        }
        evt = map_elastic(payload)
        assert evt["event"]["category"] == "malware"

    def test_host_ip_list_takes_first(self):
        payload = {
            "@timestamp": "2024-02-18T12:00:00Z",
            "event": {"id": "ip-001"},
            "rule": {"name": "Test"},
            "host": {"name": "h", "ip": ["10.0.0.1", "10.0.0.2"]},
        }
        evt = map_elastic(payload)
        # source.ip not present → falls back to host_ip
        assert evt["host"]["ip"] == "10.0.0.1"

    def test_non_dict_returns_empty(self):
        evt = map_elastic("not a dict")
        assert evt["event"]["id"] == "es-empty"

    def test_numeric_severity(self):
        payload = {
            "@timestamp": "2024-02-18T12:00:00Z",
            "event": {"id": "n-001"},
            "rule": {"name": "Test", "severity": 9},
            "host": {"name": "h", "ip": "10.0.0.1"},
        }
        evt = map_elastic(payload)
        assert evt["alert"]["severity"] == 9
