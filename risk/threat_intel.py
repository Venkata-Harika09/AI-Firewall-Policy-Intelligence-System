"""
Task 2: Threat Intelligence Correlation
AI Firewall - Milestone 3

Features
---------
• Malicious IP detection
• Malicious IP range detection
• High-risk service detection
• Abuse score thresholding
• Threat category weighting
• Public exposure detection
• Auto-block recommendations
"""

import json
import ipaddress
import os


# -----------------------------------
# Threat Category Weights
# FIX 1: botnet changed from 1.0 → 2.0
# (same severity as malware_host)
# -----------------------------------
THREAT_CATEGORY_WEIGHT = {
    "botnet"        : 2.0,   # ← FIXED (was 1.0)
    "ssh_bruteforce": 1.7,
    "scanner"       : 1.2,
    "tor_exit_node" : 1.3,
    "malware_host"  : 2.0,
    "phishing"      : 1.5
}


class ThreatIntelligence:

    def __init__(self, threat_db_path: str = None, verbose=False):

        self.verbose = verbose

        if threat_db_path is None:
            threat_db_path = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                "data",
                "threat_intel.json"
            )

        self.threat_db        = self._load(threat_db_path)
        self.malicious_ips    = {}
        self.malicious_ranges = []
        self.high_risk_ports  = {}
        self.threshold        = 75

        if self.threat_db:
            self._index()

    # -----------------------------------
    # Load Threat Database
    # -----------------------------------
    def _load(self, path):

        try:
            with open(path) as f:
                return json.load(f)

        except Exception as e:
            print(f"[ThreatIntel] Warning loading dataset: {e}")
            return {}

    # -----------------------------------
    # Build Lookup Index
    # -----------------------------------
    def _index(self):

        for entry in self.threat_db.get("malicious_ips", []):
            self.malicious_ips[entry["ip"]] = entry

        for entry in self.threat_db.get("malicious_ranges", []):
            try:
                net = ipaddress.ip_network(entry["range"], strict=False)
                self.malicious_ranges.append((net, entry))
            except Exception:
                continue

        for entry in self.threat_db.get("high_risk_ports", []):
            self.high_risk_ports[entry["port"]] = entry

        self.threshold = self.threat_db.get("abuse_score_threshold", 75)

    # -----------------------------------
    # Check IP Threat
    # -----------------------------------
    def _check_ip(self, ip: str) -> dict:

        if ip in ("any", "0.0.0.0/0", None, ""):
            return {"matched": False}

        clean_ip = ip.split("/")[0]

        # Exact match
        if clean_ip in self.malicious_ips:

            entry = self.malicious_ips[clean_ip]

            confidence = min(
                100,
                entry.get("abuse_score", 0) +
                entry.get("reports", 0) * 0.1
            )

            return {
                "matched"        : True,
                "match_type"     : "exact",
                "ip"             : clean_ip,
                "abuse_score"    : entry["abuse_score"],
                "category"       : entry["category"],
                "country"        : entry.get("country", "unknown"),
                "reports"        : entry.get("reports", 0),
                "last_seen"      : entry.get("last_seen", "unknown"),
                "confidence"     : round(confidence, 2),
                "category_weight": THREAT_CATEGORY_WEIGHT.get(entry["category"], 1.0),
                "auto_block"     : entry["abuse_score"] >= self.threshold
            }

        # Range match
        try:
            addr = ipaddress.ip_address(clean_ip)

            for net, entry in self.malicious_ranges:

                if addr in net:

                    return {
                        "matched"        : True,
                        "match_type"     : "range",
                        "ip"             : clean_ip,
                        "range"          : str(net),
                        "abuse_score"    : entry["abuse_score"],
                        "category"       : entry["category"],
                        "country"        : entry.get("country", "unknown"),
                        "category_weight": THREAT_CATEGORY_WEIGHT.get(entry["category"], 1.0),
                        "auto_block"     : entry["abuse_score"] >= self.threshold
                    }

        except Exception:
            pass

        return {"matched": False, "ip": clean_ip}

    # -----------------------------------
    # Check Port Risk
    # -----------------------------------
    def _check_port(self, port) -> dict:

        if port is None:
            return {"is_high_risk": False}

        # Single port
        if isinstance(port, int) and port in self.high_risk_ports:

            entry = self.high_risk_ports[port]

            return {
                "is_high_risk": True,
                "service"     : entry["service"],
                "risk_type"   : entry["risk"],
                "weight"      : entry["weight"]
            }

        # Port range
        if isinstance(port, str) and "-" in port:

            try:
                start, end = map(int, port.split("-"))

                matches = [
                    (p, self.high_risk_ports[p])
                    for p in self.high_risk_ports
                    if start <= p <= end
                ]

                if matches:
                    worst = max(matches, key=lambda x: x[1]["weight"])

                    return {
                        "is_high_risk" : True,
                        "service"      : worst[1]["service"],
                        "risk_type"    : worst[1]["risk"],
                        "weight"       : worst[1]["weight"],
                        "port_in_range": worst[0]
                    }

            except Exception:
                pass

        return {"is_high_risk": False}

    # -----------------------------------
    # Main Threat Check
    # -----------------------------------
    def check(self, rule: dict) -> dict:

        source_ip = rule.get("source_ip", "any")
        dest_ip   = rule.get("dest_ip") or rule.get("destination_ip", "any")
        port      = rule.get("port")
        intent    = rule.get("intent", "allow")

        # ------------------------
        # Threat Checks
        # ------------------------
        src_threat  = self._check_ip(source_ip)
        dst_threat  = self._check_ip(dest_ip)
        port_threat = self._check_port(port)

        # ------------------------
        # Auto Block Logic
        # ------------------------
        auto_block = (
            src_threat.get("auto_block") or
            (src_threat.get("matched") and intent == "allow")
        )

        alerts = []

        # ------------------------
        # Malicious Source
        # ------------------------
        if src_threat.get("matched"):

            alerts.append({
                "type"       : "MALICIOUS_SOURCE",
                "severity"   : "CRITICAL",
                "ip"         : src_threat.get("ip"),
                "abuse_score": src_threat.get("abuse_score"),
                "category"   : src_threat.get("category"),
                "country"    : src_threat.get("country"),
                "description": (
                    f"Source IP {src_threat.get('ip')} "
                    f"identified as {src_threat.get('category')} "
                    f"(abuse score: {src_threat.get('abuse_score')})"
                )
            })

        # ------------------------
        # Malicious Destination
        # ------------------------
        if dst_threat.get("matched"):

            alerts.append({
                "type"       : "MALICIOUS_DESTINATION",
                "severity"   : "HIGH",
                "ip"         : dst_threat.get("ip"),
                "abuse_score": dst_threat.get("abuse_score"),
                "description": (
                    f"Destination IP {dst_threat.get('ip')} "
                    f"is flagged by threat intelligence"
                )
            })

        # ------------------------
        # High Risk Port
        # ------------------------
        if port_threat.get("is_high_risk") and intent == "allow":

            alerts.append({
                "type"     : "HIGH_RISK_PORT",
                "severity" : "HIGH",
                "service"  : port_threat.get("service"),
                "risk_type": port_threat.get("risk_type"),
                "weight"   : port_threat.get("weight"),
                "description": (
                    f"Port {port} ({port_threat.get('service')}) "
                    f"is associated with {port_threat.get('risk_type')}"
                )
            })

        # ------------------------
        # Public Exposure Detection
        # FIX 2: Added intent == "allow" check
        # (was firing on DENY rules — now correctly skipped)
        # ------------------------
        if (source_ip in ("any", "0.0.0.0/0")
                and port_threat.get("is_high_risk")
                and intent == "allow"):          # ← FIXED

            alerts.append({
                "type"       : "PUBLIC_HIGH_RISK_SERVICE",
                "severity"   : "CRITICAL",
                "service"    : port_threat.get("service"),
                "description": (
                    f"{port_threat.get('service')} exposed to the internet "
                    f"— high attack probability"
                )
            })

        # ------------------------
        # Logging (Optional)
        # ------------------------
        if self.verbose and alerts:
            print(f"[ThreatIntel] Alerts detected: {alerts}")

        # ------------------------
        # Final Result
        # ------------------------
        return {
            "threat_detected": src_threat.get("matched") or dst_threat.get("matched"),
            "auto_block"     : auto_block,
            "alert_count"    : len(alerts),
            "alerts"         : alerts,
            "source_threat"  : src_threat,
            "dest_threat"    : dst_threat,
            "port_threat"    : port_threat,
            "matched"        : src_threat.get("matched", False),
            "abuse_score"    : src_threat.get("abuse_score", 0),
            "ip"             : src_threat.get("ip", source_ip)
        }