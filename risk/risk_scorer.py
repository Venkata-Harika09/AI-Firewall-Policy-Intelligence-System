"""
Task 1: CVSS-Inspired Risk Scoring Engine
AI Firewall - Milestone 3

Risk Score (0–10) based on:
Exposure / Port Sensitivity / Asset Sensitivity /
Source Scope / Protocol / Threat Intelligence
"""

import ipaddress


# -----------------------------
# Exposure Weights
# -----------------------------
EXPOSURE_WEIGHTS = {
    "public": 3.0,
    "restricted": 1.5,
    "internal": 0.5,
    "any": 3.0,
}


# -----------------------------
# Protocol Weights
# -----------------------------
PROTOCOL_WEIGHTS = {
    "tcp": 1.0,
    "udp": 0.6,
    "icmp": 0.3,
    "any": 0.8
}


# -----------------------------
# Port Sensitivity
# -----------------------------
PORT_SENSITIVITY = {
    23: 2.0, 2375: 2.0, 6443: 1.9, 445: 1.9,
    22: 1.7, 3389: 1.7, 27017: 1.7, 3306: 1.6,
    5432: 1.6, 6379: 1.6, 9200: 1.6,
    21: 1.3, 25: 1.2, 8080: 1.1, 8443: 1.0,
    80: 0.8, 443: 0.5, 53: 0.4, 123: 0.2,
}


# -----------------------------
# Port → Service Mapping
# -----------------------------
PORT_SERVICE = {
    22: "SSH",
    3389: "RDP",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    9200: "ElasticSearch",
    445: "SMB",
    21: "FTP",
    23: "Telnet",
}


# -----------------------------
# Known Exploit Intelligence
# -----------------------------
CVE_INTEL = {
    22: "SSH brute-force campaigns",
    3389: "RDP ransomware attacks",
    445: "SMB exploit vectors",
    3306: "Database exposure attacks",
    6379: "Redis unauthenticated access",
}


# -----------------------------
# Asset Sensitivity
# -----------------------------
ASSET_WEIGHTS = {
    "critical": 2.5,
    "high": 2.0,
    "medium": 1.0,
    "low": 0.5,
    "unknown": 1.0,
}


# -----------------------------
# Scope Weights
# -----------------------------
SCOPE_WEIGHTS = {
    "any": 1.5,
    "public": 1.5,
    "broad": 1.0,
    "medium": 0.5,
    "specific": 0.2,
    "host": 0.1,
}


# -----------------------------
# Scope Classification
# -----------------------------
def _classify_scope(source_ip: str):

    if source_ip in ("any", "0.0.0.0/0", None, ""):
        return "any"

    try:
        net = ipaddress.ip_network(source_ip, strict=False)

        if net.prefixlen <= 8:
            return "broad"

        if net.prefixlen <= 23:
            return "medium"

        if net.prefixlen <= 30:
            return "specific"

        return "host"

    except Exception:
        return "host"


# -----------------------------
# Port Score
# -----------------------------
def _port_score(port):

    if port is None:
        return 1.0

    if isinstance(port, int):
        return PORT_SENSITIVITY.get(port, 0.8)

    if isinstance(port, str) and "-" in port:
        try:
            start, end = map(int, port.split("-"))

            scores = [
                PORT_SENSITIVITY[p]
                for p in PORT_SENSITIVITY
                if start <= p <= end
            ]

            return max(scores) if scores else 0.8

        except Exception:
            return 0.8

    return 0.8


# -----------------------------
# Risk Scoring Engine
# -----------------------------
class RiskScorer:

    def score(self, rule: dict, threat_match: dict = None):

        intent = rule.get("intent", "allow")

        # Deny rules introduce no risk
        if intent == "deny":
            return {
                "risk_score": 0.5,
                "risk_level": "Low",
                "risk_vector": "Intent:DENY",
                "components": {},
                "recommendation": "Deny rule — reduces attack surface"
            }

        source_ip = rule.get("source_ip", "any")
        exposure = rule.get("exposure_type", "any")
        asset_sens = rule.get("asset_sensitivity", "unknown")
        port = rule.get("port")
        protocol = rule.get("protocol", "tcp")

        # exposure detection
        if source_ip in ("any", "0.0.0.0/0"):
            exposure = "public"

        elif not exposure:
            exposure = "internal"

        # -----------------------------
        # Base Scores
        # -----------------------------
        exposure_score = EXPOSURE_WEIGHTS.get(exposure, 3.0)
        port_sc = _port_score(port)

        protocol_score = PROTOCOL_WEIGHTS.get(protocol, 0.8)

        asset_score = ASSET_WEIGHTS.get(
            str(asset_sens).lower() if asset_sens else "unknown",
            1.0
        )

        scope = _classify_scope(source_ip)
        scope_score = SCOPE_WEIGHTS.get(scope, 0.5)

        # -----------------------------
        # Threat Intelligence Boost
        # -----------------------------
        threat_boost = 0.0

        if threat_match and threat_match.get("matched"):

            abuse = threat_match.get("abuse_score", 0)

            if abuse >= 90:
                threat_boost = 2.0
            elif abuse >= 75:
                threat_boost = 1.5
            else:
                threat_boost = 1.0

        # -----------------------------
        # Public Admin Detection
        # -----------------------------
        ADMIN_PORTS = [22, 3389]

        if exposure == "public" and port in ADMIN_PORTS:
            threat_boost += 2.0

        # -----------------------------
        # ANY-ANY Detection
        # -----------------------------
        if source_ip in ("any", "0.0.0.0/0") and port is None:
            threat_boost += 2.5

        # -----------------------------
        # Score Formula
        # -----------------------------
        raw = (
            exposure_score * 0.25 +
            port_sc * 0.20 +
            asset_score * 0.20 +
            scope_score * 0.15 +
            protocol_score * 0.20
        )

        normalized = min(10.0, (raw / 2.2) * 10)

        final_score = min(10.0, round(normalized + threat_boost, 2))

        # -----------------------------
        # Risk Level
        # -----------------------------
        if final_score >= 8:
            level = "Critical"
        elif final_score >= 6:
            level = "High"
        elif final_score >= 4:
            level = "Medium"
        else:
            level = "Low"

        # -----------------------------
        # Service Detection
        # -----------------------------
        service = PORT_SERVICE.get(port, "Unknown")

        exploit = CVE_INTEL.get(port)

        vector = (
            f"Exposure:{exposure.upper()}/"
            f"Protocol:{protocol.upper()}/"
            f"Service:{service}/"
            f"Port:{port}/"
            f"Asset:{asset_sens}/"
            f"Scope:{scope}/"
            f"Threat:{'YES' if threat_boost > 0 else 'NO'}"
        )

        return {
            "risk_score": final_score,
            "risk_level": level,
            "risk_vector": vector,

            "components": {
                "exposure_score": round(exposure_score, 2),
                "port_score": round(port_sc, 2),
                "protocol_score": round(protocol_score, 2),
                "asset_score": round(asset_score, 2),
                "scope_score": round(scope_score, 2),
                "threat_boost": round(threat_boost, 2),
            },

            "recommendation": self._recommend(
                final_score,
                exposure,
                port,
                asset_sens,
                scope,
                threat_match,
                exploit
            )
        }

    # -----------------------------
    # Recommendation Engine
    # -----------------------------
    def _recommend(
        self,
        score,
        exposure,
        port,
        asset_sens,
        scope,
        threat_match,
        exploit
    ):

        recs = []

        if exposure == "public" and scope in ("any", "broad"):
            recs.append(
                "Restrict source IP to trusted network (e.g. 10.0.0.0/8)"
            )

        if port in PORT_SENSITIVITY and PORT_SENSITIVITY[port] >= 1.5:
            recs.append(
                f"Port {port} is high-risk — consider VPN-only access"
            )

        if str(asset_sens).lower() in ("critical", "high") and exposure == "public":
            recs.append(
                "High-sensitivity asset exposed — enforce MFA and IP allowlist"
            )

        if threat_match and threat_match.get("matched"):
            recs.append(
                f"THREAT MATCH — Auto-block {threat_match.get('ip')}"
            )

        if exploit:
            recs.append(
                f"Known exploit vector: {exploit}"
            )

        if score >= 8:
            recs.append(
                "CRITICAL RISK — immediate remediation required"
            )

        elif score >= 6:
            recs.append(
                "HIGH RISK — review within 24 hours"
            )

        if not recs:
            recs.append(
                "Rule appears acceptable — monitor for anomalies"
            )

        return " | ".join(recs)