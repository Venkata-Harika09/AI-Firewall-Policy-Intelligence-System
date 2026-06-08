"""
Task 4: Explainability Engine
AI Firewall - Milestone 4 (Improved Version)

Generates human-readable explanations for:
  - Risk scores
  - Threat detections
  - Attack simulation
  - Self-healing recommendations
  - Zero Trust violations
"""

PORT_DESCRIPTIONS = {
    22:    ("SSH",            "remote shell access",        "brute-force and credential stuffing attacks"),
    23:    ("Telnet",         "unencrypted remote access",  "credential interception and MITM attacks"),
    3389:  ("RDP",            "remote desktop",             "ransomware delivery and lateral movement"),
    445:   ("SMB",            "file sharing",               "ransomware propagation"),
    3306:  ("MySQL",          "database access",            "data exfiltration and SQL injection"),
    5432:  ("PostgreSQL",     "database access",            "data exfiltration"),
    27017: ("MongoDB",        "NoSQL database",             "unauthenticated data access"),
    6379:  ("Redis",          "in-memory cache",            "remote code execution"),
    9200:  ("Elasticsearch",  "search engine",              "unauthenticated data exposure"),
    2375:  ("Docker API",     "container management",       "host compromise"),
    6443:  ("Kubernetes API", "cluster control",            "cluster takeover"),
    80:    ("HTTP",           "web traffic",                "web application attacks"),
    443:   ("HTTPS",          "secure web traffic",         "encrypted web attacks"),
}

RISK_DESCRIPTIONS = {
    "Critical" : "immediate threat — exploitation likely within hours",
    "High"     : "serious risk — remediate within 24 hours",
    "Medium"   : "moderate risk — schedule remediation soon",
    "Low"      : "minimal risk — monitor periodically",
}


class ExplainabilityEngine:

    def explain(self, rule, risk_result=None,
                threat_result=None, sim_result=None,
                healing_result=None):

        sections = {
            "rule"      : self._explain_rule(rule),
            "risk"      : self._explain_risk(rule, risk_result),
            "threat"    : self._explain_threat(threat_result),
            "simulation": self._explain_simulation(sim_result),
            "healing"   : self._explain_healing(healing_result),
        }

        narrative  = self._build_narrative(rule, risk_result, sim_result, healing_result)
        confidence = self._confidence_score(risk_result, threat_result, sim_result)

        return {
            "rule"       : sections["rule"],
            "risk"       : sections["risk"],
            "threat"     : sections["threat"],
            "simulation" : sections["simulation"],
            "healing"    : sections["healing"],
            "narrative"  : narrative,
            "confidence" : confidence,
        }

    # ─────────────────────────────────────────────────────────────
    # Rule Explanation
    # ─────────────────────────────────────────────────────────────

    def _explain_rule(self, rule):

        intent = rule.get("intent", "allow")
        port   = rule.get("port")
        src    = rule.get("source_ip", "any")
        proto  = rule.get("protocol", "tcp") or "tcp"

        if intent == "deny":
            return "This rule blocks traffic, reducing the attack surface."

        port_info = PORT_DESCRIPTIONS.get(port)

        if not port_info:
            return (
                f"This rule allows {proto.upper()} traffic on port {port} "
                f"from {'any source' if src in ('any', '0.0.0.0/0') else src}. "
                "Unknown service — manual review recommended."
            )

        service, purpose, risk = port_info

        src_desc = (
            "any internet source"
            if src in ("any", "0.0.0.0/0") else src
        )

        return (
            f"This rule allows {service} ({purpose}) from {src_desc}. "
            f"{service} is commonly targeted for {risk}."
        )

    # ─────────────────────────────────────────────────────────────
    # Risk Explanation
    # ─────────────────────────────────────────────────────────────

    def _explain_risk(self, rule, risk_result):

        if not risk_result:
            return "Risk analysis unavailable."

        score = risk_result.get("risk_score", 0)
        level = risk_result.get("risk_level", "Unknown")

        parts = [
            f"Risk score is {score}/10 categorized as {level}. "
            f"{RISK_DESCRIPTIONS.get(level, '')}"
        ]

        src = rule.get("source_ip", "any")

        if src in ("any", "0.0.0.0/0") and rule.get("intent") != "deny":
            parts.append(
                "This configuration violates Zero Trust principles "
                "because it allows unrestricted external access."
            )

        return " ".join(parts)

    # ─────────────────────────────────────────────────────────────
    # Threat Explanation
    # ─────────────────────────────────────────────────────────────

    def _explain_threat(self, threat_result):

        if not threat_result:
            return "No threat intelligence analysis performed."

        if threat_result.get("alert_count", 0) == 0:
            return "No known malicious sources detected."

        parts = []

        for alert in threat_result.get("alerts", [])[:3]:

            if alert["type"] == "MALICIOUS_SOURCE":
                parts.append(
                    f"Source IP {alert.get('ip')} is flagged as "
                    f"{alert.get('category')} with abuse score "
                    f"{alert.get('abuse_score')}."
                )

            elif alert["type"] == "HIGH_RISK_PORT":
                parts.append(
                    f"Port {alert.get('service')} is frequently targeted "
                    f"for {alert.get('risk_type')} attacks."
                )

        return " ".join(parts) if parts else "Threat alerts detected — review required."

    # ─────────────────────────────────────────────────────────────
    # Simulation Explanation
    # ─────────────────────────────────────────────────────────────

    def _explain_simulation(self, sim_result):

        if not sim_result:
            return "Attack simulation not executed."

        paths = sim_result.get("paths_found", 0)

        if paths == 0:
            return "Simulation found no viable attack paths."

        targets      = sim_result.get("target_reached", [])
        target_names = list({t["target"] for t in targets})[:5]

        text = f"Simulation discovered {paths} potential attack paths."

        if target_names:
            text += (
                f" Critical systems reachable include "
                f"{', '.join(target_names).upper()}."
            )

        if sim_result.get("lateral_movement"):
            text += (
                " Lateral movement inside the network is possible "
                "after initial compromise."
            )

        return text

    # ─────────────────────────────────────────────────────────────
    # Healing Explanation
    # ─────────────────────────────────────────────────────────────

    def _explain_healing(self, healing_result):

        if not healing_result or not healing_result.get("recommendations"):
            return "No automated remediation required."

        recs = healing_result["recommendations"][:3]

        text = f"{len(recs)} security remediation action(s) recommended: "

        for r in recs:
            # FIX 2: keep original type casing — avoids "Restrict Ip Range"
            text += f"{r['type']} ({r['impact']}). "

        return text

    # ─────────────────────────────────────────────────────────────
    # Full Narrative
    # ─────────────────────────────────────────────────────────────

    def _build_narrative(self, rule, risk_result,
                         sim_result, healing_result):

        # FIX 1: deny rule gets its own clean narrative
        if rule.get("intent") == "deny":
            return "This DENY rule blocks traffic — no exposure introduced."

        port    = rule.get("port")
        src     = rule.get("source_ip", "any")
        service = PORT_DESCRIPTIONS.get(port, ("service", "", ""))[0]
        score   = risk_result.get("risk_score", 0)   if risk_result else 0
        level   = risk_result.get("risk_level", "Unknown") if risk_result else "Unknown"

        narrative = (
            f"This firewall rule exposes {service} to "
            f"{'the public internet' if src in ('any', '0.0.0.0/0') else src}. "
            f"It results in a risk score of {score}/10 ({level}). "
        )

        if sim_result and sim_result.get("target_reached"):
            targets = {t["target"] for t in sim_result["target_reached"]}
            narrative += (
                f"Attack simulation indicates an attacker could reach "
                f"{', '.join(targets).upper()}. "
            )

        if healing_result and healing_result.get("recommendations"):
            top = healing_result["recommendations"][0]
            narrative += (
                f"Recommended mitigation: {top['type']} "
                f"to reduce exposure."
            )

        return narrative

    # ─────────────────────────────────────────────────────────────
    # Confidence Score
    # ─────────────────────────────────────────────────────────────

    def _confidence_score(self, risk_result, threat_result, sim_result):
        """
        Confidence in explanation quality:
          0.50 base
         +0.20 if risk scoring available
         +0.15 if threat intelligence available
         +0.15 if simulation available
         = 1.00 max (all data present)
        """

        score = 0.5

        if risk_result:   score += 0.20
        if threat_result: score += 0.15
        if sim_result:    score += 0.15

        return round(min(score, 1.0), 2)


# ─────────────────────────────────────────────────────────────────
# Demo Test
# ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":

    engine = ExplainabilityEngine()

    rule = {
        "intent"    : "allow",
        "port"      : 22,
        "source_ip" : "any",
        "protocol"  : "tcp",
    }

    risk_result = {
        "risk_score" : 9.8,
        "risk_level" : "Critical",
    }

    threat_result = {
        "alert_count": 2,
        "alerts": [
            {"type": "HIGH_RISK_PORT", "service": "SSH", "risk_type": "brute_force"},
            {"type": "HIGH_RISK_PORT", "service": "SSH", "risk_type": "credential_stuffing"},
        ]
    }

    sim_result = {
        "paths_found"     : 9,
        "simulation_level": "CRITICAL",
        "target_reached"  : [
            {"target": "database", "path": ["internet","dmz","database"],          "hops": 2},
            {"target": "admin",    "path": ["internet","dmz","internal","admin"],  "hops": 3},
        ],
        "lateral_movement": [{"from": "dmz", "to": "internal"}]
    }

    healing_result = {
        "recommendations": [
            {"type": "RESTRICT_IP_RANGE",    "priority": "CRITICAL", "impact": "Removes public exposure"},
            {"type": "ADD_TIME_CONSTRAINT",  "priority": "HIGH",     "impact": "Reduces attack window"},
            {"type": "PORT_HARDENING",       "priority": "HIGH",     "impact": "Hardens service config"},
        ]
    }

    print("=" * 65)
    print("  TASK 4: EXPLAINABILITY ENGINE")
    print("=" * 65)

    result = engine.explain(rule, risk_result, threat_result, sim_result, healing_result)

    print(f"\n  📋 Rule       : {result['rule']}")
    print(f"\n  📊 Risk       : {result['risk']}")
    print(f"\n  🔍 Threat     : {result['threat']}")
    print(f"\n  🎮 Simulation : {result['simulation']}")
    print(f"\n  🔧 Healing    : {result['healing']}")
    print(f"\n  📖 Narrative  : {result['narrative']}")
    print(f"\n  🎯 Confidence : {result['confidence']}")

    # Fix verifications
    print("\n" + "=" * 65)
    print("  FIX VERIFICATIONS")
    print("=" * 65)

    deny_result = engine.explain({"intent":"deny","port":None,"source_ip":"any"})
    print(f"\n  FIX 1 — Deny narrative : {deny_result['narrative']}")

    healing_text = engine._explain_healing(healing_result)
    print(f"\n  FIX 2 — Healing text   : {healing_text}")
    print(f"  Type casing correct    : {'RESTRICT_IP_RANGE' in healing_text}")