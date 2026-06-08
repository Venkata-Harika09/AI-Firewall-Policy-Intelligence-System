"""
Task 3: Self-Healing Recommendation Engine
AI Firewall - Milestone 4

For each risky rule, suggests:
  - Restrict IP range
  - Add time constraint
  - Change priority
  - Block malicious IP
  - Protocol restriction
  - Port-specific hardening
"""

import ipaddress


# ─────────────────────────────────────────
# Risk thresholds
# ─────────────────────────────────────────
CRITICAL_THRESHOLD = 8.0
HIGH_THRESHOLD     = 6.0
MEDIUM_THRESHOLD   = 4.0

ADMIN_PORTS     = {22, 3389, 2375, 6443}
SENSITIVE_PORTS = {22, 23, 3389, 445, 3306, 5432, 27017, 6379, 9200}

# Safe internal ranges
TRUSTED_RANGES = {
    "internal"  : "10.0.0.0/8",
    "corporate" : "192.168.0.0/16",
    "vpn"       : "172.16.0.0/12",
}

# Business hours suggestion
BUSINESS_HOURS = "08:00-18:00"


class SelfHealingEngine:

    def recommend(self, rule: dict, risk_score: float,
                  threat_match: dict = None) -> dict:
        """
        Generate prioritized self-healing recommendations
        for a risky rule.
        """

        if rule.get("intent") == "deny":
            return {
                "recommendations": [],
                "healed_rule"    : rule,
                "priority"       : "None",
                "summary"        : "Deny rule — no healing needed"
            }

        recs        = []
        healed_rule = dict(rule)   # copy to modify

        source_ip  = rule.get("source_ip", "any")
        port       = rule.get("port")
        exposure   = rule.get("exposure_type", "public")
        asset_sens = rule.get("asset_sensitivity", "medium")

        # ── Rec 1: Restrict IP Range ─────────────────────────────
        if source_ip in ("any", "0.0.0.0/0", None, ""):

            if port in ADMIN_PORTS:
                suggested_ip = TRUSTED_RANGES["vpn"]
                reason       = f"Admin port {port} should only be reachable via VPN"
            elif asset_sens in ("critical", "high"):
                suggested_ip = TRUSTED_RANGES["internal"]
                reason       = f"High-sensitivity asset — restrict to internal network"
            else:
                suggested_ip = TRUSTED_RANGES["corporate"]
                reason       = "Restrict public access to corporate network only"

            recs.append({
                "type"      : "RESTRICT_IP_RANGE",
                "priority"  : "CRITICAL",
                "current"   : f"source_ip = {source_ip or 'any'}",
                "suggested" : f"source_ip = {suggested_ip}",
                "reason"    : reason,
                "impact"    : "Eliminates public exposure — reduces surface score by ~40%"
            })
            healed_rule["source_ip"]    = suggested_ip
            healed_rule["exposure_type"] = "internal"

        elif source_ip:
            try:
                net = ipaddress.ip_network(source_ip, strict=False)
                if net.prefixlen <= 24:
                    narrower = f"{source_ip.split('/')[0]}/{min(net.prefixlen + 8, 30)}"
                    recs.append({
                        "type"      : "NARROW_IP_RANGE",
                        "priority"  : "HIGH",
                        "current"   : f"source_ip = {source_ip}",
                        "suggested" : f"source_ip = {narrower}",
                        "reason"    : "Wide IP range increases exposure unnecessarily",
                        "impact"    : "Reduces IP scope — moderate surface reduction"
                    })
                    healed_rule["source_ip"] = narrower
            except Exception:
                pass

        # ── Rec 2: Add Time Constraint ───────────────────────────
        if not rule.get("time_constraint"):

            if port in ADMIN_PORTS or asset_sens in ("critical", "high"):
                recs.append({
                    "type"      : "ADD_TIME_CONSTRAINT",
                    "priority"  : "HIGH",
                    "current"   : "time_constraint = None (always active)",
                    "suggested" : f"time_constraint = {BUSINESS_HOURS}",
                    "reason"    : "Limit access to business hours only",
                    "impact"    : "Reduces attack window by ~67% (8hrs vs 24hrs)"
                })
                healed_rule["time_constraint"] = BUSINESS_HOURS

        # ── Rec 3: Change Priority ───────────────────────────────
        current_priority = rule.get("priority", 1)

        if rule.get("intent") == "allow" and port in SENSITIVE_PORTS:
            if current_priority <= 3:
                recs.append({
                    "type"      : "CHANGE_PRIORITY",
                    "priority"  : "MEDIUM",
                    "current"   : f"priority = {current_priority} (near top)",
                    "suggested" : "priority = after specific DENY rules",
                    "reason"    : "Sensitive service allow rules should come after deny rules",
                    "impact"    : "Ensures deny rules evaluated first — prevents bypass"
                })

        # ── Rec 4: Block Malicious IP ────────────────────────────
        if threat_match and threat_match.get("matched"):
            ip         = threat_match.get("ip", "unknown")
            abuse_score = threat_match.get("abuse_score", 0)
            recs.append({
                "type"      : "BLOCK_MALICIOUS_IP",
                "priority"  : "CRITICAL",
                "current"   : f"source_ip allows {ip}",
                "suggested" : f"iptables -A INPUT -s {ip} -j DROP",
                "reason"    : f"IP {ip} has abuse score {abuse_score} — known threat actor",
                "impact"    : "Immediately blocks known attacker — eliminates threat match"
            })
            healed_rule["blocked_ips"] = healed_rule.get("blocked_ips", []) + [ip]

        # ── Rec 5: Protocol Restriction ──────────────────────────
        if rule.get("protocol") in ("any", None) and port is not None:
            proto_map = {22:"tcp", 3389:"tcp", 3306:"tcp", 443:"tcp", 80:"tcp", 53:"udp"}
            suggested_proto = proto_map.get(port, "tcp")
            recs.append({
                "type"      : "RESTRICT_PROTOCOL",
                "priority"  : "MEDIUM",
                "current"   : "protocol = any",
                "suggested" : f"protocol = {suggested_proto}",
                "reason"    : f"Port {port} should only use {suggested_proto}",
                "impact"    : "Eliminates unexpected protocol abuse"
            })
            healed_rule["protocol"] = suggested_proto

        # ── Rec 6: Port-Specific Hardening ───────────────────────
        PORT_HARDENING = {
            22:    "Enforce key-based auth only — disable password login",
            3389:  "Enable NLA (Network Level Authentication)",
            3306:  "Bind MySQL to localhost — use SSH tunnel for remote access",
            27017: "Enable MongoDB authentication — disable anonymous access",
            6379:  "Set Redis requirepass — bind to 127.0.0.1",
        }

        if port in PORT_HARDENING:
            recs.append({
                "type"      : "PORT_HARDENING",
                "priority"  : "HIGH",
                "current"   : f"Port {port} with default settings",
                "suggested" : PORT_HARDENING[port],
                "reason"    : f"Service-specific hardening for port {port}",
                "impact"    : "Hardens service against targeted attacks"
            })

        # Sort by priority
        priority_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        recs.sort(key=lambda x: priority_order.get(x["priority"], 3))

        # Overall healing priority
        if any(r["priority"] == "CRITICAL" for r in recs):
            overall = "CRITICAL"
        elif any(r["priority"] == "HIGH" for r in recs):
            overall = "HIGH"
        elif recs:
            overall = "MEDIUM"
        else:
            overall = "None"

        return {
            "recommendations": recs,
            "healed_rule"    : healed_rule,
            "priority"       : overall,
            "rec_count"      : len(recs),
            "summary"        : f"{len(recs)} recommendation(s) — priority: {overall}"
        }


if __name__ == "__main__":

    engine = SelfHealingEngine()

    tests = [
        ({"policy_text":"Allow SSH from any",   "intent":"allow","port":22,   "source_ip":"any",        "exposure_type":"public","asset_sensitivity":"high","protocol":"tcp","priority":1}, 9.8, None),
        ({"policy_text":"Allow RDP from any",   "intent":"allow","port":3389, "source_ip":"any",        "exposure_type":"public","asset_sensitivity":"high","protocol":"tcp","priority":1}, 9.4, None),
        ({"policy_text":"Allow MySQL internal", "intent":"allow","port":3306, "source_ip":"10.0.0.0/8", "exposure_type":"internal","asset_sensitivity":"critical","protocol":"tcp","priority":2}, 5.5, None),
        ({"policy_text":"Allow from botnet",    "intent":"allow","port":80,   "source_ip":"any",        "exposure_type":"public","asset_sensitivity":"high","protocol":"tcp","priority":1}, 8.9, {"matched":True,"ip":"198.51.100.25","abuse_score":95}),
        ({"policy_text":"Deny all traffic",     "intent":"deny", "port":None, "source_ip":"any",        "exposure_type":"public","asset_sensitivity":"low","protocol":"any","priority":100}, 0.5, None),
    ]

    print("="*65)
    print("  TASK 3: SELF-HEALING RECOMMENDATION ENGINE")
    print("="*65)

    for rule, risk_score, threat in tests:
        r = engine.recommend(rule, risk_score, threat)
        icon = "🔴" if r["priority"]=="CRITICAL" else "🟠" if r["priority"]=="HIGH" else "🟡" if r["priority"]=="MEDIUM" else "🟢"
        print(f"\n  {icon} {rule['policy_text']}  (risk={risk_score})")
        print(f"     {r['summary']}")
        for rec in r["recommendations"]:
            p_icon = "🔴" if rec["priority"]=="CRITICAL" else "🟠" if rec["priority"]=="HIGH" else "🟡"
            print(f"     {p_icon} [{rec['priority']}] {rec['type']}")
            print(f"        Current  : {rec['current']}")
            print(f"        Suggested: {rec['suggested']}")
            print(f"        Impact   : {rec['impact']}")