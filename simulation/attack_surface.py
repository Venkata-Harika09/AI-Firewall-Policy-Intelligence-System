"""
Task 2: Attack Surface Calculator
AI Firewall - Milestone 4 (Improved Version)

Attack Surface Score =
(Open Ports × w1) +
(Wide IP Ranges × w2) +
(Public Exposure × w3) +
(Admin Service Risk bonus) +
(Simulation Exposure Factors — per rule only)

Compares Before vs After optimization
"""

import ipaddress


# ─────────────────────────────────────────
# Weights
# ─────────────────────────────────────────
WEIGHT_OPEN_PORTS    = 0.40
WEIGHT_WIDE_RANGES   = 0.35
WEIGHT_PUBLIC_EXPOSE = 0.25


# High-risk service ports
PORT_DANGER = {
    22: 0.8, 23: 1.0, 3389: 0.85, 445: 0.90,
    3306: 0.85, 5432: 0.85, 27017: 0.90,
    6379: 0.88, 9200: 0.87, 2375: 0.95,
    80: 0.3, 443: 0.2, 8080: 0.4, 25: 0.5,
}

# Improvement 2: Administrative service ports get extra risk boost
ADMIN_PORTS = {22, 3389, 2375, 9200}

# Critical infrastructure assets
SENSITIVE_TARGETS = {
    "database",
    "admin",
    "backup",
    "domain_controller"
}


# ─────────────────────────────────────────
# Utility Functions
# ─────────────────────────────────────────

def _port_danger_score(port) -> float:

    if port is None:
        return 0.9

    if isinstance(port, int):
        return PORT_DANGER.get(port, 0.5)

    if isinstance(port, str) and "-" in port:
        try:
            s, e = map(int, port.split("-"))

            # Improvement 1 (FIXED):
            # Check all known danger ports that fall within the range
            # AND sample endpoints + midpoint for unknown ranges.
            # Harika's original only sampled 3 points — this missed
            # known ports like 3306, 3389, 27017 inside "1000-60000".
            known_in_range = [PORT_DANGER[p] for p in PORT_DANGER if s <= p <= e]
            sample         = [PORT_DANGER.get(p, 0.5) for p in [s, (s + e) // 2, e]]
            all_scores     = known_in_range + sample

            return max(all_scores)

        except Exception:
            return 0.6

    return 0.5


def _ip_range_width(source_ip) -> float:
    """Estimate IP exposure width: 0.0 = single host, 1.0 = entire internet"""

    if source_ip in ("any", "0.0.0.0/0", None, ""):
        return 1.0

    try:
        net = ipaddress.ip_network(source_ip, strict=False)

        if net.prefixlen <= 8:   return 0.9
        if net.prefixlen <= 16:  return 0.6
        if net.prefixlen <= 24:  return 0.3

        return 0.1

    except Exception:
        return 0.1


def _is_public(rule) -> float:

    src      = rule.get("source_ip", "any")
    exposure = rule.get("exposure_type", "")

    if src in ("any", "0.0.0.0/0") or exposure == "public":
        return 1.0

    if exposure == "restricted":
        return 0.5

    return 0.0


# ─────────────────────────────────────────
# Attack Surface Engine
# ─────────────────────────────────────────

class AttackSurfaceCalculator:

    def score_rule(self, rule: dict, simulation: dict = None) -> dict:
        """
        Score a single firewall rule's attack surface contribution.

        simulation: optional result from PolicySimulator.simulate_attack()
                    for THIS specific rule only — not shared across ruleset.
        """

        if rule.get("intent") == "deny":
            return {
                "surface_score": 0.0,
                "level"        : "None",
                "components"   : {},
                "reasons"      : ["Deny rule reduces attack surface"]
            }

        reasons = []

        port_score   = _port_danger_score(rule.get("port"))
        range_score  = _ip_range_width(rule.get("source_ip", "any"))
        public_score = _is_public(rule)

        if port_score > 0.7:
            reasons.append("High-risk service exposed")

        if range_score > 0.7:
            reasons.append("Wide IP range allowed")

        if public_score > 0.7:
            reasons.append("Public internet exposure")

        raw = (
            port_score   * WEIGHT_OPEN_PORTS  +
            range_score  * WEIGHT_WIDE_RANGES +
            public_score * WEIGHT_PUBLIC_EXPOSE
        )

        # ── Improvement 2: Administrative Service Risk ────────────
        # Admin services (SSH, RDP, Docker, Elasticsearch) are prime
        # targets for attackers — deserves a real-world risk boost.
        if rule.get("port") in ADMIN_PORTS:
            raw += 0.2
            reasons.append("Administrative service exposed")

        # ─────────────────────────────────────────────────────────
        # SIMULATION FIX:
        # simulation data is only applied in score_rule() when
        # explicitly passed for a single rule — NOT in score_ruleset()
        # or compare(). Passing a shared simulation to all rules would
        # inflate every rule equally and make before/after meaningless.
        # ─────────────────────────────────────────────────────────
        if simulation:

            reachable_nodes = simulation.get("reachable_nodes", [])
            exposed_ports   = simulation.get("exposed_ports", [])

            # Each reachable node adds exposure (capped at +0.5)
            if reachable_nodes:
                raw += min(len(reachable_nodes) * 0.05, 0.5)
                reasons.append(f"{len(reachable_nodes)} internal assets reachable")

            # Sensitive targets reachable — critical boost
            sensitive = set(reachable_nodes) & SENSITIVE_TARGETS
            if sensitive:
                raw += 0.5
                reasons.append(f"Critical infrastructure exposed: {', '.join(sensitive)}")

            # Improvement 3: Service Diversity Exposure
            # 4+ unique services = wider attack surface
            unique_services = len(set(exposed_ports))
            if unique_services >= 4:
                raw += 0.2
                reasons.append(f"Multiple service types exposed ({unique_services} services)")

            # Additional risky ports exposed via simulation paths
            risky_ports = [p for p in exposed_ports if p in PORT_DANGER]
            if risky_ports:
                raw += min(len(risky_ports) * 0.03, 0.3)
                reasons.append("Multiple services exposed via attack paths")

        surface_score = round(min(10.0, raw * 10.0), 2)

        if surface_score >= 7.0:   level = "Critical"
        elif surface_score >= 5.0: level = "High"
        elif surface_score >= 3.0: level = "Medium"
        else:                      level = "Low"

        return {
            "surface_score": surface_score,
            "level"        : level,
            "components"   : {
                "port_score"  : round(port_score, 2),
                "range_score" : round(range_score, 2),
                "public_score": round(public_score, 2),
            },
            "reasons"      : reasons
        }

    # ─────────────────────────────────────────────────────────────
    # score_ruleset: simulation intentionally NOT passed here.
    # Simulation is per-rule — passing a shared sim inflates all
    # rules equally, making before/after comparison meaningless.
    # ─────────────────────────────────────────────────────────────

    def score_ruleset(self, rules: list) -> dict:
        """Score entire ruleset's cumulative attack surface"""

        allow_rules = [r for r in rules if r.get("intent") == "allow"]

        if not allow_rules:
            return {"total_score": 0.0, "level": "None", "rule_count": 0, "details": []}

        scores  = []
        details = []

        for rule in allow_rules:

            s = self.score_rule(rule)   # no simulation — keeps comparison clean

            scores.append(s["surface_score"])
            details.append({
                "policy_text"  : rule.get("policy_text", "unknown"),
                "surface_score": s["surface_score"],
                "level"        : s["level"],
                "reasons"      : s.get("reasons", [])
            })

        avg_score  = sum(scores) / len(scores)
        peak_score = max(scores)
        total      = round(min(10.0, avg_score * 0.6 + peak_score * 0.4), 2)

        if total >= 7.0:   level = "Critical"
        elif total >= 5.0: level = "High"
        elif total >= 3.0: level = "Medium"
        else:              level = "Low"

        return {
            "total_score": total,
            "level"      : level,
            "rule_count" : len(allow_rules),
            "avg_score"  : round(avg_score, 2),
            "peak_score" : round(peak_score, 2),
            "details"    : details,
        }

    # ─────────────────────────────────────────────────────────────

    def compare(self, before_rules: list, after_rules: list) -> dict:
        """
        Compare attack surface before and after optimization.
        Uses score_ruleset() (no simulation) for a fair comparison.
        """

        before = self.score_ruleset(before_rules)
        after  = self.score_ruleset(after_rules)

        delta    = round(before["total_score"] - after["total_score"], 2)
        improved = delta > 0

        improvement_pct = (
            round((delta / before["total_score"]) * 100, 2)
            if before["total_score"] > 0 else 0
        )

        if delta >= 3.0:   reduction = "Significant"
        elif delta >= 1.0: reduction = "Moderate"
        elif delta > 0:    reduction = "Minor"
        else:              reduction = "No improvement"

        return {
            "before"             : before,
            "after"              : after,
            "delta"              : delta,
            "improvement_percent": improvement_pct,
            "improved"           : improved,
            "reduction_level"    : reduction,
            "summary"            : (
                f"Attack surface reduced by {delta} points ({reduction}) "
                f"[{improvement_pct}% improvement]"
                if improved else
                "No reduction in attack surface"
            )
        }


# ─────────────────────────────────────────
# Demo Test
# ─────────────────────────────────────────

if __name__ == "__main__":

    calc = AttackSurfaceCalculator()

    rules_before = [
        {"policy_text": "Allow SSH from any",   "intent": "allow", "port": 22,   "source_ip": "any",         "exposure_type": "public"},
        {"policy_text": "Allow RDP from any",   "intent": "allow", "port": 3389, "source_ip": "any",         "exposure_type": "public"},
        {"policy_text": "Allow MySQL from any", "intent": "allow", "port": 3306, "source_ip": "any",         "exposure_type": "public"},
        {"policy_text": "Allow HTTPS from any", "intent": "allow", "port": 443,  "source_ip": "any",         "exposure_type": "public"},
    ]

    rules_after = [
        {"policy_text": "Allow SSH from VPN",   "intent": "allow", "port": 22,   "source_ip": "10.0.0.0/8",  "exposure_type": "internal"},
        {"policy_text": "Allow RDP from LAN",   "intent": "allow", "port": 3389, "source_ip": "10.0.1.0/24", "exposure_type": "internal"},
        {"policy_text": "Allow MySQL internal", "intent": "allow", "port": 3306, "source_ip": "10.0.0.0/16", "exposure_type": "internal"},
        {"policy_text": "Allow HTTPS from any", "intent": "allow", "port": 443,  "source_ip": "any",         "exposure_type": "public"},
    ]

    ssh_simulation = {
        "reachable_nodes": ["dmz", "internal", "admin", "database", "external"],
        "exposed_ports"  : [22, 443, 3306, 3389, 27017]
    }

    print("=" * 65)
    print("  TASK 2: ATTACK SURFACE CALCULATOR — ALL 3 IMPROVEMENTS")
    print("=" * 65)

    print("\n  IMPROVEMENT 1 — Port Range Handling:")
    for rng in ["1000-60000", "20-25", "3000-4000", "50000-60000"]:
        score = _port_danger_score(rng)
        print(f"  Range {rng:<15} → danger score = {score}")

    print("\n  IMPROVEMENT 2 — Admin Service Risk:")
    for port, label in [(22,"SSH"), (3389,"RDP"), (2375,"Docker"), (80,"HTTP"), (443,"HTTPS")]:
        rule = {"port":port,"source_ip":"any","exposure_type":"public","intent":"allow"}
        s = calc.score_rule(rule)
        admin = "👑 ADMIN+" if port in ADMIN_PORTS else "normal "
        print(f"  Port {port:<6} {label:<15} [{admin}]  Score={s['surface_score']}  Reasons: {', '.join(s['reasons'])}")

    print("\n  IMPROVEMENT 3 — Service Diversity (with simulation):")
    s = calc.score_rule(rules_before[0], ssh_simulation)
    print(f"  Rule   : {rules_before[0]['policy_text']}")
    print(f"  Score  : {s['surface_score']}/10  [{s['level']}]")
    print(f"  Reasons: {chr(10)           .join('    → ' + r for r in s['reasons'])}")

    print("\n  BEFORE vs AFTER COMPARISON:")
    cmp = calc.compare(rules_before, rules_after)
    print(f"  Before : {cmp['before']['total_score']}/10  [{cmp['before']['level']}]")
    print(f"  After  : {cmp['after']['total_score']}/10  [{cmp['after']['level']}]")
    print(f"  Delta  : -{cmp['delta']} pts  ({cmp['reduction_level']})")
    print(f"  ✅ {cmp['summary']}")