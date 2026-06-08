"""
Task 4: Zero Trust Validation Engine
AI Firewall - Milestone 2

Checks:
- ANY-to-ANY rules
- Public admin exposure
- Public database exposure
- Least privilege violations
- Default deny policy
- Malicious IP allowance

Outputs:
Zero Trust compliance score (0–100)
"""

ADMIN_PORTS = {
    22: "SSH",
    3389: "RDP",
    8080: "Admin Panel",
    8443: "Admin HTTPS",
    2375: "Docker API",
    6443: "Kubernetes API",
    8888: "Jupyter Notebook"
}

DATABASE_PORTS = {
    3306: "MySQL",
    5432: "PostgreSQL",
    27017: "MongoDB",
    6379: "Redis",
    9200: "Elasticsearch",
    1433: "MSSQL",
    5984: "CouchDB"
}

PUBLIC_IPS = ("any", "0.0.0.0/0")


# ─────────────────────────────────────────
# Helper: Check port or port-range
# ─────────────────────────────────────────
def _port_in_range(port, port_set):

    if port is None:
        return False

    if isinstance(port, int):
        return port in port_set

    if isinstance(port, str) and "-" in port:
        try:
            start, end = map(int, port.split("-"))
            return any(start <= p <= end for p in port_set)
        except Exception:
            return False

    return False


# ─────────────────────────────────────────
# Zero Trust Validator
# ─────────────────────────────────────────
class ZeroTrustValidator:

    def validate_rule(self, new_rule: dict, existing_rules: list) -> dict:

        violations = []
        suggestions = []

        src = new_rule.get("source_ip", "any")
        dst = new_rule.get("destination_ip", "any")
        port = new_rule.get("port")
        intent = new_rule.get("intent", "allow")
        proto = new_rule.get("protocol", "any")

        # ─────────────────────────
        # ZT-001 ANY-to-ANY
        # ─────────────────────────
        if (
            src in PUBLIC_IPS
            and dst in PUBLIC_IPS
            and intent == "allow"
            and port in (None, "any")
        ):
            violations.append({
                "check": "ZT-001",
                "severity": "HIGH",
                "description": "Rule allows unrestricted ANY-to-ANY traffic",
                "suggestion": "Restrict source IP, destination IP, or port"
            })

        # ─────────────────────────
        # ZT-002 Public Admin Exposure
        # ─────────────────────────
        if (
            src in PUBLIC_IPS
            and intent == "allow"
            and _port_in_range(port, ADMIN_PORTS)
        ):
            violations.append({
                "check": "ZT-002",
                "severity": "CRITICAL",
                "description":
                    f"{ADMIN_PORTS.get(port, 'Admin service')} exposed to public internet",
                "suggestion":
                    "Restrict access to internal IP range (e.g., 10.0.0.0/8)"
            })

        # ─────────────────────────
        # ZT-003 Public Database Exposure
        # ─────────────────────────
        if (
            src in PUBLIC_IPS
            and intent == "allow"
            and _port_in_range(port, DATABASE_PORTS)
        ):
            violations.append({
                "check": "ZT-003",
                "severity": "CRITICAL",
                "description":
                    "Database service exposed to public internet",
                "suggestion":
                    "Databases should NEVER be publicly accessible"
            })

        # ─────────────────────────
        # ZT-004 Least Privilege
        # ─────────────────────────
        if (
            intent == "allow"
            and src in PUBLIC_IPS
            and port in (None, "any")
            and proto == "any"
        ):
            violations.append({
                "check": "ZT-004",
                "severity": "HIGH",
                "description":
                    "Allow rule lacks restrictions (violates least privilege)",
                "suggestion":
                    "Add source IP restriction, protocol, or port"
            })

        elif intent == "allow" and src in PUBLIC_IPS:
            suggestions.append(
                "Consider restricting source IP for better least privilege"
            )

        # ─────────────────────────
        # ZT-005 Default Deny Policy
        # ─────────────────────────
        sorted_rules = sorted(
            existing_rules,
            key=lambda r: int(r.get("priority", 999))
        )

        last_rule = sorted_rules[-1] if sorted_rules else None

        has_default_deny = (
            last_rule
            and last_rule.get("intent") == "deny"
            and last_rule.get("source_ip") in PUBLIC_IPS
            and last_rule.get("port") in (None, "any")
        )

        if not has_default_deny:
            suggestions.append(
                "No default deny-all rule found — add one at the end (ZT-005)"
            )

        # ─────────────────────────
        # ZT-006 Malicious IP Allowed
        # ─────────────────────────
        if new_rule.get("is_malicious_ip") and intent == "allow":
            violations.append({
                "check": "ZT-006",
                "severity": "CRITICAL",
                "description":
                    "Rule allows traffic from known malicious IP",
                "suggestion":
                    "Block this IP immediately"
            })

        # ─────────────────────────
        # Score calculation
        # ─────────────────────────
        score_impact = self._compute_score_impact(violations)

        base_score = self._compute_base_score(existing_rules)

        new_score = max(0, base_score - score_impact)

        return {
            "violations": violations,
            "suggestions": suggestions,
            "violation_count": len(violations),
            "base_score": base_score,
            "new_score": new_score,
            "score_impact": score_impact,
            "score_level": self._level(new_score)
        }

    # ─────────────────────────────────────────
    # Score impact from violations
    # ─────────────────────────────────────────
    def _compute_score_impact(self, violations):

        impact = 0

        for v in violations:

            if v["severity"] == "CRITICAL":
                impact += 15

            elif v["severity"] == "HIGH":
                impact += 8

            else:
                impact += 3

        return impact

    # ─────────────────────────────────────────
    # Base score of existing ruleset
    # ─────────────────────────────────────────
    def _compute_base_score(self, existing_rules):

        if not existing_rules:
            return 100.0

        deductions = 0

        for rule in existing_rules:

            src = rule.get("source_ip", "any")
            dst = rule.get("destination_ip", "any")
            port = rule.get("port")
            intent = rule.get("intent", "allow")

            if src in PUBLIC_IPS and dst in PUBLIC_IPS and intent == "allow":
                deductions += 3

            if src in PUBLIC_IPS and _port_in_range(port, ADMIN_PORTS) and intent == "allow":
                deductions += 5

            if src in PUBLIC_IPS and _port_in_range(port, DATABASE_PORTS) and intent == "allow":
                deductions += 5

        sorted_rules = sorted(
            existing_rules,
            key=lambda r: int(r.get("priority", 999))
        )

        last = sorted_rules[-1] if sorted_rules else None

        if not (
            last
            and last.get("intent") == "deny"
            and last.get("source_ip") in PUBLIC_IPS
        ):
            deductions += 15

        return max(0, round(100 - deductions, 1))

    # ─────────────────────────────────────────
    # Score level classification
    # ─────────────────────────────────────────
    def _level(self, score):

        if score >= 90:
            return "EXCELLENT"

        if score >= 70:
            return "GOOD"

        if score >= 50:
            return "MODERATE"

        return "POOR"