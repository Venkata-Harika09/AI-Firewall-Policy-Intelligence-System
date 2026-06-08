"""
Task 3: Rule Optimization Module
AI Firewall - Milestone 2

Detects:
- Duplicate rules
- Subnet overlaps
- Inefficient / redundant rules
- Public admin exposure
"""

import ipaddress


SENSITIVE_PORTS = {22, 3389, 3306, 5432, 27017, 2375}


# ─────────────────────────────────────────
# Subnet containment check
# ─────────────────────────────────────────
def _subnet_contains(outer: str, inner: str) -> bool:

    try:

        if outer in ("any", "0.0.0.0/0"):
            return True

        if inner in ("any", "0.0.0.0/0"):
            return False

        net_outer = ipaddress.ip_network(outer, strict=False)
        net_inner = ipaddress.ip_network(inner, strict=False)

        return net_inner.subnet_of(net_outer)

    except Exception:
        return False


# ─────────────────────────────────────────
# Port comparison helper
# Handles ranges like 8000-9000
# ─────────────────────────────────────────
def _port_matches(p1, p2):

    if p1 in (None, "any") or p2 in (None, "any"):
        return True

    if str(p1) == str(p2):
        return True

    if "-" in str(p1) or "-" in str(p2):
        return True

    return False


# ─────────────────────────────────────────
# Rule Optimizer
# ─────────────────────────────────────────
class RuleOptimizer:


    def check_rule(self, new_rule: dict, existing_rules: list) -> dict:
        """
        Interactive mode:
        Evaluate a new rule against existing rules
        """

        issues = []
        suggestions = []

        new_src = new_rule.get("source_ip", "any")
        new_dst = new_rule.get("destination_ip", "any")
        new_port = new_rule.get("port")
        new_proto = new_rule.get("protocol", "any")

        # ─────────────────────────
        # Duplicate Detection
        # ─────────────────────────
        for rule in existing_rules:

            if (
                new_rule.get("intent") == rule.get("intent") and
                new_proto == rule.get("protocol") and
                str(new_port) == str(rule.get("port")) and
                new_src == rule.get("source_ip") and
                new_dst == rule.get("destination_ip") and
                new_rule.get("direction") == rule.get("direction")
            ):

                issues.append({
                    "type": "DUPLICATE",
                    "severity": "MEDIUM",
                    "description":
                        f"Exact duplicate of Rule {rule.get('policy_id')}: "
                        f"'{rule.get('policy_text')}'",
                    "suggestion":
                        "Remove this rule — it already exists"
                })

        # ─────────────────────────
        # Subnet Overlap Detection
        # ─────────────────────────
        for rule in existing_rules:

            if new_rule.get("intent") != rule.get("intent"):
                continue

            if new_proto != rule.get("protocol"):
                continue

            if not _port_matches(new_port, rule.get("port")):
                continue

            ex_src = rule.get("source_ip", "any")
            ex_dst = rule.get("destination_ip", "any")

            # source overlap
            if _subnet_contains(ex_src, new_src) and ex_src != new_src:

                issues.append({
                    "type": "SOURCE_SUBNET_OVERLAP",
                    "severity": "LOW",
                    "description":
                        f"Rule {rule.get('policy_id')} already covers "
                        f"subnet {ex_src} which includes {new_src}",
                    "suggestion":
                        "Your rule may be redundant — existing rule handles it"
                })

            # destination overlap
            if _subnet_contains(ex_dst, new_dst) and ex_dst != new_dst:

                issues.append({
                    "type": "DEST_SUBNET_OVERLAP",
                    "severity": "LOW",
                    "description":
                        f"Rule {rule.get('policy_id')} already covers "
                        f"destination subnet {ex_dst}",
                    "suggestion":
                        "Destination restriction may already be handled"
                })

        # ─────────────────────────
        # Overly Permissive Rule
        # ─────────────────────────
        if (
            new_rule.get("intent") == "allow"
            and new_src in ("any", "0.0.0.0/0")
            and new_port in (None, "any")
            and new_proto == "any"
        ):

            issues.append({
                "type": "OVERLY_PERMISSIVE",
                "severity": "HIGH",
                "description":
                    "Allow-all rule with no source, port, or protocol restriction",
                "suggestion":
                    "Add source IP restriction, port, or protocol to enforce least privilege"
            })

        elif (
            new_rule.get("intent") == "allow"
            and new_src in ("any", "0.0.0.0/0")
            and new_port in (None, "any")
        ):

            suggestions.append(
                "Consider restricting source IP to reduce exposure"
            )

        # ─────────────────────────
        # Public Admin Exposure
        # ─────────────────────────
        if (
            new_rule.get("intent") == "allow"
            and new_port in SENSITIVE_PORTS
            and new_src in ("any", "0.0.0.0/0")
        ):

            issues.append({
                "type": "PUBLIC_ADMIN_EXPOSURE",
                "severity": "HIGH",
                "description":
                    f"Sensitive service port {new_port} exposed publicly",
                "suggestion":
                    "Restrict source IP to trusted networks"
            })

        # ─────────────────────────
        # Final result
        # ─────────────────────────
        is_clean = len(issues) == 0

        return {
            "is_clean": is_clean,
            "issues": issues,
            "suggestions": suggestions,
            "issue_count": len(issues)
        }