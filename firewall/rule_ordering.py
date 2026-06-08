"""
Task 2: Rule Ordering Engine
AI Firewall - Milestone 2

Purpose:
Reorder firewall rules for optimal security.

Implements:
- Specific rules first
- Allow rules before deny
- Sensitive services prioritized
- Deny-all rules always last
"""

import ipaddress


# Sensitive ports that should be handled carefully
SENSITIVE_PORTS = {22, 3306, 3389, 5432, 27017, 2375, 9200, 6443}


# ─────────────────────────────────────────
# Detect if rule is DENY ALL
# ─────────────────────────────────────────
def _is_deny_all(rule: dict) -> bool:

    return (
        rule.get("intent") == "deny"
        and rule.get("source_ip") in ("any", "0.0.0.0/0", None)
        and rule.get("destination_ip") in ("any", "0.0.0.0/0", None)
        and rule.get("port") in (None, "any")
    )


# ─────────────────────────────────────────
# Detect IP specificity
# /32 most specific
# /24 medium
# /8 broad
# ─────────────────────────────────────────
def _is_specific_ip(ip: str) -> bool:

    if ip in (None, "any", "0.0.0.0/0", ""):
        return False

    try:
        net = ipaddress.ip_network(ip, strict=False)

        # highly specific subnet
        if net.prefixlen >= 24:
            return True

        return False

    except Exception:
        # single IP without subnet
        return True


# ─────────────────────────────────────────
# Rule Specificity Score
# Higher score → rule placed earlier
# ─────────────────────────────────────────
def specificity_score(rule: dict) -> int:

    score = 0

    # Source IP specificity
    if _is_specific_ip(rule.get("source_ip")):
        score += 40

    # Destination IP specificity
    if _is_specific_ip(rule.get("destination_ip")):
        score += 30

    # Port specificity
    port = rule.get("port")

    if port not in (None, "any", ""):

        if isinstance(port, int):
            score += 20

            # Sensitive services prioritized
            if port in SENSITIVE_PORTS:
                score += 10

        elif isinstance(port, str) and "-" in port:
            # Port range is less specific
            score += 10

    # Protocol specificity
    proto = rule.get("protocol")

    if proto not in (None, "any"):
        score += 10

    # Allow rules slightly preferred
    if rule.get("intent") == "allow":
        score += 5

    return score


# ─────────────────────────────────────────
# Rule Ordering Engine
# ─────────────────────────────────────────
class RuleOrderingEngine:


    # ─────────────────────────────────────
    # Suggest where new rule should go
    # (Interactive mode)
    # ─────────────────────────────────────
    def suggest_priority(self, new_rule: dict, existing_rules: list) -> dict:

        new_score = specificity_score(new_rule)

        sorted_existing = sorted(
            existing_rules,
            key=lambda r: (
                _is_deny_all(r),                # deny-all last
                -specificity_score(r),          # higher specificity first
                int(r.get("priority", 999))
            )
        )

        suggested_pos = len(sorted_existing) + 1

        for i, rule in enumerate(sorted_existing, start=1):

            if new_score >= specificity_score(rule):
                suggested_pos = i
                break

        before = (
            sorted_existing[suggested_pos - 2]
            if suggested_pos > 1 else None
        )

        after = (
            sorted_existing[suggested_pos - 1]
            if suggested_pos <= len(sorted_existing) else None
        )

        # rule category
        if new_rule.get("intent") == "allow" and new_score >= 60:
            category = "Specific ALLOW rule — place near top"

        elif new_rule.get("intent") == "allow":
            category = "General ALLOW rule — place mid ruleset"

        elif new_score >= 40:
            category = "Specific DENY rule — place after allow rules"

        else:
            category = "General DENY rule — place near bottom"

        return {
            "new_rule_score": new_score,
            "suggested_priority": suggested_pos,
            "category": category,
            "before_rule": before.get("policy_text") if before else "TOP OF RULESET",
            "after_rule": after.get("policy_text") if after else "END OF RULESET",
            "total_rules": len(existing_rules)
        }


    # ─────────────────────────────────────
    # Batch sorting (dataset optimization)
    # ─────────────────────────────────────
    def sort_rules(self, rules: list) -> list:

        ordered = sorted(
            rules,
            key=lambda r: (
                _is_deny_all(r),               # deny-all always last
                -specificity_score(r),         # most specific first
                int(r.get("priority", 999))
            )
        )

        # Reassign priorities
        for i, rule in enumerate(ordered):
            rule["priority"] = i + 1

        return ordered