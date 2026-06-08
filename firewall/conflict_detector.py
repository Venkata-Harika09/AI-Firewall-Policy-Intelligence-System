"""
Task 1: Conflict Detection Logic
AI Firewall – Milestone 2

Detects:
• Rule shadowing
• Redundant rules
• Contradictions
• Priority misordering
"""

import ipaddress


# -----------------------------------------
# CONSTANTS
# -----------------------------------------

ANY_VALUES = ("any", "0.0.0.0/0", None, "")


# -----------------------------------------
# IP OVERLAP CHECK
# -----------------------------------------

def _ip_overlaps(ip1: str, ip2: str) -> bool:
    try:

        if ip1 in ANY_VALUES or ip2 in ANY_VALUES:
            return True

        net1 = ipaddress.ip_network(ip1, strict=False)
        net2 = ipaddress.ip_network(ip2, strict=False)

        return net1.overlaps(net2)

    except Exception:
        return ip1 == ip2


# -----------------------------------------
# PORT OVERLAP CHECK
# -----------------------------------------

def _port_overlaps(p1, p2) -> bool:

    if p1 in (None, "any") or p2 in (None, "any"):
        return True

    try:

        def to_range(p):

            if isinstance(p, int):
                return (p, p)

            if isinstance(p, str) and "-" in p:
                a, b = p.split("-")
                return (int(a), int(b))

            return (int(p), int(p))

        r1 = to_range(p1)
        r2 = to_range(p2)

        return r1[0] <= r2[1] and r2[0] <= r1[1]

    except Exception:
        return str(p1) == str(p2)


# -----------------------------------------
# RULE MATCH CHECK
# -----------------------------------------

def _rules_match(r1: dict, r2: dict) -> bool:

    proto1 = (r1.get("protocol") or "any").lower()
    proto2 = (r2.get("protocol") or "any").lower()

    proto_match = (
        proto1 == "any"
        or proto2 == "any"
        or proto1 == proto2
    )

    port_match = _port_overlaps(
        r1.get("port"), r2.get("port")
    )

    src_match = _ip_overlaps(
        r1.get("source_ip", "any"),
        r2.get("source_ip", "any")
    )

    dst_match = _ip_overlaps(
        r1.get("destination_ip", "any"),
        r2.get("destination_ip", "any")
    )

    dir1 = r1.get("direction", "any")
    dir2 = r2.get("direction", "any")

    dir_match = (
        dir1 == dir2
        or "any" in (dir1, dir2)
    )

    return proto_match and port_match and src_match and dst_match and dir_match


# -----------------------------------------
# CONFLICT DETECTOR CLASS
# -----------------------------------------

class ConflictDetector:

    def check_rule(self, new_rule: dict, existing_rules: list) -> dict:
        """
        Interactive rule checking.
        Compare a new rule with existing rules.
        """

        shadowing = []
        contradictions = []
        redundancy = []
        misordering = []

        new_prio = int(new_rule.get("priority", 9999))

        for rule in existing_rules:

            ex_prio = int(rule.get("priority", 9999))

            # ---------------------------------
            # REDUNDANCY CHECK
            # ---------------------------------

            if (
                new_rule.get("intent") == rule.get("intent")
                and new_rule.get("protocol") == rule.get("protocol")
                and str(new_rule.get("port")) == str(rule.get("port"))
                and new_rule.get("source_ip") == rule.get("source_ip")
                and new_rule.get("destination_ip") == rule.get("destination_ip")
            ):

                redundancy.append({

                    "type": "REDUNDANCY",
                    "severity": "MEDIUM",
                    "rule_id": rule.get("policy_id"),
                    "rule_text": rule.get("policy_text"),

                    "description":
                        f"Your rule is identical to existing Rule {rule.get('policy_id')}",

                    "resolution":
                        "Remove duplicate rule"

                })

                continue

            if not _rules_match(new_rule, rule):
                continue

            # ---------------------------------
            # CONTRADICTION
            # ---------------------------------

            if new_rule.get("intent") != rule.get("intent"):

                contradictions.append({

                    "type": "CONTRADICTION",
                    "severity": "CRITICAL",
                    "rule_id": rule.get("policy_id"),
                    "rule_text": rule.get("policy_text"),

                    "description":
                        f"Your rule ({new_rule.get('intent').upper()}) "
                        f"contradicts Rule {rule.get('policy_id')} "
                        f"({rule.get('intent').upper()})",

                    "resolution":
                        "Review rule priorities and decide which rule should apply"

                })

            # ---------------------------------
            # SHADOWING
            # ---------------------------------

            elif ex_prio < new_prio:

                shadowing.append({

                    "type": "SHADOWING",
                    "severity": "HIGH",
                    "rule_id": rule.get("policy_id"),
                    "rule_text": rule.get("policy_text"),

                    "description":
                        f"Existing Rule {rule.get('policy_id')} "
                        f"(priority {ex_prio}) already covers this rule",

                    "resolution":
                        "Assign higher priority or remove redundant rule"

                })

        # ---------------------------------
        # PRIORITY MISORDERING
        # ---------------------------------

        is_deny_all = (

            new_rule.get("intent") == "deny"
            and new_rule.get("source_ip") in ANY_VALUES
            and new_rule.get("destination_ip") in ANY_VALUES
            and new_rule.get("port") in (None, "any")

        )

        if is_deny_all:

            for rule in existing_rules:

                if (

                    rule.get("intent") == "allow"
                    and int(rule.get("priority", 9999)) > new_prio

                ):

                    misordering.append({

                        "type": "PRIORITY_MISORDERING",
                        "severity": "HIGH",
                        "rule_id": rule.get("policy_id"),
                        "rule_text": rule.get("policy_text"),

                        "description":
                            f"DENY-ALL rule will block existing "
                            f"ALLOW Rule {rule.get('policy_id')}",

                        "resolution":
                            "Place DENY-ALL after all specific ALLOW rules"

                    })

        # ---------------------------------
        # FINAL SUMMARY
        # ---------------------------------

        all_conflicts = (
            shadowing
            + contradictions
            + redundancy
            + misordering
        )

        critical = sum(
            1 for c in all_conflicts
            if c["severity"] == "CRITICAL"
        )

        high = sum(
            1 for c in all_conflicts
            if c["severity"] == "HIGH"
        )

        medium = sum(
            1 for c in all_conflicts
            if c["severity"] == "MEDIUM"
        )

        return {

            "total": len(all_conflicts),

            "critical": critical,
            "high": high,
            "medium": medium,

            "shadowing": shadowing,
            "contradictions": contradictions,
            "redundancy": redundancy,
            "misordering": misordering,

            "all_conflicts": all_conflicts

        }