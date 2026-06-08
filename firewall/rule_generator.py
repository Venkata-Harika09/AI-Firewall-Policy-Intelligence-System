"""
Task 5: Rule Generation Engine
AI Firewall - Milestone 1 (Polished Version)

Maps:
Intent + Extracted Entities -> iptables command

Includes:
- Protocol inference
- Zone -> IP mapping
- Port range handling
- Validation layer
- Risk warnings
- Malicious IP detection
- Batch processing
"""

import os
import re
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from nlp.entity_extractor import EntityExtractor


# ─────────────────────────────────────────────
# MAPPINGS
# ─────────────────────────────────────────────

INTENT_TO_IPTABLES = {
    'allow':  'ACCEPT',
    'permit': 'ACCEPT',
    'accept': 'ACCEPT',
    'deny':   'DROP',
    'block':  'DROP',
    'drop':   'DROP',
    'reject': 'REJECT'
}

DIRECTION_TO_CHAIN = {
    'inbound':  'INPUT',
    'outbound': 'OUTPUT',
    'forward':  'FORWARD'
}

SENSITIVE_PORTS = {
    22:    "SSH",
    3306:  "MySQL",
    3389:  "RDP",
    5432:  "PostgreSQL",
    27017: "MongoDB",
    2375:  "Docker API"
}

PORT_TO_PROTOCOL = {
    22: 'tcp', 80: 'tcp', 443: 'tcp', 23: 'tcp', 21: 'tcp',
    25: 'tcp', 3306: 'tcp', 3389: 'tcp', 5432: 'tcp', 27017: 'tcp',
    6379: 'tcp', 9200: 'tcp', 9092: 'tcp', 2375: 'tcp', 6443: 'tcp',
    8080: 'tcp', 8443: 'tcp', 3000: 'tcp', 9090: 'tcp', 8888: 'tcp',
    53:  'udp', 123: 'udp', 161: 'udp', 514: 'udp', 1812: 'udp',
    69:  'udp',
}

ZONE_TO_IP = {
    'internal':  '10.0.0.0/8',
    'corporate': '192.168.0.0/16',
    'vpn':       '172.16.0.0/12',
    'dmz':       '192.168.99.0/24',
}


# ─────────────────────────────────────────────
# RULE GENERATOR
# ─────────────────────────────────────────────

class RuleGenerator:

    def __init__(self):
        self.extractor = EntityExtractor()

    # ─────────────────────────────────────────
    # Normalize IP — used ONLY in validation
    # "any" → "0.0.0.0/0" for clean comparisons
    # ─────────────────────────────────────────
    def _normalize_ip(self, ip):
        if ip in (None, "any"):
            return "0.0.0.0/0"
        return ip

    # ─────────────────────────────────────────
    # Resolve protocol from port (inference)
    # ─────────────────────────────────────────
    def _resolve_protocol(self, protocol, port):
        if protocol and protocol != "any":
            return protocol
        if isinstance(port, int) and port in PORT_TO_PROTOCOL:
            return PORT_TO_PROTOCOL[port]
        return None

    # ─────────────────────────────────────────
    # Resolve source IP (zone keyword mapping)
    # ─────────────────────────────────────────
    def _resolve_source_ip(self, source_ip, policy_text):
        if source_ip and source_ip != "any":
            return source_ip
        text_lower = policy_text.lower()
        for zone, ip_range in ZONE_TO_IP.items():
            if f"from {zone}" in text_lower:
                return ip_range
        return "any"

    # ─────────────────────────────────────────
    # Resolve port ("port range X-Y" fix)
    # ─────────────────────────────────────────
    def _resolve_port(self, port, policy_text):
        if port is not None:
            return port
        m = re.search(r'port\s+range\s+(\d+)-(\d+)', policy_text, re.IGNORECASE)
        if m:
            return f"{m.group(1)}-{m.group(2)}"
        return None

    # ─────────────────────────────────────────
    # Build iptables rule
    # FIXED: only add -s / -d when NOT "any"
    # ─────────────────────────────────────────
    def _build_iptables(self, intent, entities, policy_text):

        parts = ["iptables"]

        chain = DIRECTION_TO_CHAIN.get(
            entities.get("direction", "inbound"), "INPUT"
        )
        parts.extend(["-A", chain])

        port      = self._resolve_port(entities.get("port"), policy_text)
        protocol  = self._resolve_protocol(entities.get("protocol"), port)
        source_ip = self._resolve_source_ip(entities.get("source_ip"), policy_text)
        dest_ip   = entities.get("destination_ip")

        if protocol:
            parts.extend(["-p", protocol])

        # Only add -s if source is a real IP/subnet (not "any")
        if source_ip and source_ip != "any":
            parts.extend(["-s", source_ip])

        # Only add -d if destination is a real IP/subnet (not "any")
        if dest_ip and dest_ip != "any":
            parts.extend(["-d", dest_ip])

        if port:
            if isinstance(port, int):
                parts.extend(["--dport", str(port)])
            elif isinstance(port, str) and "-" in port:
                parts.extend(["--dport", port.replace("-", ":")])

        action = INTENT_TO_IPTABLES.get(intent.lower(), "DROP")
        parts.extend(["-j", action])

        return " ".join(parts)

    # ─────────────────────────────────────────
    # Validation Layer
    # Uses _normalize_ip for clean comparisons
    # ─────────────────────────────────────────
    def _validate_rule(self, intent, entities, policy_text):

        warnings = []
        issues   = []

        # Normalize for comparison only
        source_ip = self._normalize_ip(
            self._resolve_source_ip(entities.get("source_ip"), policy_text)
        )
        dest_ip = self._normalize_ip(entities.get("destination_ip"))
        port    = self._resolve_port(entities.get("port"), policy_text)

        # ANY-to-ANY detection
        if source_ip == "0.0.0.0/0" and dest_ip == "0.0.0.0/0":
            warnings.append("ANY-to-ANY rule detected")

        # Sensitive port exposed publicly
        if isinstance(port, int) and port in SENSITIVE_PORTS:
            if source_ip == "0.0.0.0/0" and intent.lower() == "allow":
                warnings.append(
                    f"{SENSITIVE_PORTS[port]} exposed to public network"
                )

        # Malicious IP allowed
        if entities.get("is_malicious_ip") and intent.lower() == "allow":
            issues.append(
                "CRITICAL: Allowing traffic from known malicious IP"
            )

        return {
            "valid":    len(issues) == 0,
            "warnings": warnings,
            "issues":   issues
        }

    # ─────────────────────────────────────────
    # Public Generate Function
    # ─────────────────────────────────────────
    def generate(self, policy_text, intent):

        entities   = self.extractor.extract(policy_text)
        rule       = self._build_iptables(intent, entities, policy_text)
        validation = self._validate_rule(intent, entities, policy_text)

        return {
            "input_policy":       policy_text,
            "intent":             intent,
            "extracted_entities": entities,
            "iptables_rule":      rule,
            "validation":         validation
        }

    # ─────────────────────────────────────────
    # Batch Generation
    # ─────────────────────────────────────────
    def generate_batch(self, policies):

        results = []
        for policy in policies:
            result = self.generate(
                policy["policy_text"],
                policy["intent"]
            )
            result["policy_id"] = policy.get("policy_id")
            results.append(result)

        return results


# ─────────────────────────────────────────────
# Quick Test
# ─────────────────────────────────────────────

if __name__ == "__main__":

    generator = RuleGenerator()

    tests = [
        ("Allow SSH from any",                          "allow"),
        ("Block HTTP from 192.168.1.10",                "deny"),
        ("Allow HTTPS outbound to internet",            "allow"),
        ("Deny MongoDB from 10.0.0.5",                  "deny"),
        ("Allow traffic from 198.51.100.25",            "allow"),
        ("Block all incoming from external on port 22", "deny"),
        ("Allow port range 8000-9000 from internal",    "allow"),
    ]

    print("=" * 70)
    print("RULE GENERATION ENGINE - FINAL TEST")
    print("=" * 70)

    for policy_text, intent in tests:
        result = generator.generate(policy_text, intent)
        print(f"\nPolicy     : {result['input_policy']}")
        print(f"iptables   : {result['iptables_rule']}")
        v = result["validation"]
        if v["warnings"]: print(f"Warnings   : {v['warnings']}")
        if v["issues"]:   print(f"Issues     : {v['issues']}")
        if not v["warnings"] and not v["issues"]:
            print(f"Validation : Clean")