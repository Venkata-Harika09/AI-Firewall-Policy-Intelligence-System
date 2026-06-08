"""
Task 4: Entity Extraction Module
AI Firewall - Milestone 1 (Final Version)

Extracts:
- protocol
- port
- direction
- source_ip
- destination_ip
- time_constraint
- exception_logic
- malicious IP flag

Enterprise-ready + Milestone 3 compatible
"""

import re


# ─────────────────────────────────────────────
# PROTOCOL MAP
# ─────────────────────────────────────────────
PROTOCOL_MAP = {
    'tcp': 'tcp',
    'udp': 'udp',
    'icmp': 'icmp',
    'ospf': 'ospf',

    # Application protocols
    'http': 'tcp',
    'https': 'tcp',
    'ssh': 'tcp',
    'ftp': 'tcp',
    'smtp': 'tcp',
    'dns': 'udp',
    'rdp': 'tcp',
    'smb': 'tcp',
    'ntp': 'udp',
    'snmp': 'udp',
    'ldap': 'tcp',
    'imap': 'tcp',
    'pop3': 'tcp',
    'telnet': 'tcp',
    'mysql': 'tcp',
    'postgres': 'tcp',
    'mongodb': 'tcp',
    'redis': 'tcp',
    'kafka': 'tcp',
    'elasticsearch': 'tcp',
    'grpc': 'tcp',
    'kerberos': 'tcp',

    # Added: DevOps / Cloud / Monitoring
    'kubernetes': 'tcp',
    'prometheus': 'tcp',
    'jenkins': 'tcp',
    'grafana': 'tcp',
    'docker': 'tcp',
    'jupyter': 'tcp',
    'radius': 'udp',
    'tftp': 'udp',
}


# ─────────────────────────────────────────────
# SERVICE to PORT MAP (Extended for Milestone 3)
# ─────────────────────────────────────────────
SERVICE_PORT_MAP = {
    # Core services
    'http': 80,
    'https': 443,
    'ssh': 22,
    'ftp': 21,
    'smtp': 25,
    'dns': 53,
    'rdp': 3389,
    'smb': 445,
    'ntp': 123,
    'snmp': 161,
    'ldap': 389,
    'telnet': 23,

    # Databases
    'mysql': 3306,
    'postgres': 5432,
    'mongodb': 27017,
    'redis': 6379,

    # Enterprise infra
    'kafka': 9092,
    'elasticsearch': 9200,
    'grpc': 50051,
    'kerberos': 88,
    'syslog': 514,

    # DevOps / Cloud / Monitoring
    'tftp': 69,
    'radius': 1812,
    'prometheus': 9090,
    'jenkins': 8080,
    'grafana': 3000,
    'kubernetes': 6443,
    'docker': 2375,
    'jupyter': 8888,
}


# ─────────────────────────────────────────────
# DIRECTION KEYWORDS
# ─────────────────────────────────────────────
INBOUND_KEYWORDS = [
    'inbound', 'incoming', 'ingress',
    'from internet', 'from public',
    'from external', 'from outside'
]

OUTBOUND_KEYWORDS = [
    'outbound', 'outgoing', 'egress',
    'to internet', 'to public',
    'to external', 'to outside'
]


# ─────────────────────────────────────────────
# Sample malicious IPs (Phase 3 integration ready)
# ─────────────────────────────────────────────
MALICIOUS_IPS = {
    '198.51.100.25',
    '203.0.113.50',
    '45.33.32.156'
}


# ─────────────────────────────────────────────
# ENTITY EXTRACTOR
# ─────────────────────────────────────────────
class EntityExtractor:

    def __init__(self):
        self.ip_pattern = re.compile(
            r'\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b'
        )
        self.port_pattern = re.compile(
            r'\bport\s+(\d+(?:-\d+)?)\b',
            re.IGNORECASE
        )
        self.time_pattern = re.compile(
            r'\b(\d{2}:\d{2})\b'
        )

    # ─────────────────────────────────────────
    # Protocol
    # ─────────────────────────────────────────
    def extract_protocol(self, text: str) -> str:
        text_lower = text.lower()
        for keyword, proto in PROTOCOL_MAP.items():
            if re.search(r'\b' + keyword + r'\b', text_lower):
                return proto
        return "any"

    # ─────────────────────────────────────────
    # Port
    # ─────────────────────────────────────────
    def extract_port(self, text: str):
        # Explicit port number
        match = self.port_pattern.search(text)
        if match:
            value = match.group(1)
            if '-' in value:
                return value  # keep range as string
            return int(value)

        # Infer from service name
        text_lower = text.lower()
        for service, port in SERVICE_PORT_MAP.items():
            if re.search(r'\b' + service + r'\b', text_lower):
                return port

        return None

    # ─────────────────────────────────────────
    # Direction
    # ─────────────────────────────────────────
    def extract_direction(self, text: str) -> str:
        text_lower = text.lower()

        inbound_score  = sum(1 for kw in INBOUND_KEYWORDS  if kw in text_lower)
        outbound_score = sum(1 for kw in OUTBOUND_KEYWORDS if kw in text_lower)

        if outbound_score > inbound_score:
            return "outbound"

        return "inbound"  # default

    # ─────────────────────────────────────────
    # IPs
    # ─────────────────────────────────────────
    def extract_ips(self, text: str):

        all_ips    = self.ip_pattern.findall(text)
        text_lower = text.lower()

        source_ip      = "any"
        destination_ip = "any"

        # Detect "from X.X.X.X"
        src_match = re.search(
            r'\bfrom\s+((?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?)',
            text, re.IGNORECASE
        )
        if src_match:
            source_ip = src_match.group(1)

        # Detect "to X.X.X.X"
        dst_match = re.search(
            r'\bto\s+((?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?)',
            text, re.IGNORECASE
        )
        if dst_match:
            destination_ip = dst_match.group(1)

        # Internet keywords map to global range
        if any(kw in text_lower for kw in INBOUND_KEYWORDS):
            source_ip = "0.0.0.0/0"

        if any(kw in text_lower for kw in OUTBOUND_KEYWORDS):
            destination_ip = "0.0.0.0/0"

        # Malicious IP detection
        is_malicious = any(ip.split('/')[0] in MALICIOUS_IPS for ip in all_ips)

        return source_ip, destination_ip, all_ips, is_malicious

    # ─────────────────────────────────────────
    # Time Constraint
    # ─────────────────────────────────────────
    def extract_time(self, text: str):
        times = self.time_pattern.findall(text)

        if len(times) >= 2:
            return f"{times[0]}-{times[1]}"

        if len(times) == 1:
            return times[0]

        t = text.lower()
        if "weekend"            in t: return "weekend"
        if "off-peak"           in t: return "off-peak"
        if "maintenance window" in t: return "maintenance window"

        return None

    # ─────────────────────────────────────────
    # Exception Logic
    # ─────────────────────────────────────────
    def extract_exception(self, text: str):
        match = re.search(r'except\s+(.+)', text, re.IGNORECASE)
        if match:
            return match.group(1).strip()
        return None

    # ─────────────────────────────────────────
    # Full Extraction
    # ─────────────────────────────────────────
    def extract(self, text: str):

        source_ip, destination_ip, all_ips, is_malicious = self.extract_ips(text)

        return {
            "policy_text"    : text,
            "protocol"       : self.extract_protocol(text),
            "port"           : self.extract_port(text),
            "direction"      : self.extract_direction(text),
            "source_ip"      : source_ip,
            "destination_ip" : destination_ip,
            "all_ips"        : all_ips,
            "is_malicious_ip": is_malicious,
            "time_constraint": self.extract_time(text),
            "exception_logic": self.extract_exception(text)
        }


# ─────────────────────────────────────────
# Quick Test
# ─────────────────────────────────────────
if __name__ == "__main__":

    extractor = EntityExtractor()

    tests = [
        "Allow SSH from any",
        "Block HTTP from 192.168.1.10",
        "Allow Kubernetes API from internet on port 6443",
        "Deny MongoDB from 10.0.0.5 except admin subnet",
        "Allow Prometheus on port 9090 during maintenance window",
        "Block traffic from 198.51.100.25"
    ]

    print("=" * 70)
    print("FINAL ENTITY EXTRACTION MODULE")
    print("=" * 70)

    for t in tests:
        print("\nPolicy:", t)
        print(extractor.extract(t))