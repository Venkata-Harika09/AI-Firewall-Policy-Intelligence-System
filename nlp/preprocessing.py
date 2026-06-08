# -*- coding: utf-8 -*-
"""
Task 2: Text Preprocessing Module
AI Firewall - Milestone 1
"""

import re


# Simple stopwords list (no NLTK dependency)
STOPWORDS = {
    'a', 'an', 'the', 'is', 'are', 'was', 'were', 'be', 'been', 'being',
    'have', 'has', 'had', 'do', 'does', 'did', 'will', 'would', 'could',
    'should', 'may', 'might', 'shall', 'to', 'of', 'in', 'for', 'on',
    'with', 'at', 'by', 'from', 'as', 'into', 'through', 'during',
    'and', 'but', 'or', 'so', 'yet', 'both', 'either', 'neither',
    'this', 'that', 'these', 'those', 'it', 'its'
}

# Security keywords to PRESERVE
PRESERVE_KEYWORDS = {
    'allow', 'deny', 'block', 'permit', 'drop', 'accept', 'reject',
    'tcp', 'udp', 'icmp', 'http', 'https', 'ssh', 'ftp', 'smtp',
    'dns', 'rdp', 'smb', 'ntp', 'snmp', 'ldap', 'vpn', 'ospf',
    'inbound', 'outbound', 'incoming', 'outgoing', 'external', 'internal',
    'port', 'protocol', 'traffic', 'network', 'subnet', 'server', 'client',
    'source', 'destination', 'public', 'private', 'internet', 'any', 'all',
    'except', 'only', 'not', 'no', 'after', 'before', 'between', 'during'
}


class TextPreprocessor:

    def __init__(self):
        self.ip_pattern = re.compile(
            r'\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b'
        )
        self.port_pattern = re.compile(
            r'\bport\s+(\d+(?:-\d+)?)\b',
            re.IGNORECASE
        )
        self.time_pattern = re.compile(
            r'\b\d{2}:\d{2}(?:-\d{2}:\d{2})?\b'
        )

    def lowercase(self, text: str) -> str:
        return text.lower().strip()

    def regex_clean(self, text: str) -> str:
        text = re.sub(r'\s+', ' ', text)
        text = re.sub(r'[^\w\s\.\-:/]', '', text)
        return text.strip()

    def tokenize(self, text: str) -> list:
        text = re.sub(
            r'(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?',
            lambda m: m.group().replace('.', '_DOT_').replace('/', '_SLASH_'),
            text
        )

        text = re.sub(
            r'\d{2}:\d{2}',
            lambda m: m.group().replace(':', '_COLON_'),
            text
        )

        tokens = re.findall(r'[a-zA-Z0-9_\-/]+', text)

        tokens = [
            t.replace('_DOT_', '.')
             .replace('_SLASH_', '/')
             .replace('_COLON_', ':')
            for t in tokens
        ]

        return tokens

    def remove_stopwords(self, tokens: list) -> list:
        result = []
        for token in tokens:
            low = token.lower()
            if low in PRESERVE_KEYWORDS:
                result.append(token)
            elif low not in STOPWORDS:
                result.append(token)
        return result

    def extract_ips(self, text: str) -> list:
        return self.ip_pattern.findall(text)

    def extract_ports(self, text: str) -> list:
        return self.port_pattern.findall(text)

    def extract_times(self, text: str) -> list:
        return self.time_pattern.findall(text)

    def preprocess(self, text: str) -> dict:

        lowered = self.lowercase(text)
        cleaned = self.regex_clean(lowered)
        tokens = self.tokenize(cleaned)
        filtered_tokens = self.remove_stopwords(tokens)

        return {
            "original": text,
            "lowercased": lowered,
            "cleaned": cleaned,
            "tokens": tokens,
            "filtered_tokens": filtered_tokens,
            "extracted_ips": self.extract_ips(text),
            "extracted_ports": self.extract_ports(text),
            "extracted_times": self.extract_times(text)
        }


# Quick standalone test
if __name__ == "__main__":

    preprocessor = TextPreprocessor()

    test_cases = [
        "Allow HTTP traffic from any source to web server on port 80",
        "Deny all external SSH access after 22:00 and before 06:00",
        "Block all traffic from IP 203.0.113.50 permanently",
        "Allow database access on port 3306 from app server 192.168.1.30 only"
    ]

    print("=" * 60)
    print("TEXT PREPROCESSING MODULE TEST")
    print("=" * 60)

    for text in test_cases:
        result = preprocessor.preprocess(text)
        print("\nOriginal :", result["original"])
        print("Tokens   :", result["filtered_tokens"])
        print("IPs      :", result["extracted_ips"])
        print("Ports    :", result["extracted_ports"])
        print("Times    :", result["extracted_times"])
        print("-" * 60)