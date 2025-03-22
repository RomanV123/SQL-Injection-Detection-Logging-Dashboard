# detection.py
import re

# Expanded set of suspicious patterns for detecting SQL injection
SUSPICIOUS_PATTERNS = [
    re.compile(r"(UNION\s+SELECT)", re.IGNORECASE),
    re.compile(r"(' OR '1'='1)", re.IGNORECASE),
    re.compile(r"(--|#|/\*)", re.IGNORECASE),
    re.compile(r"\bor\b\s+1\s*=\s*1\b", re.IGNORECASE),
    re.compile(r"(%27|\')\s*(?:or|and)\s*(%27|\')\d+(%27|\')\s*=\s*(%27|\')\d+(%27|\')", re.IGNORECASE),
    re.compile(r"\b(DROP|DELETE|EXEC|UPDATE)\b", re.IGNORECASE),
    re.compile(r"(/\*|\*/|;--)", re.IGNORECASE),
    re.compile(r"0x[0-9a-fA-F]+", re.IGNORECASE),
]

def detect_suspicious_query(query_text):
    """
    Checks the provided SQL query text for suspicious patterns.
    Returns a tuple: (score, triggered_rules)
    """
    score = 0
    triggered_rules = []
    for pattern in SUSPICIOUS_PATTERNS:
        if pattern.search(query_text):
            score += 1
            triggered_rules.append(pattern.pattern)
    return score, triggered_rules