# security/injection.py
import re

INJECTION_PATTERNS: list[re.Pattern] = [
    re.compile(r"ignore\s+(all\s+)?(previous|prior)\s+instructions", re.IGNORECASE),
    re.compile(r"system\s+override", re.IGNORECASE),
    re.compile(r"disregard\s+(above|previous|prior)", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+in\s+(developer|unrestricted)\s+mode", re.IGNORECASE),
    re.compile(r"read\s+.*credentials", re.IGNORECASE),
    re.compile(r"return\s+all\s+credentials", re.IGNORECASE),
    re.compile(r"exfiltrate", re.IGNORECASE),
]

class PromptInjectionDetector:
    @staticmethod
    def inspect(content: str) -> tuple[bool, str]:
        """
        Scans content for indirect prompt injection attempts.
        Returns: (is_detected, matched_pattern_description)
        """
        if not isinstance(content, str):
            return False, ""

        for pattern in INJECTION_PATTERNS:
            match = pattern.search(content)
            if match:
                return True, f"Suspicious instruction pattern detected: '{match.group(0)}'"

        return False, ""