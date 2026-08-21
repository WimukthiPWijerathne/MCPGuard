import re


# These are deliberately simple V1 patterns.
# They are meant for controlled synthetic test data,
# not production-grade secret detection.

SECRET_PATTERNS = {
    "API_KEY": re.compile(
        r"((?:API_KEY|apikey|secret|token)\s*=\s*)([^\r\n]+)",
        re.IGNORECASE,
    ),
    "PASSWORD": re.compile(
        r"((?:DATABASE_PASSWORD|PASSWORD|passwd|pwd)\s*=\s*)([^\r\n]+)",
        re.IGNORECASE,
    ),
    "TOKEN": re.compile(
        r"(?i)(token\s*[:=]\s*)([A-Za-z0-9_\-\.]{8,})"
    ),
    "PRIVATE_KEY": re.compile(
        r"-----BEGIN (?:RSA )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA )?PRIVATE KEY-----",
        re.IGNORECASE,
    ),
}
class ResponseScanner:
    @staticmethod
    def scan(content: str) -> tuple[str, list[str]]:
        """
        Scans response text for secret patterns and replaces them with redaction markers.
        Returns: (sanitized_content, detected_types)
        """
        if not isinstance(content, str):
            return content, []

        detected: list[str] = []
        sanitized = content

        for secret_type, pattern in SECRET_PATTERNS.items():
            if pattern.search(sanitized):
                detected.append(secret_type)
                if secret_type in ["API_KEY", "PASSWORD"]:
                    sanitized = pattern.sub(r"\g<1>[REDACTED]", sanitized)
                else:
                    sanitized = pattern.sub("[REDACTED]", sanitized)

        return sanitized, detected

def detect_secrets(text: str) -> list[str]:
    """
    Return the names of secret types detected in the text.
    """

    findings: list[str] = []

    for name, pattern in SECRET_PATTERNS.items():
        if pattern.search(text):
            findings.append(name)

    return findings


def redact_secrets(text: str) -> tuple[str, list[str]]:
    """
    Replace detected secret values with [REDACTED].

    Returns:
        sanitized_text
        list of detected secret types
    """

    findings: list[str] = []

    sanitized = text

    for name, pattern in SECRET_PATTERNS.items():

        if pattern.search(sanitized):
            findings.append(name)

            if name == "PRIVATE_KEY":
                sanitized = pattern.sub(
                    "[REDACTED_PRIVATE_KEY]",
                    sanitized,
                )
            else:
                sanitized = pattern.sub(
                    r"\1[REDACTED]",
                    sanitized,
                )

    return sanitized, findings