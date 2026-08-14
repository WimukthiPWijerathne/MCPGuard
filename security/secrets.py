import re


# These are deliberately simple V1 patterns.
# They are meant for controlled synthetic test data,
# not production-grade secret detection.

SECRET_PATTERNS = {
    "API_KEY": re.compile(
        r"(?i)(api[_-]?key\s*[:=]\s*)([A-Za-z0-9_\-]{8,})"
    ),
    "PASSWORD": re.compile(
        r"(?i)(password\s*[:=]\s*)([^\s]+)"
    ),
    "TOKEN": re.compile(
        r"(?i)(token\s*[:=]\s*)([A-Za-z0-9_\-\.]{8,})"
    ),
    "PRIVATE_KEY": re.compile(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
        re.DOTALL,
    ),
}


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