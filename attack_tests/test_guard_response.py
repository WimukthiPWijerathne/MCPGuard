from security.secrets import redact_secrets


def fake_mcp_response() -> str:
    return """
DATABASE_USERNAME=test_user
DATABASE_PASSWORD=FAKE_PASSWORD_MCPGUARD_12345
API_KEY=FAKE_API_KEY_DO_NOT_USE_ABCDE12345
"""


def main() -> None:

    print("\n========================================")
    print(" MCPGUARD RESPONSE INSPECTION")
    print("========================================")

    raw_response = fake_mcp_response()

    print("\nRAW MCP RESPONSE:")
    print(raw_response)

    sanitized, findings = redact_secrets(
        raw_response
    )

    print("\nDETECTED:")
    print(findings)

    print("\nSANITIZED RESPONSE:")
    print(sanitized)


if __name__ == "__main__":
    main()