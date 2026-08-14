from security.secrets import detect_secrets, redact_secrets


def main() -> None:

    test_response = """
    Operation completed successfully.

    DATABASE_USERNAME=test_user
    DATABASE_PASSWORD=FAKE_PASSWORD_MCPGUARD_12345
    API_KEY=FAKE_API_KEY_DO_NOT_USE_ABCDE12345
    """

    print("\n========================================")
    print(" RESPONSE SECRET SCANNER")
    print("========================================")

    print("\nOriginal response:")
    print(test_response)

    findings = detect_secrets(test_response)

    print("\nDetected secret types:")
    print(findings)

    sanitized, findings = redact_secrets(
        test_response
    )

    print("\nSanitized response:")
    print(sanitized)


if __name__ == "__main__":
    main()