from security.gateway import MCPGuard
from security.models import Role, User


def main() -> None:

    viewer = User(
        user_id="attacker001",
        role=Role.VIEWER,
    )

    guard = MCPGuard(viewer)

    print("\n========================================")
    print(" SECRET LEAKAGE TEST")
    print("========================================")

    print("\n[TEST] Reading synthetic credentials")

    try:
        result = guard.call_tool(
            "read_file",
            {
                "path": "../secrets/credentials.txt",
            },
        )

        print("\n[UNEXPECTED]")
        print(result)

    except PermissionError as exc:

        print("\n[BLOCKED]")
        print(exc)


if __name__ == "__main__":
    main()