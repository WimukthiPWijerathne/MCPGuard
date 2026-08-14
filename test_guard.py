from security.gateway import MCPGuard
from security.models import Role, User


def run_test(name: str, function) -> None:
    print(f"\n[TEST] {name}")

    try:
        result = function()
        print("[PASS]")
        print(result)

    except Exception as exc:
        print("[BLOCKED / ERROR]")
        print(exc)


def main() -> None:

    viewer = User(
        user_id="user001",
        role=Role.VIEWER,
    )

    developer = User(
        user_id="user002",
        role=Role.DEVELOPER,
    )

    admin = User(
        user_id="admin001",
        role=Role.ADMIN,
    )

    viewer_guard = MCPGuard(viewer)
    developer_guard = MCPGuard(developer)
    admin_guard = MCPGuard(admin)

    print("\n========================================")
    print(" MCPGUARD SECURITY TESTS")
    print("========================================")

    # ---------------------------------------------------------
    # 1. Normal public read
    # ---------------------------------------------------------

    run_test(
        "Viewer reads public file",
        lambda: viewer_guard.call_tool(
            "read_file",
            {
                "path": "notes.txt"
            },
        ),
    )

    # ---------------------------------------------------------
    # 2. Viewer unauthorized delete
    # ---------------------------------------------------------

    run_test(
        "Viewer attempts delete",
        lambda: viewer_guard.call_tool(
            "delete_file",
            {
                "path": "notes.txt"
            },
        ),
    )

    # ---------------------------------------------------------
    # 3. Developer creates file
    # ---------------------------------------------------------

    run_test(
        "Developer creates file",
        lambda: developer_guard.call_tool(
            "create_file",
            {
                "path": "mcpguard_test.txt",
                "content": "Created through MCPGuard",
            },
        ),
    )

    # ---------------------------------------------------------
    # 4. Developer unauthorized delete
    # ---------------------------------------------------------

    run_test(
        "Developer attempts delete",
        lambda: developer_guard.call_tool(
            "delete_file",
            {
                "path": "mcpguard_test.txt"
            },
        ),
    )

    # ---------------------------------------------------------
    # 5. Admin delete
    # ---------------------------------------------------------

    admin_guard.call_tool(
        "create_file",
        {
            "path": "admin_test.txt",
            "content": "Temporary admin test file",
        },
    )

    run_test(
        "Admin deletes file",
        lambda: admin_guard.call_tool(
            "delete_file",
            {
                "path": "admin_test.txt"
            },
        ),
    )

    # ---------------------------------------------------------
    # 6. Path traversal
    # ---------------------------------------------------------

    run_test(
        "Path traversal attack",
        lambda: viewer_guard.call_tool(
            "read_file",
            {
                "path": "../secrets/credentials.txt"
            },
        ),
    )

    # ---------------------------------------------------------
    # 7. Direct secret access
    # ---------------------------------------------------------

    run_test(
        "Direct secret access",
        lambda: viewer_guard.call_tool(
            "read_file",
            {
                "path": "../secrets/credentials.txt"
            },
        ),
    )

    # ---------------------------------------------------------
    # 8. Private file access
    # ---------------------------------------------------------

    run_test(
        "Developer reads private file",
        lambda: developer_guard.call_tool(
            "read_file",
            {
                "path": "../private/project.txt"
            },
        ),
    )


if __name__ == "__main__":
    main()