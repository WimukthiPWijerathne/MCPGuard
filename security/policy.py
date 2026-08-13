from .models import Role


TOOL_PERMISSIONS = {
    "list_files": "file:list",
    "read_file": "file:read",
    "create_file": "file:create",
    "write_file": "file:write",
    "delete_file": "file:delete",
}


ROLE_PERMISSIONS = {
    Role.VIEWER: {
        "file:list",
        "file:read",
    },
    Role.DEVELOPER: {
        "file:list",
        "file:read",
        "file:create",
        "file:write",
    },
    Role.ADMIN: {
        "file:list",
        "file:read",
        "file:create",
        "file:write",
        "file:delete",
    },
}


def required_permission(tool_name: str) -> str:
    """
    Return the permission required to execute a tool.
    """
    try:
        return TOOL_PERMISSIONS[tool_name]
    except KeyError:
        raise ValueError(f"Unknown tool: {tool_name}")


def is_authorized(role: Role, tool_name: str) -> bool:
    """
    Check whether the user's role is allowed to execute a tool.
    """
    permission = required_permission(tool_name)

    return permission in ROLE_PERMISSIONS[role]