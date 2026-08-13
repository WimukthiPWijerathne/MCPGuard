from pathlib import Path

from mcp.server import MCPServer


# ---------------------------------------------------------
# MCP SERVER
# ---------------------------------------------------------

mcp = MCPServer("mcpguard-vulnerable-filesystem")


# ---------------------------------------------------------
# LAB DIRECTORIES
# ---------------------------------------------------------

# server.py:
# mcpguard/
#   mcp_servers/
#     vulnerable_filesystem/
#       server.py
#
# parents[2] therefore points to mcpguard/

PROJECT_ROOT = Path(__file__).resolve().parents[2]

LAB_ROOT = (PROJECT_ROOT / "sandbox").resolve()

WORKSPACE_ROOT = (LAB_ROOT / "public").resolve()


def resolve_lab_path(user_path: str) -> Path:
    """
    Resolve a path relative to the public workspace.

    IMPORTANT:
    This intentionally allows traversal from public/ into
    private/ and secrets/, because this is our vulnerable
    MCP server.

    It still prevents access outside the MCPGuard sandbox
    so that our security experiments cannot touch the
    real host filesystem.
    """

    target = (WORKSPACE_ROOT / user_path).resolve()

    # Hard safety boundary for the research environment.
    if not target.is_relative_to(LAB_ROOT):
        raise ValueError(
            "Path escaped the MCPGuard laboratory sandbox."
        )

    return target


# ---------------------------------------------------------
# MCP TOOLS
# ---------------------------------------------------------

@mcp.tool()
def list_files() -> list[str]:
    """
    List files available in the public workspace.
    """

    files = []

    for file_path in WORKSPACE_ROOT.rglob("*"):
        if file_path.is_file():
            relative_path = file_path.relative_to(WORKSPACE_ROOT)

            files.append(
                str(relative_path).replace("\\", "/")
            )

    return sorted(files)


@mcp.tool()
def read_file(path: str) -> str:
    """
    Read a text file.

    Args:
        path: File path relative to the public workspace.
    """

    target = resolve_lab_path(path)

    if not target.exists():
        raise ValueError(f"File does not exist: {path}")

    if not target.is_file():
        raise ValueError(f"Path is not a file: {path}")

    return target.read_text(
        encoding="utf-8",
        errors="replace",
    )


@mcp.tool()
def create_file(path: str, content: str) -> str:
    """
    Create a new text file.

    Args:
        path: File path relative to the public workspace.
        content: Content to write.
    """

    target = resolve_lab_path(path)

    if target.exists():
        raise ValueError(
            f"File already exists: {path}"
        )

    target.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    target.write_text(
        content,
        encoding="utf-8",
    )

    return f"Created file: {path}"


@mcp.tool()
def write_file(path: str, content: str) -> str:
    """
    Write or overwrite a text file.

    Args:
        path: File path relative to the public workspace.
        content: New file content.
    """

    target = resolve_lab_path(path)

    target.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    target.write_text(
        content,
        encoding="utf-8",
    )

    return f"Wrote file: {path}"


@mcp.tool()
def delete_file(path: str) -> str:
    """
    Delete a file.

    Args:
        path: File path relative to the public workspace.
    """

    target = resolve_lab_path(path)

    if not target.exists():
        raise ValueError(
            f"File does not exist: {path}"
        )

    if not target.is_file():
        raise ValueError(
            f"Path is not a file: {path}"
        )

    target.unlink()

    return f"Deleted file: {path}"


# ---------------------------------------------------------
# START SERVER
# ---------------------------------------------------------

if __name__ == "__main__":
    mcp.run(transport="stdio")