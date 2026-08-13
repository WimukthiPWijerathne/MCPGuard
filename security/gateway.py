from pathlib import Path
from typing import Any

from mcp_servers.vulnerable_filesystem import server as vulnerable_server

from .models import (
    Decision,
    RiskLevel,
    SecurityDecision,
    User,
)
from .policy import is_authorized


PROJECT_ROOT = Path(__file__).resolve().parents[1]
LAB_ROOT = (PROJECT_ROOT / "sandbox").resolve()


class MCPGuard:
    """
    First version of the MCPGuard security gateway.

    It performs:
    - authorization
    - basic path/resource checks
    - tool dispatch
    """

    def __init__(self, user: User):
        self.user = user

    def authorize(self, tool_name: str) -> SecurityDecision:
        """
        Check whether the current user may execute the requested tool.
        """

        try:
            allowed = is_authorized(self.user.role, tool_name)
        except ValueError as exc:
            return SecurityDecision(
                decision=Decision.BLOCK,
                risk_score=100,
                risk_level=RiskLevel.CRITICAL,
                reason=str(exc),
            )

        if not allowed:
            return SecurityDecision(
                decision=Decision.BLOCK,
                risk_score=90,
                risk_level=RiskLevel.CRITICAL,
                reason=(
                    f"user '{self.user.user_id}' with role "
                    f"'{self.user.role.value}' is not authorized "
                    f"to execute '{tool_name}'"
                ),
            )

        # Preliminary score only.
        risk_score = self._base_risk(tool_name)

        return SecurityDecision(
            decision=Decision.ALLOW,
            risk_score=risk_score,
            risk_level=self._risk_level(risk_score),
            reason=f"authorized tool: {tool_name}",
        )

    def call_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any] | None = None,
    ) -> Any:
        """
        Security gateway entry point.

        Every tool invocation must pass through this function.
        """

        arguments = arguments or {}

        # ---------------------------------------------------------
        # 1. Authorization
        # ---------------------------------------------------------
        decision = self.authorize(tool_name)

        if decision.decision == Decision.BLOCK:
            raise PermissionError(decision.reason)

        # ---------------------------------------------------------
        # 2. Basic argument validation
        # ---------------------------------------------------------
        self._validate_arguments(tool_name, arguments)

        # ---------------------------------------------------------
        # 3. Basic path validation
        # ---------------------------------------------------------
        if "path" in arguments:
            self._validate_path(arguments["path"])

        # ---------------------------------------------------------
        # 4. Dispatch to vulnerable MCP server implementation
        # ---------------------------------------------------------
        tool_function = getattr(vulnerable_server, tool_name, None)

        if tool_function is None:
            raise ValueError(
                f"Tool '{tool_name}' does not exist "
                "in the vulnerable filesystem server."
            )

        return tool_function(**arguments)

    # -------------------------------------------------------------
    # SECURITY CHECKS
    # -------------------------------------------------------------

    def _validate_arguments(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> None:

        allowed_tools = {
            "list_files",
            "read_file",
            "create_file",
            "write_file",
            "delete_file",
        }

        if tool_name not in allowed_tools:
            raise ValueError(f"Unsupported tool: {tool_name}")

        if tool_name == "list_files":
            if arguments:
                raise ValueError(
                    "list_files() does not accept arguments."
                )

        if tool_name in {
            "read_file",
            "delete_file",
        }:
            if "path" not in arguments:
                raise ValueError(
                    f"{tool_name} requires a 'path' argument."
                )

            if not isinstance(arguments["path"], str):
                raise TypeError(
                    "'path' must be a string."
                )

        if tool_name in {
            "create_file",
            "write_file",
        }:
            if "path" not in arguments:
                raise ValueError(
                    f"{tool_name} requires a 'path' argument."
                )

            if "content" not in arguments:
                raise ValueError(
                    f"{tool_name} requires 'content'."
                )

            if not isinstance(arguments["path"], str):
                raise TypeError(
                    "'path' must be a string."
                )

            if not isinstance(arguments["content"], str):
                raise TypeError(
                    "'content' must be a string."
                )

    def _validate_path(self, user_path: str) -> None:
        """
        Validate that a requested path stays inside sandbox.
        """

        if not user_path.strip():
            raise ValueError("Path cannot be empty.")

        candidate = (LAB_ROOT / user_path).resolve()

        try:
            candidate.relative_to(LAB_ROOT)
        except ValueError:
            raise PermissionError(
                f"Path traversal detected: {user_path}"
            )

    # -------------------------------------------------------------
    # RISK
    # -------------------------------------------------------------

    @staticmethod
    def _base_risk(tool_name: str) -> int:

        risk = {
            "list_files": 10,
            "read_file": 20,
            "create_file": 40,
            "write_file": 60,
            "delete_file": 80,
        }

        return risk.get(tool_name, 100)

    @staticmethod
    def _risk_level(score: int) -> RiskLevel:

        if score <= 30:
            return RiskLevel.LOW

        if score <= 60:
            return RiskLevel.MEDIUM

        if score <= 80:
            return RiskLevel.HIGH

        return RiskLevel.CRITICAL