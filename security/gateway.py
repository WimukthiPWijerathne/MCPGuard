from pathlib import Path
from typing import Any
from .secrets import redact_secrets
from mcp_servers.vulnerable_filesystem import server as vulnerable_server

from .audit import write_audit_event
from .models import (
    Decision,
    ResourceSensitivity,
    RiskLevel,
    SecurityDecision,
    User,
)
from .policy import is_authorized
from .resources import classify_path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
LAB_ROOT = (PROJECT_ROOT / "sandbox").resolve()


class MCPGuard:
    """
    MCPGuard V1 security gateway.

    Current security controls:
        1. Role-based authorization
        2. Argument validation
        3. Path validation
        4. Resource classification
        5. Secret-resource protection
        6. Audit logging
    """

    def __init__(self, user: User):
        self.user = user

    def authorize(self, tool_name: str) -> SecurityDecision:
        """
        Check whether the user is allowed to use the tool.
        """

        try:
            allowed = is_authorized(
                self.user.role,
                tool_name,
            )

        except ValueError as exc:

            decision = SecurityDecision(
                decision=Decision.BLOCK,
                risk_score=100,
                risk_level=RiskLevel.CRITICAL,
                reason=str(exc),
            )

            self._audit(
                tool_name=tool_name,
                arguments={},
                decision=decision,
            )

            return decision

        if not allowed:

            decision = SecurityDecision(
                decision=Decision.BLOCK,
                risk_score=90,
                risk_level=RiskLevel.CRITICAL,
                reason=(
                    f"user '{self.user.user_id}' with role "
                    f"'{self.user.role.value}' is not authorized "
                    f"to execute '{tool_name}'"
                ),
            )

            self._audit(
                tool_name=tool_name,
                arguments={},
                decision=decision,
            )

            return decision

        risk_score = self._base_risk(tool_name)

        return SecurityDecision(
            decision=Decision.ALLOW,
            risk_score=risk_score,
            risk_level=self._risk_level(risk_score),
            reason=f"authorized tool: {tool_name}",
        )
    def _inspect_response(
        self,
        result: Any,
    ) -> Any:
        """
        Inspect an MCP tool response for secrets.

        V1 supports text responses.
        """

        if not isinstance(result, str):
            return result

        sanitized, findings = redact_secrets(result)

        if findings:
            print(
                "[MCPGuard] Secret detected in tool response:"
                f" {', '.join(findings)}"
            )

            return sanitized

        return result

    def call_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any] | None = None,
    ) -> Any:
        """
        Main MCPGuard security entry point.
        """

        arguments = arguments or {}

        # ---------------------------------------------------------
        # STEP 1: Authorization
        # ---------------------------------------------------------

        decision = self.authorize(tool_name)

        if decision.decision == Decision.BLOCK:

            self._audit(
                tool_name=tool_name,
                arguments=arguments,
                decision=decision,
            )

            raise PermissionError(decision.reason)

        # ---------------------------------------------------------
        # STEP 2: Argument validation
        # ---------------------------------------------------------

        try:
            self._validate_arguments(
                tool_name,
                arguments,
            )
        except (ValueError, TypeError) as exc:

            decision = SecurityDecision(
                decision=Decision.BLOCK,
                risk_score=95,
                risk_level=RiskLevel.CRITICAL,
                reason=str(exc),
            )

            self._audit(
                tool_name=tool_name,
                arguments=arguments,
                decision=decision,
            )

            raise

        # ---------------------------------------------------------
        # STEP 3: Path validation
        # ---------------------------------------------------------

        if "path" in arguments:

            try:
                self._validate_path(
                    arguments["path"]
                )

            except PermissionError as exc:

                decision = SecurityDecision(
                    decision=Decision.BLOCK,
                    risk_score=100,
                    risk_level=RiskLevel.CRITICAL,
                    reason=str(exc),
                )

                self._audit(
                    tool_name=tool_name,
                    arguments=arguments,
                    decision=decision,
                )

                raise

        # ---------------------------------------------------------
        # STEP 4: Resource classification
        # ---------------------------------------------------------

        resource = None

        if "path" in arguments:

            resource = classify_path(
                arguments["path"]
            )

            # Outside sandbox should never be allowed.
            if resource == ResourceSensitivity.OUTSIDE_SANDBOX:

                decision = SecurityDecision(
                    decision=Decision.BLOCK,
                    risk_score=100,
                    risk_level=RiskLevel.CRITICAL,
                    reason="resource is outside the sandbox",
                    metadata={
                        "resource": resource.value,
                    },
                )

                self._audit(
                    tool_name=tool_name,
                    arguments=arguments,
                    decision=decision,
                )

                raise PermissionError(
                    decision.reason
                )

            # Secret resources are blocked in V1.
            if resource == ResourceSensitivity.SECRET:

                decision = SecurityDecision(
                    decision=Decision.BLOCK,
                    risk_score=100,
                    risk_level=RiskLevel.CRITICAL,
                    reason="access to secret resources is blocked",
                    metadata={
                        "resource": resource.value,
                    },
                )

                self._audit(
                    tool_name=tool_name,
                    arguments=arguments,
                    decision=decision,
                )

                raise PermissionError(
                    decision.reason
                )

        # ---------------------------------------------------------
        # STEP 5: Adjust risk according to resource
        # ---------------------------------------------------------

        risk_score = decision.risk_score

        if resource == ResourceSensitivity.PRIVATE:
            risk_score += 20

        risk_score = min(risk_score, 100)

        decision = SecurityDecision(
            decision=Decision.ALLOW,
            risk_score=risk_score,
            risk_level=self._risk_level(risk_score),
            reason=(
                f"authorized access to "
                f"{resource.value.lower()}"
                if resource
                else "authorized tool execution"
            ),
            metadata={
                "resource": resource.value
                if resource
                else None
            },
        )

        # ---------------------------------------------------------
        # STEP 6: Execute
        # ---------------------------------------------------------

        tool_function = getattr(
            vulnerable_server,
            tool_name,
            None,
        )

        if tool_function is None:

            failure = SecurityDecision(
                decision=Decision.BLOCK,
                risk_score=100,
                risk_level=RiskLevel.CRITICAL,
                reason=(
                    f"Tool '{tool_name}' does not exist."
                ),
            )

            self._audit(
                tool_name=tool_name,
                arguments=arguments,
                decision=failure,
            )

            raise ValueError(
                failure.reason
            )

        try:

            result = tool_function(
                **arguments
            )

        except Exception as exc:

            failure = SecurityDecision(
                decision=Decision.BLOCK,
                risk_score=100,
                risk_level=RiskLevel.CRITICAL,
                reason=f"tool execution failed: {exc}",
            )

            self._audit(
                tool_name=tool_name,
                arguments=arguments,
                decision=failure,
            )

            raise
        
        # -------------------------------------------------------------
        # STEP 7: Inspect tool response
        # -------------------------------------------------------------

        sanitized_result = self._inspect_response(result)

        # ---------------------------------------------------------
        # STEP 8: Audit successful execution
        # ---------------------------------------------------------

        self._audit(
            tool_name=tool_name,
            arguments=arguments,
            decision=decision,
        )

        return sanitized_result

    # =============================================================
    # VALIDATION
    # =============================================================

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
            raise ValueError(
                f"Unsupported tool: {tool_name}"
            )

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
                    f"{tool_name} requires 'path'."
                )

            if not isinstance(
                arguments["path"],
                str,
            ):
                raise TypeError(
                    "'path' must be a string."
                )

        if tool_name in {
            "create_file",
            "write_file",
        }:

            if "path" not in arguments:
                raise ValueError(
                    f"{tool_name} requires 'path'."
                )

            if "content" not in arguments:
                raise ValueError(
                    f"{tool_name} requires 'content'."
                )

            if not isinstance(
                arguments["path"],
                str,
            ):
                raise TypeError(
                    "'path' must be a string."
                )

            if not isinstance(
                arguments["content"],
                str,
            ):
                raise TypeError(
                    "'content' must be a string."
                )

    def _validate_path(
        self,
        user_path: str,
    ) -> None:

        if not user_path.strip():
            raise ValueError(
                "Path cannot be empty."
            )

        candidate = (
            LAB_ROOT / user_path
        ).resolve()

        try:

            candidate.relative_to(
                LAB_ROOT
            )

        except ValueError:

            raise PermissionError(
                f"Path traversal detected: "
                f"{user_path}"
            )

    # =============================================================
    # RISK
    # =============================================================

    @staticmethod
    def _base_risk(
        tool_name: str,
    ) -> int:

        risk = {
            "list_files": 10,
            "read_file": 20,
            "create_file": 40,
            "write_file": 60,
            "delete_file": 80,
        }

        return risk.get(
            tool_name,
            100,
        )

    @staticmethod
    def _risk_level(
        score: int,
    ) -> RiskLevel:

        if score <= 30:
            return RiskLevel.LOW

        if score <= 60:
            return RiskLevel.MEDIUM

        if score <= 80:
            return RiskLevel.HIGH

        return RiskLevel.CRITICAL

    # =============================================================
    # AUDIT
    # =============================================================

    def _audit(
        self,
        *,
        tool_name: str,
        arguments: dict[str, Any],
        decision: SecurityDecision,
    ) -> None:

        write_audit_event(
            user_id=self.user.user_id,
            role=self.user.role.value,
            tool=tool_name,
            arguments=arguments,
            decision=decision.decision.value,
            risk_score=decision.risk_score,
            risk_level=decision.risk_level.value,
            reason=decision.reason,
        )



"""
read_file("secrets/credentials.txt")
             ↓
       classify_path()
             ↓
          SECRET
             ↓
           BLOCK
"""