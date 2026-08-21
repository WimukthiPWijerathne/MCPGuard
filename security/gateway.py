# security/gateway.py
import datetime
import json
from pathlib import Path
from typing import Any

from mcp import Client
from security.models import UserContext, PolicyDecision
from security.risk import RiskEngine
from security.rate_limit import RateLimiter
from security.secrets import ResponseScanner
from security.approval import ApprovalManager
from security.injection import PromptInjectionDetector

PROJECT_ROOT = Path(__file__).resolve().parents[1]
LOG_FILE = PROJECT_ROOT / "logs" / "security_events.jsonl"

class MCPGuard:
    def __init__(self, mcp_server_instance: Any, lab_root: Path, workspace_root: Path):
        self.server = mcp_server_instance
        self.lab_root = lab_root.resolve()
        self.workspace_root = workspace_root.resolve()
        self.rate_limiter = RateLimiter(max_requests=5, window_seconds=10)
        
        LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

    def _log_event(self, event: dict) -> None:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(event) + "\n")

    def _classify_path(self, raw_path: str | None) -> tuple[str, str | None]:
        if not raw_path:
            return "PUBLIC", None

        try:
            target = (self.workspace_root / raw_path).resolve()
        except Exception:
            return "OUTSIDE_SANDBOX", None

        if not target.is_relative_to(self.lab_root):
            return "OUTSIDE_SANDBOX", str(target)

        relative = target.relative_to(self.lab_root)
        parts = relative.parts

        if len(parts) > 0 and parts[0] == "secrets":
            return "SECRET", str(target)
        elif len(parts) > 0 and parts[0] == "private":
            return "PRIVATE", str(target)

        return "PUBLIC", str(target)

    async def call_tool(self, user: UserContext, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        path_arg = arguments.get("path")

        # 1. Rate Limiting Check (T07)
        allowed, rate_msg = self.rate_limiter.check(user.user_id, tool_name)
        if not allowed:
            self._log_event({
                "timestamp": timestamp,
                "user_id": user.user_id,
                "role": user.role.value,
                "tool": tool_name,
                "arguments": arguments,
                "decision": PolicyDecision.BLOCK.value,
                "risk_score": 85,
                "reason": rate_msg
            })
            return {"status": "BLOCKED", "error": rate_msg, "risk_score": 85}

        # 2. Resource Boundary Check (T02, T03)
        classification, resolved_path = self._classify_path(path_arg)
        if classification == "OUTSIDE_SANDBOX":
            reason = f"Path traversal blocked: outside sandbox boundary ({path_arg})"
            self._log_event({
                "timestamp": timestamp,
                "user_id": user.user_id,
                "role": user.role.value,
                "tool": tool_name,
                "arguments": arguments,
                "decision": PolicyDecision.BLOCK.value,
                "risk_score": 100,
                "reason": reason
            })
            return {"status": "BLOCKED", "error": reason, "risk_score": 100}

        # 3. Contextual Risk Assessment
        risk_assessment = RiskEngine.calculate(
            tool=tool_name,
            role=user.role,
            path=path_arg,
            resource_classification=classification
        )

        # 4. Enforce Policy Block
        if risk_assessment.decision == PolicyDecision.BLOCK.value:
            reason = f"Policy violation: {'; '.join(risk_assessment.reasons)}"
            self._log_event({
                "timestamp": timestamp,
                "user_id": user.user_id,
                "role": user.role.value,
                "tool": tool_name,
                "arguments": arguments,
                "decision": PolicyDecision.BLOCK.value,
                "risk_score": risk_assessment.score,
                "reason": reason
            })
            return {"status": "BLOCKED", "error": reason, "risk_score": risk_assessment.score}

        # 5. Human Approval Check (T06)
        if risk_assessment.decision == PolicyDecision.REQUIRE_APPROVAL.value:
            approved = ApprovalManager.prompt_approval(
                user_id=user.user_id,
                tool=tool_name,
                arguments=arguments,
                risk_score=risk_assessment.score
            )
            if not approved:
                reason = "Destructive operation rejected by administrator"
                self._log_event({
                    "timestamp": timestamp,
                    "user_id": user.user_id,
                    "role": user.role.value,
                    "tool": tool_name,
                    "arguments": arguments,
                    "decision": PolicyDecision.BLOCK.value,
                    "risk_score": risk_assessment.score,
                    "reason": reason
                })
                return {"status": "BLOCKED", "error": reason, "risk_score": risk_assessment.score}

        # 6. Server Execution
        async with Client(self.server) as client:
            raw_result = await client.call_tool(tool_name, arguments)
            raw_content = str(raw_result.structured_content if hasattr(raw_result, 'structured_content') else raw_result)

        # 7. Prompt Injection Inspection (T04)
        is_injection, injection_msg = PromptInjectionDetector.inspect(raw_content)
        if is_injection:
            quarantine_text = f"[MCPGuard Quarantine]: Response blocked. {injection_msg}"
            self._log_event({
                "timestamp": timestamp,
                "user_id": user.user_id,
                "role": user.role.value,
                "tool": tool_name,
                "arguments": arguments,
                "decision": "FLAG_INJECTION",
                "risk_score": 90,
                "reason": injection_msg
            })
            return {
                "status": "FLAGGED_INJECTION",
                "decision": "QUARANTINED",
                "risk_score": 90,
                "result": quarantine_text,
                "warning": injection_msg
            }

        # 8. Secret Redaction (T05)
        sanitized_content, detected_secrets = ResponseScanner.scan(raw_content)

        # 9. Log Successful Event
        self._log_event({
            "timestamp": timestamp,
            "user_id": user.user_id,
            "role": user.role.value,
            "tool": tool_name,
            "arguments": arguments,
            "decision": risk_assessment.decision,
            "risk_score": risk_assessment.score,
            "secret_detected": len(detected_secrets) > 0,
            "redacted_types": detected_secrets,
            "reason": "Authorized execution completed"
        })

        return {
            "status": "SUCCESS",
            "decision": risk_assessment.decision,
            "risk_score": risk_assessment.score,
            "result": sanitized_content,
            "secrets_redacted": detected_secrets
        }