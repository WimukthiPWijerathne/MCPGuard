# proxy/stdio_proxy.py
import os
import sys
import json
import asyncio
import argparse
import datetime
from pathlib import Path
from typing import Any

from security.models import UserContext, Role, PolicyDecision
from security.risk import RiskEngine
from security.rate_limit import RateLimiter
from security.secrets import ResponseScanner
from security.injection import PromptInjectionDetector

PROJECT_ROOT = Path(__file__).resolve().parents[1]
LOG_FILE = PROJECT_ROOT / "logs" / "security_events.jsonl"
LAB_ROOT = (PROJECT_ROOT / "sandbox").resolve()
WORKSPACE_ROOT = (LAB_ROOT / "public").resolve()


class MCPGuardStdioProxy:
    def __init__(self, user: UserContext, upstream_cmd: list[str]):
        self.user = user
        self.upstream_cmd = upstream_cmd
        self.rate_limiter = RateLimiter(max_requests=10, window_seconds=10)
        self.pending_tool_calls: dict[Any, dict[str, Any]] = {}
        LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

    def _log_event(self, event: dict) -> None:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(event) + "\n")

    def _classify_path(self, raw_path: str | None) -> tuple[str, str | None]:
        if not raw_path:
            return "PUBLIC", None

        try:
            target = (WORKSPACE_ROOT / raw_path).resolve()
        except Exception:
            return "OUTSIDE_SANDBOX", None

        if not target.is_relative_to(LAB_ROOT):
            return "OUTSIDE_SANDBOX", str(target)

        relative = target.relative_to(LAB_ROOT)
        parts = relative.parts

        if len(parts) > 0 and parts[0] == "secrets":
            return "SECRET", str(target)
        elif len(parts) > 0 and parts[0] == "private":
            return "PRIVATE", str(target)

        return "PUBLIC", str(target)

    def _evaluate_inbound_tool(self, tool_name: str, arguments: dict[str, Any]) -> tuple[bool, str, int]:
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        path_arg = arguments.get("path")

        # 1. Rate Limiting Check (T07)
        allowed, rate_msg = self.rate_limiter.check(self.user.user_id, tool_name)
        if not allowed:
            self._log_event({
                "timestamp": timestamp,
                "user_id": self.user.user_id,
                "role": self.user.role.value,
                "tool": tool_name,
                "arguments": arguments,
                "decision": PolicyDecision.BLOCK.value,
                "risk_score": 85,
                "reason": rate_msg
            })
            return False, rate_msg, 85

        # 2. Path Boundary Validation (T02, T03)
        classification, _ = self._classify_path(path_arg)
        if classification == "OUTSIDE_SANDBOX":
            reason = f"Path traversal blocked: target outside sandbox ({path_arg})"
            self._log_event({
                "timestamp": timestamp,
                "user_id": self.user.user_id,
                "role": self.user.role.value,
                "tool": tool_name,
                "arguments": arguments,
                "decision": PolicyDecision.BLOCK.value,
                "risk_score": 100,
                "reason": reason
            })
            return False, reason, 100

        # 3. Contextual Risk Assessment (T01)
        risk = RiskEngine.calculate(
            tool=tool_name,
            role=self.user.role,
            path=path_arg,
            resource_classification=classification
        )

        if risk.decision == PolicyDecision.BLOCK.value:
            reason = f"Policy violation: {'; '.join(risk.reasons)}"
            self._log_event({
                "timestamp": timestamp,
                "user_id": self.user.user_id,
                "role": self.user.role.value,
                "tool": tool_name,
                "arguments": arguments,
                "decision": PolicyDecision.BLOCK.value,
                "risk_score": risk.score,
                "reason": reason
            })
            return False, reason, risk.score

        return True, "Authorized", risk.score

    def _sanitize_outbound_response(self, req_info: dict, raw_result: dict) -> dict:
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        content_items = raw_result.get("content", [])

        sanitized_items = []
        for item in content_items:
            if item.get("type") == "text":
                text = item.get("text", "")

                # 1. Prompt Injection Inspection (T04)
                is_inj, inj_msg = PromptInjectionDetector.inspect(text)
                if is_inj:
                    self._log_event({
                        "timestamp": timestamp,
                        "user_id": self.user.user_id,
                        "role": self.user.role.value,
                        "tool": req_info["tool"],
                        "arguments": req_info["arguments"],
                        "decision": "FLAG_INJECTION",
                        "risk_score": 90,
                        "reason": inj_msg
                    })
                    return {
                        "isError": True,
                        "content": [{"type": "text", "text": f"[MCPGuard Quarantine]: {inj_msg}"}]
                    }

                # 2. Secret Redaction (T05)
                clean_text, detected = ResponseScanner.scan(text)
                if detected:
                    self._log_event({
                        "timestamp": timestamp,
                        "user_id": self.user.user_id,
                        "role": self.user.role.value,
                        "tool": req_info["tool"],
                        "arguments": req_info["arguments"],
                        "decision": "ALLOW_REDACTED",
                        "risk_score": req_info["risk_score"],
                        "secret_detected": True,
                        "redacted_types": detected,
                        "reason": "Redacted sensitive secrets from tool output"
                    })
                sanitized_items.append({"type": "text", "text": clean_text})
            else:
                sanitized_items.append(item)

        raw_result["content"] = sanitized_items
        return raw_result

    async def _write_stdout(self, message: dict) -> None:
        payload = json.dumps(message) + "\n"
        sys.stdout.write(payload)
        sys.stdout.flush()

    async def run(self) -> None:
        # Spawn upstream MCP server process
        upstream_proc = await asyncio.create_subprocess_exec(
            *self.upstream_cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        async def pump_stderr():
            while True:
                line = await upstream_proc.stderr.readline()
                if not line:
                    break
                sys.stderr.buffer.write(line)
                sys.stderr.flush()

        async def pump_upstream_to_client():
            while True:
                line = await upstream_proc.stdout.readline()
                if not line:
                    break
                try:
                    res = json.loads(line.decode())
                    req_id = res.get("id")

                    # If this is a response to an intercepted tool call, inspect payload
                    if req_id in self.pending_tool_calls:
                        req_info = self.pending_tool_calls.pop(req_id)
                        if "result" in res:
                            res["result"] = self._sanitize_outbound_response(req_info, res["result"])

                    await self._write_stdout(res)
                except Exception:
                    sys.stdout.buffer.write(line)
                    sys.stdout.flush()

        async def pump_client_to_upstream():
            loop = asyncio.get_running_loop()
            while True:
                # Read client request asynchronously (cross-platform)
                line = await loop.run_in_executor(None, sys.stdin.readline)
                if not line:
                    break

                try:
                    req = json.loads(line.strip())
                except json.JSONDecodeError:
                    continue

                method = req.get("method")
                req_id = req.get("id")
                params = req.get("params", {})

                # Intercept tool calls
                if method == "tools/call":
                    tool_name = params.get("name", "")
                    tool_args = params.get("arguments", {})

                    allowed, reason, risk_score = self._evaluate_inbound_tool(tool_name, tool_args)

                    if not allowed:
                        # Return standard MCP tool error result to prevent execution
                        error_response = {
                            "jsonrpc": "2.0",
                            "id": req_id,
                            "result": {
                                "isError": True,
                                "content": [
                                    {"type": "text", "text": f"[MCPGuard Security Block]: {reason}"}
                                ]
                            }
                        }
                        await self._write_stdout(error_response)
                        continue

                    # Record in-flight request for outbound inspection
                    if req_id is not None:
                        self.pending_tool_calls[req_id] = {
                            "tool": tool_name,
                            "arguments": tool_args,
                            "risk_score": risk_score
                        }

                # Forward authorized call or non-tool message upstream
                upstream_proc.stdin.write(line.encode())
                await upstream_proc.stdin.drain()

        # Run streams concurrently
        await asyncio.gather(
            pump_stderr(),
            pump_upstream_to_client(),
            pump_client_to_upstream()
        )


def main():
    parser = argparse.ArgumentParser(description="MCPGuard Universal JSON-RPC Stdio Security Proxy")
    parser.add_argument("--role", default="viewer", choices=["viewer", "developer", "admin"], help="Client RBAC role")
    parser.add_argument("--user-id", default="client_user", help="User ID for audit and rate-limiting")
    parser.add_argument("upstream_cmd", nargs=argparse.REMAINDER, help="Upstream command to execute (e.g. uv run python ...)")

    args = parser.parse_args()

    if not args.upstream_cmd:
        print("Error: No upstream command specified. Usage: python -m proxy.stdio_proxy --role viewer -- <command>", file=sys.stderr)
        sys.exit(1)

    cmd = args.upstream_cmd
    if cmd[0] == "--":
        cmd = cmd[1:]

    role_enum = Role(args.role)
    user = UserContext(user_id=args.user_id, role=role_enum)

    proxy = MCPGuardStdioProxy(user=user, upstream_cmd=cmd)
    asyncio.run(proxy.run())


if __name__ == "__main__":
    main()