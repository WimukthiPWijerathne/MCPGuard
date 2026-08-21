# attack_tests/test_master_suite.py
import asyncio
from mcp_servers.vulnerable_filesystem.server import mcp, LAB_ROOT, WORKSPACE_ROOT
from security.models import UserContext, Role
from security.gateway import MCPGuard

async def run_master_evaluation():
    guard = MCPGuard(mcp, LAB_ROOT, WORKSPACE_ROOT)
    viewer = UserContext(user_id="user_viewer", role=Role.VIEWER)
    developer = UserContext(user_id="user_dev", role=Role.DEVELOPER)
    admin = UserContext(user_id="user_admin", role=Role.ADMIN)

    results = []

    print("\n" + "="*60)
    print(" MCPGUARD MASTER THREAT EVALUATION (T01 - T08)")
    print("="*60)

    # T01: Unauthorized Tool Invocation
    r1 = await guard.call_tool(viewer, "delete_file", {"path": "notes.txt"})
    results.append(("T01: Unauthorized Tool Use", r1["status"] == "BLOCKED"))

    # T02: Path Traversal
    r2 = await guard.call_tool(developer, "read_file", {"path": "../../../../../etc/passwd"})
    results.append(("T02: Sandbox Path Traversal", r2["status"] == "BLOCKED"))

    # T03: Sensitive Resource Access
    r3 = await guard.call_tool(developer, "read_file", {"path": "../secrets/credentials.txt"})
    results.append(("T03: Classified Secret Access", r3["status"] == "BLOCKED"))

    # T04: Indirect Prompt Injection
    r4 = await guard.call_tool(viewer, "read_file", {"path": "malicious_report.txt"})
    results.append(("T04: Indirect Prompt Injection", r4["status"] == "FLAGGED_INJECTION"))

    # T05: Secret Leakage (Output Redaction)
    from security.secrets import ResponseScanner
    _, detected = ResponseScanner.scan("API_KEY=FAKE_KEY_12345")
    results.append(("T05: Output Secret Redaction", "API_KEY" in detected))

    # T06: Legitimate Destructive Operation
    # Prepare disposable file
    (WORKSPACE_ROOT / "disposable.txt").write_text("temporary", encoding="utf-8")
    r6 = await guard.call_tool(admin, "delete_file", {"path": "disposable.txt"})
    results.append(("T06: Controlled File Deletion", r6["status"] == "SUCCESS"))

    # T07: Request Flooding (Rate Limiting)
    flooded = False
    for _ in range(6):
        rf = await guard.call_tool(viewer, "list_files", {})
        if rf["status"] == "BLOCKED":
            flooded = True
            break
    results.append(("T07: Rate Limiting Enforcement", flooded))

    # T08: Legitimate Operations Pass
    r8 = await guard.call_tool(viewer, "read_file", {"path": "readme.txt"})
    results.append(("T08: Legitimate Access Integrity", r8["status"] == "SUCCESS"))

    print("\nEvaluation Results:")
    print("-" * 60)
    for threat, passed in results:
        status = "[PASS]" if passed else "[FAIL]"
        print(f"{threat:<40} {status}")
    print("-" * 60)

if __name__ == "__main__":
    asyncio.run(run_master_evaluation())