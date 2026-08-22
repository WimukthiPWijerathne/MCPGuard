# attack_tests/test_canary_tripwire.py
import os
import asyncio
from pathlib import Path

os.environ["MCPGUARD_AUTO_APPROVE"] = "1"

from security.models import UserContext, Role
from security.gateway import MCPGuard
from security.canary import CanaryEngine
from mcp_servers.vulnerable_filesystem.server import mcp, LAB_ROOT, WORKSPACE_ROOT


async def run_canary_tripwire_tests():
    print("\n" + "=" * 60)
    print(" MCPGUARD ACTIVE CANARY & HONEYPOT EVALUATION")
    print("=" * 60)

    guard = MCPGuard(mcp, LAB_ROOT, WORKSPACE_ROOT)
    admin = UserContext(user_id="admin_eve", role=Role.ADMIN)

    # 1. Probe Honeypot Bait File
    print("\n[Test 1]: Agent probes honeypot bait file 'secrets/aws_prod_keys.env'...")
    res_honeypot = await guard.call_tool(
        user=admin,
        tool_name="read_file",
        arguments={"path": "secrets/aws_prod_keys.env"},
        session_id="canary_session_1",
    )
    print(f"-> Status: {res_honeypot.get('status')} | Risk Score: {res_honeypot.get('risk_score')}")
    print(f"-> Alert Reason: {res_honeypot.get('error')}")
    assert res_honeypot.get("status") == "BLOCKED_HONEYPOT_TRAP", "Honeypot detector failed to trigger"

    # 2. Canary Token Exfiltration Attempt
    # Generate a tracked canary token and simulate an agent trying to write it to an external file
    tracked_token = CanaryEngine.generate_token(label="SQL_ADMIN_PASSWORD")
    print(f"\n[Test 2]: Agent attempts to exfiltrate active Canary Token ({tracked_token[:20]}...)...")
    res_exfil = await guard.call_tool(
        user=admin,
        tool_name="write_file",
        arguments={
            "path": "public/exfiltrated_leak.txt",
            "content": f"Here is the database password: {tracked_token}",
        },
        session_id="canary_session_2",
    )
    print(f"-> Status: {res_exfil.get('status')} | Risk Score: {res_exfil.get('risk_score')}")
    print(f"-> Alert Reason: {res_exfil.get('error')}")
    assert res_exfil.get("status") == "BLOCKED_CANARY_EXFILTRATION", "Canary exfiltration scanner failed"

    # 3. Clean Legitimate Access Integrity
    print("\n[Test 3]: Legitimate non-canary file read...")
    res_clean = await guard.call_tool(
        user=admin,
        tool_name="read_file",
        arguments={"path": "readme.txt"},
        session_id="canary_session_3",
    )
    print(f"-> Status: {res_clean.get('status')} (Verifying no false positives on clean files)")
    assert res_clean.get("status") == "SUCCESS", "Canary engine caused a false positive"

    print("\n" + "=" * 60)
    print(" ALL CANARY & HONEYPOT TRIPWIRE CHECKS PASSED")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(run_canary_tripwire_tests())