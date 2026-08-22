# attack_tests/test_taint_cascading.py
import asyncio
from security.models import UserContext, Role
from security.gateway import MCPGuard
from security.taint import TaintTracker
from mcp_servers.vulnerable_filesystem.server import mcp, LAB_ROOT, WORKSPACE_ROOT

async def run_taint_attack_test():
    print("\n" + "="*60)
    print(" MCPGUARD MULTI-TURN SESSION TAINT EVALUATION")
    print("="*60)

    TaintTracker.reset_all()
    guard = MCPGuard(mcp, LAB_ROOT, WORKSPACE_ROOT)
    
    # An Admin normally has permission to delete files
    admin = UserContext(user_id="admin_carol", role=Role.ADMIN)
    session_id = "session_proc_8821"

    # Turn 1: Admin agent reads a public document (Valid read, but marks context as TAINTED)
    print("\n[Turn 1]: Agent reads public file 'readme.txt'...")
    res1 = await guard.call_tool(admin, "read_file", {"path": "readme.txt"}, session_id=session_id)
    print(f"-> Turn 1 Status: {res1.get('status')} | Session Taint: {TaintTracker.get_or_create(session_id).status.value}")

    # Turn 2: Attacker prompt inside context commands agent to delete 'notes.txt'
    # Even though user is ADMIN, the gateway locks the action due to prior untrusted ingestion
    print("\n[Turn 2]: Injected instruction commands Admin Agent to execute 'delete_file'...")
    res2 = await guard.call_tool(admin, "delete_file", {"path": "notes.txt"}, session_id=session_id)
    print(f"-> Turn 2 Status: {res2.get('status')} | Error: {res2.get('error')}")

    assert res2.get("status") == "BLOCKED_TAINTED", "Taint tracker failed to block post-ingestion action!"
    print("\n" + "="*60)
    print(" SUCCESS: Multi-turn cascading attack neutralized by Taint Engine.")
    print("="*60)

if __name__ == "__main__":
    asyncio.run(run_taint_attack_test())