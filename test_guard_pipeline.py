# test_guard_pipeline.py
import asyncio
from mcp_servers.vulnerable_filesystem.server import mcp, LAB_ROOT, WORKSPACE_ROOT
from security.models import UserContext, Role
from security.gateway import MCPGuard

async def main():
    guard = MCPGuard(mcp, LAB_ROOT, WORKSPACE_ROOT)

    viewer = UserContext(user_id="usr_viewer", role=Role.VIEWER)
    developer = UserContext(user_id="usr_dev", role=Role.DEVELOPER)

    print("\n" + "="*50)
    print(" MCPGUARD INTEGRATED PIPELINE TESTS")
    print("="*50)

    # Test 1: Legitimate Public Read
    print("\n[TEST 1] Viewer reading public readme.txt")
    res1 = await guard.call_tool(viewer, "read_file", {"path": "readme.txt"})
    print(f"Status: {res1['status']} | Risk: {res1['risk_score']}")
    assert res1["status"] == "SUCCESS"

    # Test 2: Unauthorized Action (RBAC)
    print("\n[TEST 2] Viewer attempting delete_file")
    res2 = await guard.call_tool(viewer, "delete_file", {"path": "readme.txt"})
    print(f"Status: {res2['status']} | Error: {res2.get('error')}")
    assert res2["status"] == "BLOCKED"

    # Test 3: Path Traversal to Secret
    print("\n[TEST 3] Developer attempting path traversal to secrets")
    res3 = await guard.call_tool(developer, "read_file", {"path": "../secrets/credentials.txt"})
    print(f"Status: {res3['status']} | Error: {res3.get('error')}")
    assert res3["status"] == "BLOCKED"

    # Test 4: Escape Lab Boundary
    print("\n[TEST 4] Developer attempting escape outside sandbox")
    res4 = await guard.call_tool(developer, "read_file", {"path": "../../../../../Windows/System32/drivers/etc/hosts"})
    print(f"Status: {res4['status']} | Error: {res4.get('error')}")
    assert res4["status"] == "BLOCKED"

    print("\n" + "="*50)
    print("[PIPELINE VERIFICATION COMPLETE - ALL CHECKS PASSED]")
    print("="*50)

if __name__ == "__main__":
    asyncio.run(main())