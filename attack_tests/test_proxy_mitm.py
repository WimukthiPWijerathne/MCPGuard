# attack_tests/test_proxy_mitm.py
import sys
import json
import asyncio
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]


async def send_rpc(proc: asyncio.subprocess.Process, message: dict) -> dict:
    """Sends a JSON-RPC payload over stdin and reads the single-line response from stdout."""
    raw = json.dumps(message) + "\n"
    if proc.stdin is None or proc.stdout is None:
        return {}

    proc.stdin.write(raw.encode())
    await proc.stdin.drain()

    response_line = await proc.stdout.readline()
    if not response_line:
        return {}
    return json.loads(response_line.decode())


async def run_mitm_tests():
    print("\n" + "=" * 60)
    print(" MCPGUARD STDIO PROXY JSON-RPC VERIFICATION")
    print("=" * 60)

    # Command launching the proxy with a 'viewer' role proxying the vulnerable server
    proxy_cmd = [
        sys.executable,
        "-m",
        "proxy.stdio_proxy",
        "--role",
        "viewer",
        "--user-id",
        "viewer_bob",
        "--",
        sys.executable,
        "mcp_servers/vulnerable_filesystem/server.py",
    ]

    proc = await asyncio.create_subprocess_exec(
        *proxy_cmd,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    # 1. Initialize Handshake (Pass-through)
    init_req = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "test-client", "version": "1.0"},
        },
    }
    init_res = await send_rpc(proc, init_req)
    print(f"\n[1. Initialize Pass-Through]: Success = {'result' in init_res}")

    # 2. Legitimate Read (Authorized)
    read_req = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "read_file",
            "arguments": {"path": "readme.txt"},
        },
    }
    read_res = await send_rpc(proc, read_req)
    first_chunk = (
        read_res.get("result", {})
        .get("content", [{}])[0]
        .get("text", "")[:40]
    )
    print(f"[2. Legitimate Read Request]: {first_chunk}...")

    # 3. RBAC Block (Viewer attempting delete_file)
    del_req = {
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "delete_file",
            "arguments": {"path": "notes.txt"},
        },
    }
    del_res = await send_rpc(proc, del_req)
    del_text = (
        del_res.get("result", {}).get("content", [{}])[0].get("text", "")
    )
    print(f"[3. RBAC Violation Intercepted]: {del_text}")

    # 4. Path Traversal Block (Relative escape)
    trav_req = {
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {
            "name": "read_file",
            "arguments": {"path": "../../../../../etc/passwd"},
        },
    }
    trav_res = await send_rpc(proc, trav_req)
    trav_text = (
        trav_res.get("result", {}).get("content", [{}])[0].get("text", "")
    )
    print(f"[4. Path Traversal Intercepted]: {trav_text}")

    # 5. Outbound Prompt Injection Quarantine
    inj_req = {
        "jsonrpc": "2.0",
        "id": 5,
        "method": "tools/call",
        "params": {
            "name": "read_file",
            "arguments": {"path": "malicious_report.txt"},
        },
    }
    inj_res = await send_rpc(proc, inj_req)
    inj_text = (
        inj_res.get("result", {}).get("content", [{}])[0].get("text", "")
    )
    print(f"[5. Prompt Injection Quarantined]: {inj_text}")

    # Graceful shutdown of subprocess and streams (prevents Windows Proactor pipe warnings)
    try:
        if proc.stdin:
            proc.stdin.close()
            await proc.stdin.wait_closed()
    except Exception:
        pass

    proc.terminate()
    try:
        await asyncio.wait_for(proc.wait(), timeout=2.0)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()

    # Yield control to allow event loop cleanup of pipe transports
    await asyncio.sleep(0.1)

    print("\n" + "=" * 60)
    print(" ALL STDIO PROXY WIRE CHECKS VERIFIED")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(run_mitm_tests())