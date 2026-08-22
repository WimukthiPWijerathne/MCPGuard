# benchmark/benchmark_gateway.py
import os
import time
import asyncio
import statistics
from pathlib import Path
from mcp import Client

# Enable auto-approval for benchmark runs
os.environ["MCPGUARD_AUTO_APPROVE"] = "1"

from security.models import UserContext, Role
from security.gateway import MCPGuard
from mcp_servers.vulnerable_filesystem.server import mcp, LAB_ROOT, WORKSPACE_ROOT

PROJECT_ROOT = Path(__file__).resolve().parents[1]
BENCHMARK_REPORT = PROJECT_ROOT / "docs" / "BENCHMARK_REPORT.md"


async def benchmark_baseline(iterations: int = 100) -> list[float]:
    """Measures raw MCP server execution time without MCPGuard."""
    latencies = []
    async with Client(mcp) as client:
        # Warmup
        for _ in range(5):
            await client.call_tool("read_file", {"path": "readme.txt"})

        for _ in range(iterations):
            t0 = time.perf_counter()
            await client.call_tool("read_file", {"path": "readme.txt"})
            t1 = time.perf_counter()
            latencies.append((t1 - t0) * 1000.0)  # ms
    return latencies


async def benchmark_gateway(iterations: int = 100) -> list[float]:
    """Measures end-to-end tool execution through the full MCPGuard security pipeline."""
    guard = MCPGuard(mcp, LAB_ROOT, WORKSPACE_ROOT)
    user = UserContext(user_id="bench_user", role=Role.DEVELOPER)
    latencies = []

    # Warmup
    for _ in range(5):
        await guard.call_tool(user, "read_file", {"path": "readme.txt"}, session_id="bench_warmup")

    for i in range(iterations):
        session_id = f"bench_session_{i}"
        t0 = time.perf_counter()
        await guard.call_tool(user, "read_file", {"path": "readme.txt"}, session_id=session_id)
        t1 = time.perf_counter()
        latencies.append((t1 - t0) * 1000.0)  # ms
    return latencies


def compute_metrics(latencies: list[float]) -> dict[str, float]:
    sorted_l = sorted(latencies)
    return {
        "mean": statistics.mean(sorted_l),
        "median": statistics.median(sorted_l),
        "stdev": statistics.stdev(sorted_l) if len(sorted_l) > 1 else 0.0,
        "p95": sorted_l[int(len(sorted_l) * 0.95)],
        "p99": sorted_l[int(len(sorted_l) * 0.99)],
        "min": min(sorted_l),
        "max": max(sorted_l),
    }


async def run_benchmark(iterations: int = 200):
    print("\n" + "=" * 60)
    print(f" MCPGUARD LATENCY & PERFORMANCE BENCHMARK (N={iterations})")
    print("=" * 60)

    print("\n[1/2] Benchmarking direct MCP baseline execution...")
    base_l = await benchmark_baseline(iterations)
    base_m = compute_metrics(base_l)

    print("[2/2] Benchmarking MCPGuard Zero-Trust Gateway execution...")
    guard_l = await benchmark_gateway(iterations)
    guard_m = compute_metrics(guard_l)

    overhead_mean = max(0.0, guard_m["mean"] - base_m["mean"])
    overhead_p95 = max(0.0, guard_m["p95"] - base_m["p95"])
    overhead_p99 = max(0.0, guard_m["p99"] - base_m["p99"])

    print("\n" + "-" * 60)
    print(" BENCHMARK RESULTS SUMMARY (in milliseconds)")
    print("-" * 60)
    print(f"{'Metric':<16} | {'Baseline (No Guard)':<20} | {'MCPGuard Gateway':<18} | {'Overhead (Delta)':<15}")
    print("-" * 75)
    print(f"{'Mean Latency':<16} | {base_m['mean']:>18.3f} ms | {guard_m['mean']:>16.3f} ms | {overhead_mean:>13.3f} ms")
    print(f"{'Median (P50)':<16} | {base_m['median']:>18.3f} ms | {guard_m['median']:>16.3f} ms | {(guard_m['median'] - base_m['median']):>13.3f} ms")
    print(f"{'P95 Latency':<16} | {base_m['p95']:>18.3f} ms | {guard_m['p95']:>16.3f} ms | {overhead_p95:>13.3f} ms")
    print(f"{'P99 Latency':<16} | {base_m['p99']:>18.3f} ms | {guard_m['p99']:>16.3f} ms | {overhead_p99:>13.3f} ms")
    print(f"{'Std Dev':<16} | {base_m['stdev']:>18.3f} ms | {guard_m['stdev']:>16.3f} ms | {'-':>15}")
    print("-" * 75)

    # Export Markdown Report
    BENCHMARK_REPORT.parent.mkdir(parents=True, exist_ok=True)
    with open(BENCHMARK_REPORT, "w", encoding="utf-8") as f:
        f.write(f"""# MCPGuard Performance Benchmark Report

**Sample Size ($N$):** {iterations} iterations  
**Date:** {time.strftime('%Y-%m-%d %H:%M:%S')}  

## Latency Overhead Breakdown

| Metric | Direct MCP Baseline | MCPGuard Gateway | Gateway Overhead (Delta) |
| :--- | :--- | :--- | :--- |
| **Mean Latency** | `{base_m['mean']:.3f} ms` | `{guard_m['mean']:.3f} ms` | **`{overhead_mean:.3f} ms`** |
| **Median (P50)** | `{base_m['median']:.3f} ms` | `{guard_m['median']:.3f} ms` | **`{guard_m['median'] - base_m['median']:.3f} ms`** |
| **P95 Latency** | `{base_m['p95']:.3f} ms` | `{guard_m['p95']:.3f} ms` | **`{overhead_p95:.3f} ms`** |
| **P99 Latency** | `{base_m['p99']:.3f} ms` | `{guard_m['p99']:.3f} ms` | **`{overhead_p99:.3f} ms`** |
| **Std Deviation** | `{base_m['stdev']:.3f} ms` | `{guard_m['stdev']:.3f} ms` | `-` |

### Pipeline Components Included in Measurement:
1. Inbound Rate Limiting & Sliding Window Checks
2. Path Resolution & Sandbox Boundary Canonicalization
3. Resource Sensitivity Classification
4. Role-Based Access Control (RBAC) Enforcement
5. Contextual Risk Scoring Matrix (0–100)
6. Stateful Multi-Turn Session Taint Lineage Lookup
7. Active Canary Token Exfiltration Scanner
8. Outbound Heuristic Prompt Injection Regex Scanner
9. Outbound Secret Redaction Engine
10. Synchronous Structured JSONL Audit Logging
""")

    print(f"\n[+] Full benchmark report saved to: docs/BENCHMARK_REPORT.md\n")


if __name__ == "__main__":
    asyncio.run(run_benchmark(iterations=200))