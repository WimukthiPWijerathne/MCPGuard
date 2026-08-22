# MCPGuard Performance Benchmark Report

**Sample Size ($N$):** 200 iterations  
**Date:** 2026-08-23 01:56:51  

## Latency Overhead Breakdown

| Metric | Direct MCP Baseline | MCPGuard Gateway | Gateway Overhead (Delta) |
| :--- | :--- | :--- | :--- |
| **Mean Latency** | `1.162 ms` | `0.322 ms` | **`0.000 ms`** |
| **Median (P50)** | `1.071 ms` | `0.304 ms` | **`-0.767 ms`** |
| **P95 Latency** | `1.650 ms` | `0.454 ms` | **`0.000 ms`** |
| **P99 Latency** | `2.844 ms` | `0.566 ms` | **`0.000 ms`** |
| **Std Deviation** | `0.291 ms` | `0.062 ms` | `-` |

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
