# dashboard.py
import json
import time
from pathlib import Path
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

st.set_page_config(
    page_title="MCPGuard — AI Security Gateway Dashboard",
    page_icon="🛡️",
    layout="wide",
)

LOG_FILE = Path(__file__).resolve().parent / "logs" / "security_events.jsonl"


def load_logs() -> pd.DataFrame:
    """Reads JSONL logs and returns a cleaned DataFrame."""
    if not LOG_FILE.exists():
        return pd.DataFrame()

    records = []
    with open(LOG_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

    if not records:
        return pd.DataFrame()

    df = pd.DataFrame(records)
    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        df = df.sort_values(by="timestamp", ascending=False)
    return df


# Header & Auto-refresh Sidebar
st.title("🛡️ MCPGuard Security Operations Center (SOC)")
st.caption("Real-Time Zero-Trust Gateway Observability & Threat Analytics")

with st.sidebar:
    st.header("⚙️ Dashboard Controls")
    auto_refresh = st.checkbox("Auto-refresh (every 3s)", value=True)
    refresh_rate = st.slider("Refresh interval (seconds)", 1, 10, 3)

    st.divider()
    st.markdown("### 🔍 Filters")

df = load_logs()

if df.empty:
    st.warning("No security events recorded yet in `logs/security_events.jsonl`.")
    st.info("Run `uv run python agent.py` or attack tests to generate activity.")
    if auto_refresh:
        time.sleep(refresh_rate)
        st.rerun()
    st.stop()

# Sidebar Filters
with st.sidebar:
    all_decisions = ["ALL"] + sorted(df["decision"].dropna().unique().tolist())
    selected_decision = st.selectbox("Filter by Decision", all_decisions)

    all_roles = ["ALL"] + sorted(df["role"].dropna().unique().tolist())
    selected_role = st.selectbox("Filter by Role", all_roles)

    if selected_decision != "ALL":
        df = df[df["decision"] == selected_decision]
    if selected_role != "ALL":
        df = df[df["role"] == selected_role]

# -------------------------------------------------------------
# Top-Level KPI Metric Cards
# -------------------------------------------------------------
total_calls = len(df)
blocked_attacks = len(df[df["decision"].isin(["BLOCK", "QUARANTINED"])])
flagged_injections = len(df[df.get("decision", pd.Series()) == "FLAG_INJECTION"])
secret_leaks_prevented = len(df[df.get("secret_detected", False) == True])
avg_risk = df["risk_score"].mean() if "risk_score" in df.columns else 0.0

kpi1, kpi2, kpi3, kpi4, kpi5 = st.columns(5)
kpi1.metric("Total Tool Invocations", total_calls)
kpi2.metric("Blocked Attacks", blocked_attacks, delta_color="inverse")
kpi3.metric("Prompt Injections Flagged", flagged_injections)
kpi4.metric("Secret Leaks Redacted", secret_leaks_prevented)
kpi5.metric("Avg Risk Score", f"{avg_risk:.1f} / 100")

st.divider()

# -------------------------------------------------------------
# Visualizations Row 1: Decisions Breakdown & Risk Distribution
# -------------------------------------------------------------
col_chart1, col_chart2 = st.columns(2)

with col_chart1:
    st.subheader("📊 Decision Distribution")
    decision_counts = df["decision"].value_counts().reset_index()
    decision_counts.columns = ["Decision", "Count"]

    color_map = {
        "ALLOW": "#22c55e",
        "ALLOW_WITH_AUDIT": "#3b82f6",
        "REQUIRE_APPROVAL": "#f59e0b",
        "BLOCK": "#ef4444",
        "FLAG_INJECTION": "#a855f7",
        "QUARANTINED": "#ec4899",
    }

    fig_decisions = px.pie(
        decision_counts,
        names="Decision",
        values="Count",
        hole=0.4,
        color="Decision",
        color_discrete_map=color_map,
    )
    fig_decisions.update_layout(margin=dict(t=20, b=20, l=20, r=20))
    st.plotly_chart(fig_decisions, use_container_width=True)

with col_chart2:
    st.subheader("📈 Risk Score Distribution")
    fig_risk = px.histogram(
        df,
        x="risk_score",
        nbins=10,
        color="decision",
        color_discrete_map=color_map,
        labels={"risk_score": "Risk Score (0 - 100)", "count": "Events"},
    )
    fig_risk.update_layout(bargap=0.1, margin=dict(t=20, b=20, l=20, r=20))
    st.plotly_chart(fig_risk, use_container_width=True)

# -------------------------------------------------------------
# Visualizations Row 2: Invocations by Tool & Role
# -------------------------------------------------------------
col_chart3, col_chart4 = st.columns(2)

with col_chart3:
    st.subheader("🛠️ Tool Invocation Frequency")
    tool_counts = df["tool"].value_counts().reset_index()
    tool_counts.columns = ["Tool", "Count"]
    fig_tools = px.bar(tool_counts, x="Tool", y="Count", color="Tool")
    fig_tools.update_layout(showlegend=False, margin=dict(t=20, b=20, l=20, r=20))
    st.plotly_chart(fig_tools, use_container_width=True)

with col_chart4:
    st.subheader("👤 Invocations by Role")
    role_counts = df["role"].value_counts().reset_index()
    role_counts.columns = ["Role", "Count"]
    fig_roles = px.bar(role_counts, x="Role", y="Count", color="Role")
    fig_roles.update_layout(showlegend=False, margin=dict(t=20, b=20, l=20, r=20))
    st.plotly_chart(fig_roles, use_container_width=True)

st.divider()

# -------------------------------------------------------------
# Live Audit Log Stream Table
# -------------------------------------------------------------
st.subheader("📜 Live Intercepted Event Stream")

display_cols = [
    c
    for c in [
        "timestamp",
        "user_id",
        "role",
        "tool",
        "risk_score",
        "decision",
        "reason",
        "arguments",
    ]
    if c in df.columns
]
st.dataframe(
    df[display_cols],
    use_container_width=True,
    height=320,
)

# Auto-refresh loop
if auto_refresh:
    time.sleep(refresh_rate)
    st.rerun()