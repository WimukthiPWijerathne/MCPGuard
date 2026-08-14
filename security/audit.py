import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
LOG_DIR = PROJECT_ROOT / "logs"
LOG_FILE = LOG_DIR / "security_events.jsonl"


def write_audit_event(
    *,
    user_id: str,
    role: str,
    tool: str,
    arguments: dict[str, Any],
    decision: str,
    risk_score: int,
    risk_level: str,
    reason: str,
) -> None:
    """
    Write one security event as a JSON Lines record.
    """

    LOG_DIR.mkdir(parents=True, exist_ok=True)

    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "user_id": user_id,
        "role": role,
        "tool": tool,
        "arguments": arguments,
        "decision": decision,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "reason": reason,
    }

    with LOG_FILE.open("a", encoding="utf-8") as file:
        file.write(json.dumps(event) + "\n")





## this file used for write the audit event.logs/
## └── security_events.jsonl

## {
## "timestamp": "...",
##  "user_id": "user001",
##  "role": "viewer",
##  "tool": "delete_file",
##  "arguments": {
##    "path": "notes.txt"
##  },
##  "decision": "BLOCK",
##  "risk_score": 90,
##  "risk_level": "CRITICAL",
##  "reason": "user 'user001' ..."
##}