# security/taint.py
import datetime
from enum import Enum
from dataclasses import dataclass, field
from typing import Optional


class TaintStatus(str, Enum):
    CLEAN = "CLEAN"
    TAINTED = "TAINTED"


@dataclass
class TaintRecord:
    source: str
    timestamp: str
    reason: str


@dataclass
class SessionState:
    session_id: str
    status: TaintStatus = TaintStatus.CLEAN
    taint_trail: list[TaintRecord] = field(default_factory=list)

    def mark_tainted(self, source: str, reason: str) -> None:
        self.status = TaintStatus.TAINTED
        self.taint_trail.append(
            TaintRecord(
                source=source,
                timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                reason=reason
            )
        )

    def clear_taint(self) -> None:
        self.status = TaintStatus.CLEAN
        self.taint_trail.clear()


class TaintTracker:
    """Manages cross-turn session taint tracking to prevent delayed cascading attacks."""
    _sessions: dict[str, SessionState] = {}

    @classmethod
    def get_or_create(cls, session_id: str) -> SessionState:
        if session_id not in cls._sessions:
            cls._sessions[session_id] = SessionState(session_id=session_id)
        return cls._sessions[session_id]

    @classmethod
    def evaluate_action(
        cls,
        session_id: str,
        tool_name: str,
        resource_classification: str
    ) -> tuple[bool, Optional[str]]:
        """
        Enforces policy restrictions if the session context has been tainted by prior turns.
        """
        session = cls.get_or_create(session_id)

        if session.status == TaintStatus.TAINTED:
            # Dangerous tools blocked when context is tainted
            restricted_tools = ["delete_file", "write_file", "execute_command", "send_request"]
            
            if tool_name in restricted_tools:
                taint_source = session.taint_trail[-1].source if session.taint_trail else "Unknown"
                return (
                    False,
                    f"Taint Violation: Session tainted by prior ingestion of '{taint_source}'. "
                    f"State-modifying tool '{tool_name}' is locked."
                )

            if resource_classification in ["SECRET", "PRIVATE"]:
                return (
                    False,
                    f"Taint Violation: Tainted session prohibited from accessing {resource_classification} resources."
                )

        return True, None

    @classmethod
    def reset_all(cls) -> None:
        cls._sessions.clear()