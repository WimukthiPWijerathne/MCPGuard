from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Role(str, Enum):
    VIEWER = "viewer"
    DEVELOPER = "developer"
    ADMIN = "admin"


class Decision(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    APPROVAL = "APPROVAL"


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class User:
    user_id: str
    role: Role


@dataclass
class SecurityDecision:
    decision: Decision
    risk_score: int
    risk_level: RiskLevel
    reason: str
    metadata: dict[str, Any] = field(default_factory=dict)