# security/risk.py
from dataclasses import dataclass
from security.models import Role

@dataclass
class RiskAssessment:
    score: int
    level: str
    decision: str
    reasons: list[str]

# Base tool risks
TOOL_RISK_SCORES: dict[str, int] = {
    "list_files": 10,
    "read_file": 20,
    "create_file": 40,
    "write_file": 60,
    "delete_file": 80,
}

class RiskEngine:
    @staticmethod
    def calculate(
        tool: str,
        role: Role,
        path: str | None = None,
        resource_classification: str = "PUBLIC",
    ) -> RiskAssessment:
        reasons: list[str] = []
        score = TOOL_RISK_SCORES.get(tool, 50)
        reasons.append(f"Base tool risk for '{tool}': {score}")

        # 1. Resource Sensitivity Modifier
        if resource_classification == "SECRET":
            score += 50
            reasons.append("Target is a classified SECRET resource (+50)")
        elif resource_classification == "PRIVATE":
            score += 20
            reasons.append("Target is a classified PRIVATE resource (+20)")

        # 2. Path Traversal & Suspicious Argument Flags
        if path:
            if ".." in path:
                score += 40
                reasons.append("Suspicious relative path detected (+40)")
            if any(p in path.lower() for p in [".env", "id_rsa", "password", "token"]):
                score += 30
                reasons.append("Sensitive file name keyword matched (+30)")

        # 3. Role-based Context Modifiers
        if role == Role.VIEWER and tool in ["create_file", "write_file", "delete_file"]:
            score += 40
            reasons.append("Write/Delete action attempted under Viewer role (+40)")

        # Cap score between 0 and 100
        final_score = max(0, min(100, score))

        # Determine Decision and Level based on V1 Scope
        if final_score <= 30:
            level = "LOW"
            decision = "ALLOW"
        elif final_score <= 60:
            level = "MEDIUM"
            decision = "ALLOW_WITH_AUDIT"
        elif final_score <= 80:
            level = "HIGH"
            decision = "REQUIRE_APPROVAL"
        else:
            level = "CRITICAL"
            decision = "BLOCK"

        return RiskAssessment(
            score=final_score,
            level=level,
            decision=decision,
            reasons=reasons,
        )