from dataclasses import dataclass
from typing import Any

from .models import ResourceSensitivity, RiskLevel, Role


@dataclass
class RiskAssessment:
    score: int
    level: RiskLevel
    reasons: list[str]


# ------------------------------------------------------------
# Base risk by tool
# ------------------------------------------------------------

TOOL_RISK = {
    "list_files": 10,
    "read_file": 20,
    "create_file": 40,
    "write_file": 60,
    "delete_file": 80,
}


# ------------------------------------------------------------
# Additional risk by resource sensitivity
# ------------------------------------------------------------

RESOURCE_RISK = {
    ResourceSensitivity.PUBLIC: 0,
    ResourceSensitivity.PRIVATE: 20,
    ResourceSensitivity.SECRET: 50,
    ResourceSensitivity.OUTSIDE_SANDBOX: 100,
}


# ------------------------------------------------------------
# Role/context modifiers
# ------------------------------------------------------------

ROLE_MODIFIER = {
    Role.VIEWER: 0,
    Role.DEVELOPER: 0,
    Role.ADMIN: -10,
}


def calculate_risk(
    *,
    tool_name: str,
    role: Role,
    resource: ResourceSensitivity | None = None,
    arguments: dict[str, Any] | None = None,
) -> RiskAssessment:

    arguments = arguments or {}

    score = TOOL_RISK.get(tool_name, 100)
    reasons: list[str] = []

    reasons.append(
        f"base tool risk={score}"
    )

    # --------------------------------------------------------
    # Resource sensitivity
    # --------------------------------------------------------

    if resource is not None:

        resource_modifier = RESOURCE_RISK[resource]

        score += resource_modifier

        if resource_modifier > 0:
            reasons.append(
                f"resource sensitivity +{resource_modifier}"
            )

    # --------------------------------------------------------
    # Role
    # --------------------------------------------------------

    role_modifier = ROLE_MODIFIER[role]

    if role_modifier != 0:

        score += role_modifier

        reasons.append(
            f"role modifier {role_modifier}"
        )

    # --------------------------------------------------------
    # Destructive operation
    # --------------------------------------------------------

    if tool_name == "delete_file":

        score += 10

        reasons.append(
            "destructive operation +10"
        )

    # --------------------------------------------------------
    # Large content modification
    # --------------------------------------------------------

    content = arguments.get("content")

    if isinstance(content, str):

        if len(content) > 10_000:

            score += 10

            reasons.append(
                "large content payload +10"
            )

    # --------------------------------------------------------
    # Suspicious path characteristics
    # --------------------------------------------------------

    path = arguments.get("path")

    if isinstance(path, str):

        if ".." in path:

            score += 30

            reasons.append(
                "parent-directory reference +30"
            )

    # --------------------------------------------------------
    # Clamp score
    # --------------------------------------------------------

    score = max(0, min(score, 100))

    return RiskAssessment(
        score=score,
        level=_risk_level(score),
        reasons=reasons,
    )


def _risk_level(score: int) -> RiskLevel:

    if score <= 30:
        return RiskLevel.LOW

    if score <= 60:
        return RiskLevel.MEDIUM

    if score <= 80:
        return RiskLevel.HIGH

    return RiskLevel.CRITICAL