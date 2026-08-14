from enum import Enum
from pathlib import Path


class ResourceSensitivity(str, Enum):
    PUBLIC = "PUBLIC"
    PRIVATE = "PRIVATE"
    SECRET = "SECRET"
    OUTSIDE_SANDBOX = "OUTSIDE_SANDBOX"


PROJECT_ROOT = Path(__file__).resolve().parents[1]
LAB_ROOT = (PROJECT_ROOT / "sandbox").resolve()
WORKSPACE_ROOT = (LAB_ROOT / "public").resolve()


def classify_path(user_path: str) -> ResourceSensitivity:
    """
    Classify a path according to the MCPGuard sandbox model.

    The vulnerable filesystem server interprets paths relative
    to sandbox/public/.
    """

    candidate = (WORKSPACE_ROOT / user_path).resolve()

    # Anything outside the complete sandbox is forbidden.
    try:
        relative_to_lab = candidate.relative_to(LAB_ROOT)
    except ValueError:
        return ResourceSensitivity.OUTSIDE_SANDBOX

    # Resource classification is based on the resolved location.
    parts = relative_to_lab.parts

    if not parts:
        return ResourceSensitivity.OUTSIDE_SANDBOX

    top_level = parts[0].lower()

    if top_level == "public":
        return ResourceSensitivity.PUBLIC

    if top_level == "private":
        return ResourceSensitivity.PRIVATE

    if top_level == "secrets":
        return ResourceSensitivity.SECRET

    # Anything else inside the sandbox is private by default.
    return ResourceSensitivity.PRIVATE