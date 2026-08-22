# security/canary.py
import os
import secrets
from pathlib import Path
from dataclasses import dataclass
from typing import Optional


@dataclass
class CanaryToken:
    token: str
    label: str
    created_at: str
    associated_file: Optional[str] = None


class CanaryEngine:
    """Manages synthetic honeypot bait files and detects canary token exfiltration attempts."""

    _active_tokens: dict[str, CanaryToken] = {}
    _honeypot_files: set[str] = set()

    @classmethod
    def generate_token(cls, label: str, associated_file: Optional[str] = None) -> str:
        """Generates a high-entropy tracked canary token."""
        rand_suffix = secrets.token_hex(8)
        token = f"CANARY_MCPGUARD_{label.upper()}_{rand_suffix}"
        cls._active_tokens[token] = CanaryToken(
            token=token,
            label=label,
            created_at=str(os.times()),
            associated_file=associated_file,
        )
        return token

    @classmethod
    def register_honeypot_path(cls, relative_path: str) -> None:
        """Registers a normalized relative path as a tripwire honeypot."""
        normalized = relative_path.replace("\\", "/").strip("/.")
        cls._honeypot_files.add(normalized)

    @classmethod
    def is_honeypot_path(cls, raw_path: Optional[str]) -> tuple[bool, Optional[str]]:
        """Checks if a target path is an active honeypot bait file."""
        if not raw_path:
            return False, None

        normalized = raw_path.replace("\\", "/").strip("/.")
        for bait in cls._honeypot_files:
            if normalized == bait or normalized.endswith(f"/{bait}"):
                return True, bait
        return False, None

    @classmethod
    def detect_canary_leak(cls, payload: str) -> tuple[bool, list[str]]:
        """Scans arbitrary text or argument dictionaries for leaked canary tokens."""
        detected = []
        for token, metadata in cls._active_tokens.items():
            if token in payload:
                detected.append(f"{metadata.label} ({token})")
        return len(detected) > 0, detected

    @classmethod
    def deploy_honeypots(cls, lab_root: Path) -> None:
        """Deploys physical bait files containing tracked canary tokens inside the sandbox."""
        secrets_dir = lab_root / "secrets"
        secrets_dir.mkdir(parents=True, exist_ok=True)

        # Honeypot 1: AWS Production Credentials
        aws_token = cls.generate_token(label="AWS_SECRET_EXFIL", associated_file="secrets/aws_prod_keys.env")
        aws_file = secrets_dir / "aws_prod_keys.env"
        with open(aws_file, "w", encoding="utf-8") as f:
            f.write(
                "# CRITICAL PRODUCTION ROOT KEYS - DO NOT DISTRIBUTE\n"
                f"AWS_ACCESS_KEY_ID=AKIA_MCPGUARD_PROD_ROOT\n"
                f"AWS_SECRET_ACCESS_KEY={aws_token}\n"
                "AWS_DEFAULT_REGION=us-east-1\n"
            )
        cls.register_honeypot_path("secrets/aws_prod_keys.env")

        # Honeypot 2: Master Database Dump
        db_token = cls.generate_token(label="DB_CANARY_DUMP", associated_file="secrets/master_db_backup.sql")
        db_file = secrets_dir / "master_db_backup.sql"
        with open(db_file, "w", encoding="utf-8") as f:
            f.write(
                "-- MASTER USER TABLE DUMP\n"
                f"INSERT INTO users (id, role, canary_hash) VALUES (1, 'superadmin', '{db_token}');\n"
            )
        cls.register_honeypot_path("secrets/master_db_backup.sql")

    @classmethod
    def reset(cls) -> None:
        cls._active_tokens.clear()
        cls._honeypot_files.clear()