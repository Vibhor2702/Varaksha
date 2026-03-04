"""CapabilityToken validation helpers."""

from __future__ import annotations

import hashlib
from pathlib import Path

from .models import CapabilityToken, RejectionResult


def validate_token(token: CapabilityToken) -> list[str]:
    """Return list of validation error strings (empty = valid)."""
    errors: list[str] = []

    if not token.task_id:
        errors.append("task_id is required")
    if not token.natural_language_goal:
        errors.append("natural_language_goal is required")
    if not token.read_scope and not token.write_scope:
        errors.append("At least one of read_scope or write_scope must be non-empty")
    if token.retry_budget < 0:
        errors.append("retry_budget must be >= 0")
    if token.ttl_minutes <= 0:
        errors.append("ttl_minutes must be > 0")

    valid_categories = {"modify", "add", "delete", "refactor"}
    bad = set(token.allowed_edit_categories) - valid_categories
    if bad:
        errors.append(f"Unknown edit categories: {bad}")

    return errors


def compute_file_hash(path: str) -> str:
    """Return SHA-256 hex digest of a file's contents."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def build_must_not_change(paths: list[str]) -> dict[str, str]:
    """Snapshot current hashes for the given paths."""
    result: dict[str, str] = {}
    for p in paths:
        if Path(p).exists():
            result[p] = compute_file_hash(p)
    return result
