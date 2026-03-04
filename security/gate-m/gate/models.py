"""Shared dataclasses for GATE-M."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class CapabilityToken:
    task_id: str
    natural_language_goal: str
    read_scope: list[str]        # glob patterns e.g. ["src/**", "tests/**"]
    write_scope: list[str]       # specific files only, no globs
    forbidden: list[str]         # glob patterns, hard block
    allowed_edit_categories: list[str]  # ["modify", "add", "delete", "refactor"]
    allowed_new_files: bool
    allowed_new_dependencies: bool
    retry_budget: int
    ttl_minutes: int
    created_at: datetime
    must_pass_tests: list[str]   # test paths to run post-write
    must_not_change: dict[str, str]  # filepath -> sha256 hash

    @classmethod
    def create(
        cls,
        natural_language_goal: str,
        read_scope: list[str],
        write_scope: list[str],
        forbidden: list[str] | None = None,
        allowed_edit_categories: list[str] | None = None,
        allowed_new_files: bool = False,
        allowed_new_dependencies: bool = False,
        retry_budget: int = 3,
        ttl_minutes: int = 30,
        must_pass_tests: list[str] | None = None,
        must_not_change: dict[str, str] | None = None,
    ) -> "CapabilityToken":
        return cls(
            task_id=str(uuid.uuid4()),
            natural_language_goal=natural_language_goal,
            read_scope=read_scope,
            write_scope=write_scope,
            forbidden=forbidden or [],
            allowed_edit_categories=allowed_edit_categories or ["modify", "add", "delete", "refactor"],
            allowed_new_files=allowed_new_files,
            allowed_new_dependencies=allowed_new_dependencies,
            retry_budget=retry_budget,
            ttl_minutes=ttl_minutes,
            created_at=datetime.utcnow(),
            must_pass_tests=must_pass_tests or [],
            must_not_change=must_not_change or {},
        )

    def is_expired(self) -> bool:
        from datetime import timezone, timedelta
        now = datetime.utcnow()
        elapsed = now - self.created_at
        return elapsed > timedelta(minutes=self.ttl_minutes)


@dataclass
class IntentDeclaration:
    intent: str
    affected_scope: list[str]    # e.g. ["src/auth.py::validate_user"]
    edit_category: str           # "add" | "modify" | "delete" | "refactor"
    expected_postcondition: str


@dataclass
class ToolCall:
    tool_type: str               # "read" | "write" | "exec" | "pool"
    path: Optional[str] = None
    command: Optional[str] = None
    intent: Optional[IntentDeclaration] = None
    proposed_diff: Optional[str] = None


@dataclass
class RejectionResult:
    rejection_reason: str
    layer_failed: int            # 1=scope, 2=category, 3=side_effects, 4=invariant, 5=verifier
    violation_detail: str
    kernel_suggestion: str
    retries_remaining: int
    is_hard_stop: bool = False


@dataclass
class ApprovalResult:
    approved: bool
    snapshot_id: Optional[str] = None
