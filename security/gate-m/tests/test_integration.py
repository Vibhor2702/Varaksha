"""Full kernel integration tests — realistic agent scenarios.

Tests the complete pipeline: token → kernel → sip → verifier (mocked) → invariants.

Scenarios:
  1. Happy path — clean write, approved, invariants pass
  2. Retry exhaustion — agent keeps sending bad diffs, budget hits zero
  3. TTL expiry — token expires mid-session
  4. Snapshot + rollback — invariant failure triggers rollback
  5. Hash invariant protection — protected file modified → rollback
  6. Test gate — must_pass_tests enforced post-write
  7. Hard stop bypasses retry budget — user notified immediately
  8. Read gate — agents can't read outside read_scope
"""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from gate.kernel import GATEKernel
from gate.models import (
    ApprovalResult, CapabilityToken, IntentDeclaration,
    RejectionResult, ToolCall,
)


# ── fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture()
def project(tmp_path: Path):
    """Create a minimal project structure in a temp dir."""
    src = tmp_path / "src"
    src.mkdir()
    tests = tmp_path / "tests"
    tests.mkdir()
    secrets = tmp_path / "secrets"
    secrets.mkdir()

    (src / "auth.py").write_text(
        "def validate_user(user):\n    return user.is_active\n"
    )
    (src / "models.py").write_text(
        "class User:\n    def __init__(self):\n        self.is_active = True\n"
    )
    (src / "config.py").write_text("DEBUG = False\nSECRET_KEY = 'changeme'\n")
    (secrets / "db.key").write_text("top_secret\n")

    # Passing test suite
    (tests / "test_auth.py").write_text(
        "import sys, os\n"
        "sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))\n"
        "from src.auth import validate_user\n"
        "from src.models import User\n"
        "def test_pass():\n"
        "    u = User()\n"
        "    assert validate_user(u) is True\n"
    )
    # Failing test suite (for gate-failure scenarios)
    (tests / "test_always_fail.py").write_text(
        "def test_fail():\n    assert False, 'intentional failure'\n"
    )
    return tmp_path


def make_token(
    project_root: str,
    write_scope: list[str] | None = None,
    forbidden: list[str] | None = None,
    retry_budget: int = 3,
    ttl_minutes: int = 30,
    must_pass_tests: list[str] | None = None,
    must_not_change: dict[str, str] | None = None,
    created_at: datetime | None = None,
) -> CapabilityToken:
    tok = CapabilityToken(
        task_id="integ-test",
        natural_language_goal="fix null check in validate_user",
        read_scope=["src/**", "tests/**"],
        write_scope=write_scope or ["src/auth.py"],
        forbidden=forbidden or ["secrets/**", ".env"],
        allowed_edit_categories=["modify", "add", "delete", "refactor"],
        allowed_new_files=False,
        allowed_new_dependencies=False,
        retry_budget=retry_budget,
        ttl_minutes=ttl_minutes,
        created_at=created_at or datetime.utcnow(),
        must_pass_tests=must_pass_tests or [],
        must_not_change=must_not_change or {},
    )
    return tok


def make_kernel(token: CapabilityToken, project_root: str) -> GATEKernel:
    return GATEKernel(
        token=token,
        project_root=project_root,
        groq_key="",
        gemini_key="",
    )


CLEAN_DIFF = """\
--- a/src/auth.py
+++ b/src/auth.py
@@ -1,4 +1,7 @@
 def validate_user(user):
-    return user.is_active
+    if user is None:
+        return False
+    return user.is_active
"""

CLEAN_INTENT = IntentDeclaration(
    intent="add null guard",
    affected_scope=["src/auth.py::validate_user"],
    edit_category="modify",
    expected_postcondition="returns False for None",
)

BAD_DIFF_SUBPROCESS = """\
--- a/src/auth.py
+++ b/src/auth.py
@@ -1,4 +1,7 @@
+import subprocess
 def validate_user(user):
-    return user.is_active
+    subprocess.run(["id"])
+    return user.is_active
"""


# ═══════════════════════════════════════════════════════════════════════════
# 1. HAPPY PATH
# ═══════════════════════════════════════════════════════════════════════════

class TestHappyPath:
    def test_clean_write_approved(self, project):
        tok = make_token(str(project))
        kernel = make_kernel(tok, str(project))
        tc = ToolCall(
            tool_type="write",
            path="src/auth.py",
            proposed_diff=CLEAN_DIFF,
            intent=CLEAN_INTENT,
        )
        result = kernel.execute_tool(tc)
        assert isinstance(result, ApprovalResult)
        assert result.approved is True
        assert result.snapshot_id is not None
        kernel.shutdown()

    def test_read_in_scope_approved(self, project):
        tok = make_token(str(project))
        kernel = make_kernel(tok, str(project))
        result = kernel.execute_tool(ToolCall(tool_type="read", path="src/auth.py"))
        assert isinstance(result, ApprovalResult)
        assert result.approved is True
        kernel.shutdown()

    def test_exec_safe_command_approved(self, project):
        tok = make_token(str(project))
        kernel = make_kernel(tok, str(project))
        result = kernel.execute_tool(ToolCall(tool_type="exec", command="python --version"))
        assert isinstance(result, ApprovalResult)
        kernel.shutdown()

    def test_session_log_written(self, project):
        tok = make_token(str(project))
        kernel = make_kernel(tok, str(project))
        kernel.execute_tool(ToolCall(tool_type="read", path="src/auth.py"))
        kernel.shutdown()
        log_path = project / ".gate_logs" / f"{tok.task_id}.jsonl"
        assert log_path.exists()
        assert log_path.stat().st_size > 0


# ═══════════════════════════════════════════════════════════════════════════
# 2. RETRY EXHAUSTION
# ═══════════════════════════════════════════════════════════════════════════

class TestRetryExhaustion:
    def test_retry_budget_decrements_on_soft_reject(self, project, capsys):
        tok = make_token(str(project), retry_budget=3)
        kernel = make_kernel(tok, str(project))

        # Out-of-scope diff → layer 1 soft reject
        bad_tc = ToolCall(
            tool_type="write",
            path="src/auth.py",
            proposed_diff="""\
--- a/src/models.py
+++ b/src/models.py
@@ -1,3 +1,4 @@
 class User:
+    evil = True
""",
            intent=CLEAN_INTENT,
        )

        r1 = kernel.execute_tool(bad_tc)
        assert isinstance(r1, RejectionResult)
        assert r1.retries_remaining == 3  # set from budget before decrement

        r2 = kernel.execute_tool(bad_tc)
        assert isinstance(r2, RejectionResult)

        r3 = kernel.execute_tool(bad_tc)
        assert isinstance(r3, RejectionResult)

        # Budget should now be 0 — escalation printed
        out = capsys.readouterr().out
        assert "ESCALATION" in out or "exhausted" in out.lower() or tok.retry_budget == 0
        kernel.shutdown()

    def test_hard_stop_does_not_decrement_budget(self, project):
        tok = make_token(str(project), retry_budget=3)
        kernel = make_kernel(tok, str(project))

        hard_tc = ToolCall(
            tool_type="write",
            path="src/auth.py",
            proposed_diff=BAD_DIFF_SUBPROCESS,
            intent=IntentDeclaration(
                intent="add subprocess",
                affected_scope=["src/auth.py"],
                edit_category="modify",
                expected_postcondition="runs subprocess",
            ),
        )
        result = kernel.execute_tool(hard_tc)
        assert isinstance(result, RejectionResult)
        assert result.is_hard_stop is True
        # Hard stop should NOT consume retry budget
        assert tok.retry_budget == 3
        kernel.shutdown()


# ═══════════════════════════════════════════════════════════════════════════
# 3. TTL EXPIRY
# ═══════════════════════════════════════════════════════════════════════════

class TestTTLExpiry:
    def test_expired_token_hard_stop(self, project, capsys):
        expired_time = datetime.utcnow() - timedelta(minutes=60)
        tok = make_token(str(project), ttl_minutes=30, created_at=expired_time)
        kernel = make_kernel(tok, str(project))

        result = kernel.execute_tool(ToolCall(
            tool_type="write",
            path="src/auth.py",
            proposed_diff=CLEAN_DIFF,
            intent=CLEAN_INTENT,
        ))
        assert isinstance(result, RejectionResult)
        assert result.is_hard_stop is True
        assert "expired" in result.violation_detail.lower()
        kernel.shutdown()

    def test_active_token_not_expired(self, project):
        tok = make_token(str(project), ttl_minutes=30)
        kernel = make_kernel(tok, str(project))
        assert not tok.is_expired()
        kernel.shutdown()


# ═══════════════════════════════════════════════════════════════════════════
# 4. SNAPSHOT + ROLLBACK
# ═══════════════════════════════════════════════════════════════════════════

class TestSnapshotRollback:
    def test_snapshot_created_on_write(self, project):
        tok = make_token(str(project))
        kernel = make_kernel(tok, str(project))
        result = kernel.execute_tool(ToolCall(
            tool_type="write",
            path="src/auth.py",
            proposed_diff=CLEAN_DIFF,
            intent=CLEAN_INTENT,
        ))
        assert isinstance(result, ApprovalResult)
        snap_dir = project / ".gate_snapshots" / result.snapshot_id
        assert snap_dir.exists()
        kernel.shutdown()

    def test_rollback_restores_file(self, project):
        original = (project / "src" / "auth.py").read_text()
        tok = make_token(str(project))
        kernel = make_kernel(tok, str(project))

        result = kernel.execute_tool(ToolCall(
            tool_type="write",
            path="src/auth.py",
            proposed_diff=CLEAN_DIFF,
            intent=CLEAN_INTENT,
        ))
        assert isinstance(result, ApprovalResult)
        snapshot_id = result.snapshot_id

        # Simulate agent applying the write (corrupt the file)
        (project / "src" / "auth.py").write_text("# corrupted\n")

        # Rollback
        kernel._snapshot_mgr.rollback(snapshot_id)
        restored = (project / "src" / "auth.py").read_text()
        assert restored == original
        kernel.shutdown()


# ═══════════════════════════════════════════════════════════════════════════
# 5. HASH INVARIANT PROTECTION
# ═══════════════════════════════════════════════════════════════════════════

class TestHashInvariant:
    def _sha256(self, path: str) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            h.update(f.read())
        return h.hexdigest()

    def test_protected_file_unchanged_passes(self, project):
        config_path = str(project / "src" / "config.py")
        config_hash = self._sha256(config_path)

        tok = make_token(
            str(project),
            must_not_change={"src/config.py": config_hash},
        )
        kernel = make_kernel(tok, str(project))
        result = kernel.execute_tool(ToolCall(
            tool_type="write",
            path="src/auth.py",
            proposed_diff=CLEAN_DIFF,
            intent=CLEAN_INTENT,
        ))
        assert isinstance(result, ApprovalResult)
        snap_id = result.snapshot_id

        # Apply write (doesn't touch config.py)
        (project / "src" / "auth.py").write_text(
            "def validate_user(user):\n"
            "    if user is None: return False\n"
            "    return user.is_active\n"
        )
        inv_result = kernel.run_invariant_checks(snap_id)
        assert isinstance(inv_result, ApprovalResult)
        kernel.shutdown()

    def test_protected_file_modified_triggers_rollback(self, project):
        config_path = str(project / "src" / "config.py")
        config_hash = self._sha256(config_path)

        tok = make_token(
            str(project),
            must_not_change={"src/config.py": config_hash},
        )
        kernel = make_kernel(tok, str(project))
        result = kernel.execute_tool(ToolCall(
            tool_type="write",
            path="src/auth.py",
            proposed_diff=CLEAN_DIFF,
            intent=CLEAN_INTENT,
        ))
        snap_id = result.snapshot_id

        # Agent secretly modifies config.py too
        (project / "src" / "config.py").write_text("SECRET_KEY = 'stolen'\n")
        (project / "src" / "auth.py").write_text("# modified\n")

        inv_result = kernel.run_invariant_checks(snap_id)
        assert isinstance(inv_result, RejectionResult)
        assert inv_result.is_hard_stop is True
        assert "config.py" in inv_result.violation_detail

        # auth.py should be rolled back to original
        auth_content = (project / "src" / "auth.py").read_text()
        assert "validate_user" in auth_content  # original content restored
        kernel.shutdown()


# ═══════════════════════════════════════════════════════════════════════════
# 6. TEST GATE
# ═══════════════════════════════════════════════════════════════════════════

class TestTestGate:
    def test_passing_tests_allow_write(self, project):
        tok = make_token(
            str(project),
            must_pass_tests=["tests/test_auth.py"],
        )
        kernel = make_kernel(tok, str(project))
        result = kernel.execute_tool(ToolCall(
            tool_type="write",
            path="src/auth.py",
            proposed_diff=CLEAN_DIFF,
            intent=CLEAN_INTENT,
        ))
        assert isinstance(result, ApprovalResult)
        snap_id = result.snapshot_id

        # Apply a compatible write (tests still pass)
        (project / "src" / "auth.py").write_text(
            "def validate_user(user):\n"
            "    if user is None: return False\n"
            "    return user.is_active\n"
        )
        inv_result = kernel.run_invariant_checks(snap_id)
        assert isinstance(inv_result, ApprovalResult)
        kernel.shutdown()

    def test_failing_tests_trigger_rollback(self, project):
        original_auth = (project / "src" / "auth.py").read_text()
        tok = make_token(
            str(project),
            must_pass_tests=["tests/test_auth.py"],
        )
        kernel = make_kernel(tok, str(project))
        result = kernel.execute_tool(ToolCall(
            tool_type="write",
            path="src/auth.py",
            proposed_diff=CLEAN_DIFF,
            intent=CLEAN_INTENT,
        ))
        snap_id = result.snapshot_id

        # Break validate_user so test fails
        (project / "src" / "auth.py").write_text(
            "def validate_user(user):\n    return None  # broken\n"
        )
        inv_result = kernel.run_invariant_checks(snap_id)
        assert isinstance(inv_result, RejectionResult)
        assert inv_result.is_hard_stop is True
        assert "test" in inv_result.violation_detail.lower()

        # File must be rolled back
        restored = (project / "src" / "auth.py").read_text()
        assert restored == original_auth
        kernel.shutdown()


# ═══════════════════════════════════════════════════════════════════════════
# 7. HARD STOP — user notified, no retry consumed
# ═══════════════════════════════════════════════════════════════════════════

class TestHardStop:
    def test_forbidden_read_hard_stop(self, project, capsys):
        tok = make_token(str(project))
        kernel = make_kernel(tok, str(project))
        result = kernel.execute_tool(ToolCall(
            tool_type="read",
            path="secrets/db.key",
        ))
        assert isinstance(result, RejectionResult)
        assert result.is_hard_stop is True
        out = capsys.readouterr().out
        assert "HARD STOP" in out
        kernel.shutdown()

    def test_subprocess_in_diff_hard_stop(self, project, capsys):
        tok = make_token(str(project), retry_budget=3)
        kernel = make_kernel(tok, str(project))
        result = kernel.execute_tool(ToolCall(
            tool_type="write",
            path="src/auth.py",
            proposed_diff=BAD_DIFF_SUBPROCESS,
            intent=IntentDeclaration(
                intent="validate",
                affected_scope=["src/auth.py"],
                edit_category="modify",
                expected_postcondition="done",
            ),
        ))
        assert isinstance(result, RejectionResult)
        assert result.is_hard_stop is True
        assert result.layer_failed == 3
        # Budget not consumed by hard stop
        assert tok.retry_budget == 3
        kernel.shutdown()

    def test_exec_forbidden_path_hard_stop(self, project, capsys):
        tok = make_token(str(project))
        kernel = make_kernel(tok, str(project))
        result = kernel.execute_tool(ToolCall(
            tool_type="exec",
            command="cat secrets/db.key",
        ))
        assert isinstance(result, RejectionResult)
        assert result.is_hard_stop is True
        kernel.shutdown()


# ═══════════════════════════════════════════════════════════════════════════
# 8. READ GATE
# ═══════════════════════════════════════════════════════════════════════════

class TestReadGate:
    def test_read_out_of_scope_rejected(self, project):
        tok = make_token(str(project))
        kernel = make_kernel(tok, str(project))
        result = kernel.execute_tool(ToolCall(tool_type="read", path="config/app.yaml"))
        assert isinstance(result, RejectionResult)
        assert result.is_hard_stop is False  # soft reject
        kernel.shutdown()

    def test_read_forbidden_hard_stop(self, project):
        tok = make_token(str(project))
        kernel = make_kernel(tok, str(project))
        result = kernel.execute_tool(ToolCall(tool_type="read", path="secrets/db.key"))
        assert isinstance(result, RejectionResult)
        assert result.is_hard_stop is True
        kernel.shutdown()

    def test_read_in_scope_approved(self, project):
        tok = make_token(str(project))
        kernel = make_kernel(tok, str(project))
        result = kernel.execute_tool(ToolCall(tool_type="read", path="src/auth.py"))
        assert isinstance(result, ApprovalResult)
        kernel.shutdown()

    def test_read_tests_dir_approved(self, project):
        tok = make_token(str(project))
        kernel = make_kernel(tok, str(project))
        result = kernel.execute_tool(ToolCall(tool_type="read", path="tests/test_auth.py"))
        assert isinstance(result, ApprovalResult)
        kernel.shutdown()


# ═══════════════════════════════════════════════════════════════════════════
# 9. REALISTIC AGENT SESSION SIMULATION
# ═══════════════════════════════════════════════════════════════════════════

class TestRealisticSession:
    """Simulate a full agent task: read → plan → write → invariant check."""

    def test_full_session_good_agent(self, project):
        """A well-behaved agent completes the task successfully."""
        tok = make_token(
            str(project),
            must_pass_tests=["tests/test_auth.py"],
        )
        kernel = make_kernel(tok, str(project))

        # Step 1: agent reads the file
        r1 = kernel.execute_tool(ToolCall(tool_type="read", path="src/auth.py"))
        assert isinstance(r1, ApprovalResult)

        # Step 2: agent reads the tests
        r2 = kernel.execute_tool(ToolCall(tool_type="read", path="tests/test_auth.py"))
        assert isinstance(r2, ApprovalResult)

        # Step 3: agent submits a write
        r3 = kernel.execute_tool(ToolCall(
            tool_type="write",
            path="src/auth.py",
            proposed_diff=CLEAN_DIFF,
            intent=CLEAN_INTENT,
        ))
        assert isinstance(r3, ApprovalResult)
        snap_id = r3.snapshot_id

        # Step 4: agent applies the write
        (project / "src" / "auth.py").write_text(
            "def validate_user(user):\n"
            "    if user is None: return False\n"
            "    return user.is_active\n"
        )

        # Step 5: invariant check
        r4 = kernel.run_invariant_checks(snap_id)
        assert isinstance(r4, ApprovalResult)
        kernel.shutdown()

    def test_full_session_bad_agent_escalated(self, project, capsys):
        """A bad agent exhausts its retry budget and gets escalated."""
        tok = make_token(str(project), retry_budget=2)
        kernel = make_kernel(tok, str(project))

        # Bad diff: out of scope
        bad_diff = """\
--- a/src/models.py
+++ b/src/models.py
@@ -1,3 +1,4 @@
 class User:
+    backdoor = True
"""
        bad_tc = ToolCall(
            tool_type="write",
            path="src/models.py",
            proposed_diff=bad_diff,
            intent=CLEAN_INTENT,
        )

        r1 = kernel.execute_tool(bad_tc)
        assert isinstance(r1, RejectionResult)

        r2 = kernel.execute_tool(bad_tc)
        assert isinstance(r2, RejectionResult)

        # Budget now zero — escalation message printed
        out = capsys.readouterr().out
        assert "ESCALATION" in out
        kernel.shutdown()
