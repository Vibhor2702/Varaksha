"""GATEKernel — main entry point.

The kernel never applies writes itself. It approves or rejects.
The agent applies the write after receiving an ApprovalResult.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import logging
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Union

from .corrector import CorrectionInjector
from .models import ApprovalResult, CapabilityToken, RejectionResult, ToolCall
from .os_watcher import OSWatcher
from .sip_checker import SIPChecker
from .snapshot import SnapshotManager
from .verifier import VerifierClient, count_diff_lines

logger = logging.getLogger(__name__)


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _matches_any(path: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(path, p) for p in patterns)


def _extract_touched_files(diff: str) -> list[str]:
    """Quick extraction of filenames from a unified diff header."""
    files: list[str] = []
    for line in diff.splitlines():
        if line.startswith("+++ "):
            path = line[4:].strip()
            if path.startswith(("b/", "a/")):
                path = path[2:]
            if path != "/dev/null":
                files.append(path)
    return files or []


class GATEKernel:
    def __init__(
        self,
        token: CapabilityToken,
        project_root: str,
        groq_key: str,
        gemini_key: str,
    ) -> None:
        self.token = token
        self.project_root = Path(project_root).resolve()
        self._session_log: list[dict] = []
        self._log_dir = self.project_root / ".gate_logs"
        self._log_dir.mkdir(exist_ok=True)
        self._log_path = self._log_dir / f"{token.task_id}.jsonl"

        self._sip = SIPChecker()
        self._corrector = CorrectionInjector()
        self._snapshot_mgr = SnapshotManager(project_root)
        self._verifier = VerifierClient(groq_key, gemini_key)

        def _on_violation(violation_type: str, path: str) -> None:
            logger.error("OS-level violation: %s → %s", violation_type, path)
            self._log({"type": "os_violation", "violation": violation_type, "path": path})

        self._watcher = OSWatcher(
            project_root=project_root,
            forbidden=token.forbidden,
            write_scope=token.write_scope,
            read_scope=token.read_scope,
            on_violation=_on_violation,
        )

    # ------------------------------------------------------------------ #
    # Main dispatch
    # ------------------------------------------------------------------ #

    def execute_tool(
        self, tool_call: ToolCall
    ) -> Union[ApprovalResult, RejectionResult]:

        # Token TTL
        if self.token.is_expired():
            return self._hard_stop(
                layer=4,
                detail="CapabilityToken has expired",
                suggestion="Start a new gate-m session with a fresh token.",
            )

        if tool_call.tool_type == "read":
            return self._handle_read(tool_call)
        elif tool_call.tool_type == "write":
            return self._handle_write(tool_call)
        elif tool_call.tool_type == "exec":
            return self._handle_exec(tool_call)
        else:
            return self._hard_stop(
                layer=4,
                detail=f"Unknown tool_type: {tool_call.tool_type!r}",
                suggestion="Use one of: read, write, exec, pool",
            )

    # ------------------------------------------------------------------ #
    # Read
    # ------------------------------------------------------------------ #

    def _handle_read(
        self, tool_call: ToolCall
    ) -> Union[ApprovalResult, RejectionResult]:
        path = tool_call.path or ""
        if _matches_any(path, self.token.forbidden):
            return self._hard_stop(
                layer=1,
                detail=f"Read on forbidden path: {path}",
                suggestion="This path is in the forbidden list. Do not access it.",
            )
        in_read_scope = _matches_any(path, self.token.read_scope)
        if not in_read_scope:
            return self._soft_reject(
                layer=1,
                detail=f"Path not in read_scope: {path}",
                suggestion=(
                    f"'{path}' is not covered by read_scope patterns "
                    f"{self.token.read_scope}. Adjust scope or avoid reading this file."
                ),
            )
        self._log({"type": "read_approved", "path": path})
        return ApprovalResult(approved=True)

    # ------------------------------------------------------------------ #
    # Write
    # ------------------------------------------------------------------ #

    def _handle_write(
        self, tool_call: ToolCall
    ) -> Union[ApprovalResult, RejectionResult]:
        diff = tool_call.proposed_diff or ""
        touched = _extract_touched_files(diff) or ([tool_call.path] if tool_call.path else [])

        # 1. Snapshot BEFORE any checks.
        # Always include must_not_change files — they need to be restorable even
        # if the agent tampers with them outside the declared diff.
        protected = list(self.token.must_not_change.keys())
        snapshot_files = list(dict.fromkeys(touched + protected))  # deduplicated
        snapshot_id = self._snapshot_mgr.take_snapshot(snapshot_files)

        # 2. SIP check
        rejection = self._sip.check(tool_call, self.token)
        if rejection:
            rejection.retries_remaining = self.token.retry_budget
            self._log({"type": "sip_rejection", "layer": rejection.layer_failed,
                       "detail": rejection.violation_detail})
            if rejection.is_hard_stop:
                self._notify_user(tool_call, rejection)
                return rejection
            self.token.retry_budget -= 1
            if self.token.retry_budget <= 0:
                self._escalate_to_user(tool_call)
            return rejection

        # 3. LLM verifier (only for large diffs)
        if count_diff_lines(diff) > 20:
            approved, reason = self._verifier.verify(tool_call, self.token)
            if not approved:
                self.token.retry_budget -= 1
                self._log({"type": "verifier_rejection", "reason": reason})
                if self.token.retry_budget <= 0:
                    self._escalate_to_user(tool_call)
                return self._corrector.build(
                    layer=5,
                    detail=reason,
                    suggestion=(
                        "The LLM verifier rejected this diff. "
                        "Review the reason and revise your change."
                    ),
                    retries_remaining=self.token.retry_budget,
                )

        # 4. Approve — caller applies the write
        self._log({"type": "write_approved", "snapshot_id": snapshot_id, "files": touched})
        return ApprovalResult(approved=True, snapshot_id=snapshot_id)

    # ------------------------------------------------------------------ #
    # Post-write invariant checks (called by agent after applying write)
    # ------------------------------------------------------------------ #

    def run_invariant_checks(
        self, snapshot_id: str
    ) -> Union[ApprovalResult, RejectionResult]:
        """Run hash + test invariant checks. Rollback on failure."""

        # Hash invariants
        for path, expected_hash in self.token.must_not_change.items():
            full = self.project_root / path
            if not full.exists():
                self._snapshot_mgr.rollback(snapshot_id)
                return self._hard_stop(
                    layer=4,
                    detail=f"Protected file deleted: {path}",
                    suggestion="Restore the file — it is in must_not_change.",
                )
            actual = _sha256(str(full))
            if actual != expected_hash:
                self._snapshot_mgr.rollback(snapshot_id)
                return self._hard_stop(
                    layer=4,
                    detail=f"Hash mismatch for protected file: {path}",
                    suggestion="The file was unexpectedly modified. Changes rolled back.",
                )

        # Test runner
        for test_path in self.token.must_pass_tests:
            result = subprocess.run(
                ["python", "-m", "pytest", test_path, "-x", "-q"],
                capture_output=True,
                text=True,
                cwd=str(self.project_root),
            )
            if result.returncode != 0:
                self._snapshot_mgr.rollback(snapshot_id)
                output = (result.stdout + result.stderr)[:1000]
                return self._hard_stop(
                    layer=4,
                    detail=f"Tests failed: {test_path}\n{output}",
                    suggestion="Fix the failing tests before re-attempting this write.",
                )

        return ApprovalResult(approved=True, snapshot_id=snapshot_id)

    # ------------------------------------------------------------------ #
    # Exec
    # ------------------------------------------------------------------ #

    def _handle_exec(
        self, tool_call: ToolCall
    ) -> Union[ApprovalResult, RejectionResult]:
        cmd = tool_call.command or ""
        # Extract path-like tokens from the command string and glob-match them
        tokens = cmd.split()
        for tok in tokens:
            for pattern in self.token.forbidden:
                if fnmatch.fnmatch(tok, pattern) or fnmatch.fnmatch(tok, pattern.rstrip("/**") + "*"):
                    return self._hard_stop(
                        layer=3,
                        detail=f"Exec command references forbidden path '{tok}' (matches '{pattern}'): {cmd}",
                        suggestion="Remove references to forbidden paths from the command.",
                    )
        self._log({"type": "exec_approved", "command": cmd})
        return ApprovalResult(approved=True)

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #

    def _hard_stop(self, layer: int, detail: str, suggestion: str) -> RejectionResult:
        result = self._corrector.build(
            layer=layer,
            detail=detail,
            suggestion=suggestion,
            retries_remaining=self.token.retry_budget,
            is_hard_stop=True,
        )
        self._log({"type": "hard_stop", "layer": layer, "detail": detail})
        self._notify_user(None, result)
        return result

    def _soft_reject(self, layer: int, detail: str, suggestion: str) -> RejectionResult:
        self.token.retry_budget -= 1
        result = self._corrector.build(
            layer=layer,
            detail=detail,
            suggestion=suggestion,
            retries_remaining=self.token.retry_budget,
            is_hard_stop=False,
        )
        self._log({"type": "soft_reject", "layer": layer, "detail": detail})
        if self.token.retry_budget <= 0:
            self._escalate_to_user(None)
        return result

    def _notify_user(
        self,
        tool_call: ToolCall | None,
        rejection: RejectionResult,
    ) -> None:
        print("\n[GATE-M HARD STOP]")
        print(f"  Reason : {rejection.rejection_reason}")
        print(f"  Detail : {rejection.violation_detail}")
        print(f"  Suggest: {rejection.kernel_suggestion}")

    def _escalate_to_user(self, tool_call: ToolCall | None) -> None:
        print("\n[GATE-M ESCALATION] Retry budget exhausted.")
        print(f"  Goal: {self.token.natural_language_goal}")
        print(f"  Attempts logged: {len(self._session_log)}")
        print("\n  Options:")
        print("    1. Expand scope / adjust token permissions")
        print("    2. Abandon this task")
        print("    3. Override (use --override flag at your own risk)")
        print("\n  Session log:")
        for entry in self._session_log[-5:]:
            print(f"    {entry}")
        print("\nSession suspended.")

    def _log(self, record: dict) -> None:
        record["ts"] = datetime.utcnow().isoformat()
        self._session_log.append(record)
        with open(self._log_path, "a") as f:
            f.write(json.dumps(record) + "\n")

    def shutdown(self) -> None:
        self._watcher.stop()
        self._snapshot_mgr.cleanup_old_snapshots()
