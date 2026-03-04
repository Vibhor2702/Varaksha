"""Snapshot and rollback support.

Git repos: uses git stash / unstaged-diff approach.
Non-git: copies files to .gate_snapshots/{uuid}/.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
import uuid
from pathlib import Path

logger = logging.getLogger(__name__)


class SnapshotManager:
    def __init__(self, project_root: str) -> None:
        self.project_root = Path(project_root).resolve()
        self._is_git = (self.project_root / ".git").exists()
        self._snapshot_dir = self.project_root / ".gate_snapshots"
        self._snapshot_dir.mkdir(exist_ok=True)
        self._snapshots: list[str] = []  # ordered list of snapshot_ids

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    def take_snapshot(self, files: list[str]) -> str:
        snapshot_id = str(uuid.uuid4())
        if self._is_git:
            self._git_snapshot(snapshot_id)
        else:
            self._file_snapshot(snapshot_id, files)
        self._snapshots.append(snapshot_id)
        logger.debug("Snapshot taken: %s", snapshot_id)
        return snapshot_id

    def rollback(self, snapshot_id: str) -> None:
        if self._is_git:
            self._git_rollback(snapshot_id)
        else:
            self._file_rollback(snapshot_id)
        logger.info("Rolled back to snapshot %s", snapshot_id)

    def cleanup_old_snapshots(self, keep_last_n: int = 10) -> None:
        to_remove = self._snapshots[:-keep_last_n] if len(self._snapshots) > keep_last_n else []
        for sid in to_remove:
            snap_path = self._snapshot_dir / sid
            if snap_path.exists():
                shutil.rmtree(snap_path)
            self._snapshots.remove(sid)

    # ------------------------------------------------------------------ #
    # Git-based snapshots
    # ------------------------------------------------------------------ #

    def _git_snapshot(self, snapshot_id: str) -> None:
        # Store the current HEAD SHA and the unstaged diff
        snap_path = self._snapshot_dir / snapshot_id
        snap_path.mkdir(parents=True)

        head = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=self.project_root, capture_output=True, text=True
        )
        (snap_path / "HEAD").write_text(head.stdout.strip())

        diff = subprocess.run(
            ["git", "diff", "HEAD"],
            cwd=self.project_root, capture_output=True, text=True
        )
        (snap_path / "unstaged.diff").write_text(diff.stdout)

    def _git_rollback(self, snapshot_id: str) -> None:
        snap_path = self._snapshot_dir / snapshot_id
        head_sha = (snap_path / "HEAD").read_text().strip()
        unstaged_diff = (snap_path / "unstaged.diff").read_text()

        # Hard reset to recorded HEAD
        subprocess.run(
            ["git", "reset", "--hard", head_sha],
            cwd=self.project_root, check=True
        )
        # Re-apply unstaged changes if any
        if unstaged_diff.strip():
            proc = subprocess.run(
                ["git", "apply", "--whitespace=fix"],
                input=unstaged_diff, text=True,
                cwd=self.project_root, capture_output=True
            )
            if proc.returncode != 0:
                logger.warning("git apply during rollback had issues: %s", proc.stderr)

    # ------------------------------------------------------------------ #
    # File-based snapshots (non-git repos)
    # ------------------------------------------------------------------ #

    def _file_snapshot(self, snapshot_id: str, files: list[str]) -> None:
        snap_path = self._snapshot_dir / snapshot_id
        snap_path.mkdir(parents=True)
        for rel in files:
            src = self.project_root / rel
            if not src.exists():
                continue
            dst = snap_path / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)

    def _file_rollback(self, snapshot_id: str) -> None:
        snap_path = self._snapshot_dir / snapshot_id
        if not snap_path.exists():
            logger.error("Snapshot %s not found", snapshot_id)
            return
        for src in snap_path.rglob("*"):
            if src.is_file():
                rel = src.relative_to(snap_path)
                dst = self.project_root / rel
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, dst)
