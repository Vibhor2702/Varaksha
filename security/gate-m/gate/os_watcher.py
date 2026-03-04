"""OS-level filesystem watcher.

Three modes, tried in priority order:

  1. fanotify FAN_OPEN_PERM (preferred, requires CAP_SYS_ADMIN)
       C layer holds the open() syscall in the kernel until Python
       returns a verdict. Atomic blocking — the write cannot happen
       until we say FAN_ALLOW or FAN_DENY.

  2. sys.addaudithook() + inotify-simple (fallback, no privileges needed)
       audit hook: in-process Python open()/exec* interception (pre-event)
       inotify:    out-of-process post-hoc FS event detection

Mode is printed at startup so it's always visible.
"""

from __future__ import annotations

import fnmatch
import logging
import sys
import threading
from pathlib import Path
from typing import Callable, Optional

logger = logging.getLogger(__name__)


def _matches_any_glob(path: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(path, p) for p in patterns)

# inotify event mask constants
try:
    import inotify_simple  # type: ignore

    _INOTIFY_AVAILABLE = True
except ImportError:
    _INOTIFY_AVAILABLE = False
    logger.warning("inotify-simple not installed — out-of-process FS watching disabled")


# ---------------------------------------------------------------------------
# Event type
# ---------------------------------------------------------------------------

class FSEvent:
    def __init__(self, path: str, event_type: str, in_process: bool) -> None:
        self.path = path
        self.event_type = event_type  # "open_read" | "open_write" | "exec" | "inotify_*"
        self.in_process = in_process

    def __repr__(self) -> str:
        src = "in-process" if self.in_process else "inotify"
        return f"FSEvent({self.event_type!r}, {self.path!r}, {src})"


# ---------------------------------------------------------------------------
# Audit hook (in-process)
# ---------------------------------------------------------------------------

def _install_audit_hook(
    project_root: str,
    forbidden: list[str],
    write_scope: list[str],
    read_scope: list[str],
    on_violation: Callable[[str, str], None],
) -> None:
    root = str(Path(project_root).resolve())

    def _hook(event: str, args: tuple) -> None:  # noqa: ANN001
        try:
            if event == "open":
                path_arg = str(args[0]) if args else ""
                flags = args[1] if len(args) > 1 else 0
                abs_path = str(Path(path_arg).resolve()) if path_arg else ""

                # Only care about paths inside (or targeting) project root
                if not abs_path.startswith(root):
                    return

                rel = abs_path[len(root):].lstrip("/")

                # Forbidden check (hard block regardless of R/W)
                if any(fnmatch.fnmatch(rel, p) for p in forbidden):
                    on_violation("forbidden_access", rel)
                    return

                # Write flag check (flags & os.O_WRONLY or O_RDWR)
                is_write = bool(flags & (1 | 2))  # O_WRONLY=1, O_RDWR=2
                if is_write and rel not in write_scope:
                    on_violation("out_of_scope_write", rel)

            elif event in ("os.exec", "subprocess.Popen"):
                cmd = str(args[0]) if args else "<unknown>"
                abs_cmd = str(Path(cmd).resolve()) if cmd else ""
                if not abs_cmd.startswith(root):
                    on_violation("exec_outside_project", cmd)

        except Exception:  # noqa: BLE001
            pass  # audit hooks must never raise

    sys.addaudithook(_hook)
    logger.debug("Audit hook installed for project root: %s", root)


# ---------------------------------------------------------------------------
# inotify watcher (out-of-process, daemon thread)
# ---------------------------------------------------------------------------

_INOTIFY_FLAGS = 0
if _INOTIFY_AVAILABLE:
    _INOTIFY_FLAGS = (
        inotify_simple.flags.CLOSE_WRITE
        | inotify_simple.flags.CREATE
        | inotify_simple.flags.DELETE
        | inotify_simple.flags.MOVED_TO
    )


class _InotifyThread(threading.Thread):
    def __init__(
        self,
        project_root: str,
        on_event: Callable[[FSEvent], None],
    ) -> None:
        super().__init__(daemon=True, name="gate-inotify")
        self.project_root = Path(project_root).resolve()
        self.on_event = on_event
        self._stop_event = threading.Event()
        self._inotify: Optional["inotify_simple.INotify"] = None
        self._wd_to_path: dict[int, Path] = {}

    def stop(self) -> None:
        self._stop_event.set()
        if self._inotify:
            try:
                self._inotify.close()
            except Exception:
                pass

    def _add_watch(self, path: Path) -> None:
        if not _INOTIFY_AVAILABLE or self._inotify is None:
            return
        try:
            wd = self._inotify.add_watch(str(path), _INOTIFY_FLAGS)
            self._wd_to_path[wd] = path
        except (OSError, ValueError) as e:
            logger.debug("inotify add_watch failed for %s: %s", path, e)

    def run(self) -> None:
        if not _INOTIFY_AVAILABLE:
            return
        self._inotify = inotify_simple.INotify()
        # Add watch recursively
        self._add_watch(self.project_root)
        for d in self.project_root.rglob("*"):
            if d.is_dir():
                self._add_watch(d)

        while not self._stop_event.is_set():
            try:
                events = self._inotify.read(timeout=500)  # 500ms poll
            except (OSError, ValueError):
                break
            for ev in events:
                parent = self._wd_to_path.get(ev.wd, self.project_root)
                full_path = parent / ev.name if ev.name else parent
                flag_name = str(inotify_simple.flags.from_mask(ev.mask))
                fs_event = FSEvent(
                    path=str(full_path),
                    event_type=f"inotify_{flag_name}",
                    in_process=False,
                )
                try:
                    self.on_event(fs_event)
                except Exception as exc:
                    logger.error("inotify event handler error: %s", exc)
                # Auto-watch newly created directories
                if inotify_simple.flags.CREATE in inotify_simple.flags.from_mask(ev.mask):
                    if full_path.is_dir():
                        self._add_watch(full_path)


# ---------------------------------------------------------------------------
# Public facade
# ---------------------------------------------------------------------------

class OSWatcher:
    """FS watcher — fanotify (atomic) if available, else audit hook + inotify."""

    def __init__(
        self,
        project_root: str,
        forbidden: list[str],
        write_scope: list[str],
        read_scope: list[str],
        on_violation: Callable[[str, str], None],
        on_inotify_event: Optional[Callable[[FSEvent], None]] = None,
    ) -> None:
        self.project_root = project_root
        self._inotify_thread: Optional[_InotifyThread] = None
        self._fanotify: Optional[object] = None

        # ── Try fanotify first ───────────────────────────────────────────────
        try:
            from .fanotify_watcher import FanotifyWatcher

            available, reason = FanotifyWatcher.is_available()
            if available:
                root = str(Path(project_root).resolve())

                def _fanotify_verdict(path: str, pid: int, is_write: bool) -> bool:
                    rel = path[len(root):].lstrip("/")

                    # Forbidden — always deny
                    if _matches_any_glob(rel, forbidden):
                        on_violation("forbidden_access", rel)
                        return False

                    if is_write:
                        if rel not in write_scope:
                            on_violation("out_of_scope_write", rel)
                            return False
                    else:
                        if not _matches_any_glob(rel, read_scope):
                            on_violation("out_of_scope_read", rel)
                            # reads are soft-rejected by the kernel layer too —
                            # let kernel.py handle the correction; here just log
                            return True  # don't block reads at OS level

                    return True

                self._fanotify = FanotifyWatcher(root, _fanotify_verdict)
                self._fanotify.start()
                print(f"[GATE-M] watcher: fanotify FAN_OPEN_PERM (atomic blocking) on {root}")
                return  # fanotify covers everything — skip audit hook + inotify

            else:
                print(f"[GATE-M] watcher: fanotify unavailable ({reason}) → using inotify fallback")

        except Exception as exc:
            logger.debug("fanotify init error: %s", exc)
            print(f"[GATE-M] watcher: fanotify error ({exc}) → using inotify fallback")

        # ── Fallback: audit hook + inotify ───────────────────────────────────
        _install_audit_hook(
            project_root=project_root,
            forbidden=forbidden,
            write_scope=write_scope,
            read_scope=read_scope,
            on_violation=on_violation,
        )

        def _default_inotify(event: FSEvent) -> None:
            logger.info("inotify event: %s", event)

        handler = on_inotify_event or _default_inotify
        if _INOTIFY_AVAILABLE:
            self._inotify_thread = _InotifyThread(project_root, handler)
            self._inotify_thread.start()
            print(f"[GATE-M] watcher: audit hook + inotify (post-hoc) on {project_root}")

    def stop(self) -> None:
        if self._fanotify is not None:
            self._fanotify.stop()
        if self._inotify_thread:
            self._inotify_thread.stop()
            self._inotify_thread.join(timeout=2)
