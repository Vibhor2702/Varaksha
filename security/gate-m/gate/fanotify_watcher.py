"""Python wrapper for gate_watcher.so — fanotify FAN_OPEN_PERM integration.

Provides atomic kernel-level blocking of open() syscalls inside project_root.
Falls back gracefully when:
  - gate_watcher.so is not compiled
  - CAP_SYS_ADMIN is not available (not root, no suitable user namespace)

Usage:
    if FanotifyWatcher.is_available():
        w = FanotifyWatcher(project_root, on_open_cb)
        w.start()
        ...
        w.stop()
"""

from __future__ import annotations

import ctypes
import logging
import os
from pathlib import Path
from typing import Callable, Optional

logger = logging.getLogger(__name__)

# Signature: (path: bytes, pid: int, is_write: int) -> int  (1=allow, 0=deny)
_VERDICT_CB = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_int)

_SO_PATH = Path(__file__).parent / "watcher" / "gate_watcher.so"


def _load_lib() -> Optional[ctypes.CDLL]:
    if not _SO_PATH.exists():
        return None
    try:
        lib = ctypes.CDLL(str(_SO_PATH))

        lib.gate_check_privileges.argtypes = []
        lib.gate_check_privileges.restype  = ctypes.c_int

        lib.gate_init.argtypes = [ctypes.c_char_p]
        lib.gate_init.restype  = ctypes.c_int

        lib.gate_start.argtypes = [_VERDICT_CB]
        lib.gate_start.restype  = ctypes.c_int

        lib.gate_stop.argtypes = []
        lib.gate_stop.restype  = None

        return lib
    except OSError as e:
        logger.debug("fanotify: could not load %s: %s", _SO_PATH, e)
        return None


class FanotifyWatcher:
    """Atomic kernel-level FS watcher using fanotify FAN_OPEN_PERM."""

    def __init__(
        self,
        project_root: str,
        on_open: Callable[[str, int, bool], bool],
    ) -> None:
        """
        Args:
            project_root: Absolute path to watch. Only opens inside this
                          prefix reach `on_open`; everything else is
                          auto-allowed in C without a Python call.
            on_open:      Called for every open() inside project_root.
                          Signature: (path: str, pid: int, is_write: bool) -> bool
                          Return True to allow, False to deny.
        """
        lib = _load_lib()
        if lib is None:
            raise RuntimeError("gate_watcher.so not found — run: make -C gate/watcher")

        self._lib      = lib
        self._root     = str(Path(project_root).resolve())
        self._on_open  = on_open
        self._started  = False

        # Keep strong reference so GC doesn't collect the ctypes callback
        self._c_cb = _VERDICT_CB(self._verdict)

        rc = self._lib.gate_init(self._root.encode())
        if rc != 0:
            err = -rc
            raise PermissionError(
                f"gate_init failed (errno {err}): {os.strerror(err)}. "
                "fanotify requires CAP_SYS_ADMIN — run as root or with sudo."
            )

    def _verdict(self, path_bytes: bytes, pid: int, is_write: int) -> int:
        """C thread calls this for every open() inside project_root."""
        try:
            path = path_bytes.decode(errors="replace")
            allow = self._on_open(path, pid, bool(is_write))
            return 1 if allow else 0
        except Exception as exc:
            logger.error("fanotify verdict callback raised: %s", exc)
            return 1  # fail open — never deadlock

    def start(self) -> None:
        rc = self._lib.gate_start(self._c_cb)
        if rc != 0:
            raise RuntimeError(f"gate_start failed: {os.strerror(-rc)}")
        self._started = True
        logger.info("fanotify watcher active on %s", self._root)

    def stop(self) -> None:
        if self._started:
            self._lib.gate_stop()
            self._started = False

    # ── class-level availability check ──────────────────────────────────────

    @classmethod
    def is_available(cls) -> tuple[bool, str]:
        """
        Returns (available: bool, reason: str).

        Checks both .so presence and CAP_SYS_ADMIN without side effects.
        """
        lib = _load_lib()
        if lib is None:
            return False, f"gate_watcher.so not found at {_SO_PATH} — run: make -C gate/watcher"

        rc = lib.gate_check_privileges()
        if rc != 0:
            err = -rc
            return False, f"fanotify unavailable (errno {err}: {os.strerror(err)}) — needs CAP_SYS_ADMIN"

        return True, "fanotify available"
