#!/usr/bin/env python3
"""Live rollback demo — applies real writes and shows GATE-M rolling them back.

Three scenarios:
  1. Test failure rollback  — write breaks pytest, file restored
  2. Hash invariant rollback — protected file tampered, write reverted
  3. Clean write             — write passes, file stays changed
"""

import os, sys, hashlib, shutil, tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from gate.kernel import GATEKernel
from gate.models import CapabilityToken, IntentDeclaration, ToolCall, ApprovalResult, RejectionResult
from gate.token import build_must_not_change

G = "\033[92m"; R = "\033[91m"; Y = "\033[93m"; C = "\033[96m"; B = "\033[1m"; Z = "\033[0m"

def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def banner(title):
    print(f"\n{'─'*60}\n{B}{C}{title}{Z}\n{'─'*60}")

def show_file(label, path):
    content = Path(path).read_text()
    print(f"\n  {B}{label}{Z}")
    for line in content.splitlines():
        print(f"    {line}")

# ── build a temp project ─────────────────────────────────────────────────────
project = Path(tempfile.mkdtemp(prefix="gate_demo_"))
(project / "src").mkdir()
(project / "tests").mkdir()

ORIGINAL_AUTH = """\
def validate_user(user):
    if user is None:
        return False
    return bool(user.is_active)
"""

ORIGINAL_CONFIG = "DEBUG = False\nSECRET_KEY = 'changeme'\n"

(project / "src" / "auth.py").write_text(ORIGINAL_AUTH)
(project / "src" / "config.py").write_text(ORIGINAL_CONFIG)
(project / "tests" / "test_auth.py").write_text("""\
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from src.auth import validate_user

class FakeUser:
    def __init__(self, active): self.is_active = active

def test_active():   assert validate_user(FakeUser(True))  is True
def test_inactive(): assert validate_user(FakeUser(False)) is False
def test_none():     assert validate_user(None)             is False
""")

GROQ_KEY   = os.environ.get("GROQ_API_KEY", "")
GEMINI_KEY = os.environ.get("GEMINI_API_KEY", "")

# ═══════════════════════════════════════════════════════════════════════════
# SCENARIO 1 — test failure triggers rollback
# ═══════════════════════════════════════════════════════════════════════════
banner("SCENARIO 1 — write breaks tests → rollback")

tok1 = CapabilityToken.create(
    natural_language_goal="simplify validate_user",
    read_scope=["src/**", "tests/**"],
    write_scope=["src/auth.py"],
    forbidden=["secrets/**", ".env"],
    must_pass_tests=["tests/test_auth.py"],
)
kernel1 = GATEKernel(tok1, str(project), GROQ_KEY, GEMINI_KEY)

# A diff that looks plausible but breaks the None test
BAD_DIFF = """\
--- a/src/auth.py
+++ b/src/auth.py
@@ -1,4 +1,2 @@
-def validate_user(user):
-    if user is None:
-        return False
-    return bool(user.is_active)
+def validate_user(user):
+    return bool(user.is_active)
"""

print(f"\n  {B}Proposed diff:{Z} removes the None guard (will break test_none)")
result = kernel1.execute_tool(ToolCall(
    tool_type="write",
    path="src/auth.py",
    proposed_diff=BAD_DIFF,
    intent=IntentDeclaration(
        intent="simplify validate_user by removing redundant None check",
        affected_scope=["src/auth.py::validate_user"],
        edit_category="modify",
        expected_postcondition="validate_user returns bool(user.is_active)",
    ),
))

assert isinstance(result, ApprovalResult), f"unexpected rejection: {result}"
snap_id = result.snapshot_id
print(f"\n  {G}✓ Kernel approved the diff (pre-write){Z}")
print(f"  Snapshot ID: {snap_id[:16]}...")

# Agent applies the write
show_file("File AFTER agent write (broken):", project / "src" / "auth.py")
(project / "src" / "auth.py").write_text(
    "def validate_user(user):\n    return bool(user.is_active)\n"
)
show_file("File content applied by agent:", project / "src" / "auth.py")

print(f"\n  {Y}Running invariant checks (pytest)...{Z}")
inv = kernel1.run_invariant_checks(snap_id)
kernel1.shutdown()

assert isinstance(inv, RejectionResult), "expected rollback"
assert inv.is_hard_stop
print(f"  {R}✗ Tests failed — rollback triggered{Z}")
print(f"  Detail: {inv.violation_detail[:120]}")

restored = (project / "src" / "auth.py").read_text()
show_file("File AFTER rollback (restored):", project / "src" / "auth.py")
assert restored == ORIGINAL_AUTH, "ROLLBACK FAILED — file not restored!"
print(f"\n  {G}{B}✓ ROLLBACK VERIFIED — file byte-for-byte identical to original{Z}")


# ═══════════════════════════════════════════════════════════════════════════
# SCENARIO 2 — hash invariant: protected file tampered
# ═══════════════════════════════════════════════════════════════════════════
banner("SCENARIO 2 — agent secretly modifies protected file → rollback")

config_hash = sha256(str(project / "src" / "config.py"))
tok2 = CapabilityToken.create(
    natural_language_goal="add logging to validate_user",
    read_scope=["src/**"],
    write_scope=["src/auth.py"],
    forbidden=["secrets/**", ".env"],
    must_not_change={"src/config.py": config_hash},
)
kernel2 = GATEKernel(tok2, str(project), GROQ_KEY, GEMINI_KEY)

GOOD_DIFF = """\
--- a/src/auth.py
+++ b/src/auth.py
@@ -1,4 +1,6 @@
+import logging
+logger = logging.getLogger(__name__)
 def validate_user(user):
     if user is None:
         return False
     return bool(user.is_active)
"""

result2 = kernel2.execute_tool(ToolCall(
    tool_type="write",
    path="src/auth.py",
    proposed_diff=GOOD_DIFF,
    intent=IntentDeclaration(
        intent="add logging import",
        affected_scope=["src/auth.py"],
        edit_category="add",
        expected_postcondition="logging is imported",
    ),
))
assert isinstance(result2, ApprovalResult)
snap_id2 = result2.snapshot_id
print(f"  {G}✓ Kernel approved the diff{Z}  snapshot={snap_id2[:16]}...")

# Agent applies the declared write AND secretly tampers with config.py
(project / "src" / "auth.py").write_text(
    "import logging\nlogger = logging.getLogger(__name__)\n" + ORIGINAL_AUTH
)
print(f"  {R}Agent secretly modifies config.py (not in write_scope)...{Z}")
(project / "src" / "config.py").write_text(
    "DEBUG = True\nSECRET_KEY = 'attacker_value'\n"
)
show_file("config.py AFTER secret tamper:", project / "src" / "config.py")

print(f"\n  {Y}Running invariant checks (hash)...{Z}")
inv2 = kernel2.run_invariant_checks(snap_id2)
kernel2.shutdown()

assert isinstance(inv2, RejectionResult)
assert inv2.is_hard_stop
print(f"  {R}✗ Hash mismatch on config.py — rollback triggered{Z}")
print(f"  Detail: {inv2.violation_detail}")

show_file("config.py AFTER rollback:", project / "src" / "config.py")
show_file("auth.py AFTER rollback:", project / "src" / "auth.py")

assert (project / "src" / "config.py").read_text() == ORIGINAL_CONFIG, "config not restored!"
assert (project / "src" / "auth.py").read_text() == ORIGINAL_AUTH, "auth not restored!"
print(f"\n  {G}{B}✓ ROLLBACK VERIFIED — both files restored to pre-write state{Z}")


# ═══════════════════════════════════════════════════════════════════════════
# SCENARIO 3 — clean write, no rollback
# ═══════════════════════════════════════════════════════════════════════════
banner("SCENARIO 3 — clean write passes all checks → no rollback")

tok3 = CapabilityToken.create(
    natural_language_goal="add None guard with logging",
    read_scope=["src/**", "tests/**"],
    write_scope=["src/auth.py"],
    forbidden=["secrets/**", ".env"],
    must_pass_tests=["tests/test_auth.py"],
    must_not_change={"src/config.py": sha256(str(project / "src" / "config.py"))},
)
kernel3 = GATEKernel(tok3, str(project), GROQ_KEY, GEMINI_KEY)

CLEAN_DIFF = """\
--- a/src/auth.py
+++ b/src/auth.py
@@ -1,4 +1,7 @@
+import logging
+logger = logging.getLogger(__name__)
+
 def validate_user(user):
     if user is None:
+        logger.warning("validate_user called with None")
         return False
     return bool(user.is_active)
"""

NEW_CONTENT = """\
import logging
logger = logging.getLogger(__name__)

def validate_user(user):
    if user is None:
        logger.warning("validate_user called with None")
        return False
    return bool(user.is_active)
"""

result3 = kernel3.execute_tool(ToolCall(
    tool_type="write",
    path="src/auth.py",
    proposed_diff=CLEAN_DIFF,
    intent=IntentDeclaration(
        intent="add logging to None branch of validate_user",
        affected_scope=["src/auth.py::validate_user"],
        edit_category="add",
        expected_postcondition="None input is logged and returns False",
    ),
))
assert isinstance(result3, ApprovalResult)
snap_id3 = result3.snapshot_id
print(f"  {G}✓ Kernel approved the diff{Z}  snapshot={snap_id3[:16]}...")

# Agent applies the write correctly
(project / "src" / "auth.py").write_text(NEW_CONTENT)
show_file("File AFTER agent write (correct):", project / "src" / "auth.py")

print(f"\n  {Y}Running invariant checks (tests + hash)...{Z}")
inv3 = kernel3.run_invariant_checks(snap_id3)
kernel3.shutdown()

assert isinstance(inv3, ApprovalResult), f"unexpected failure: {getattr(inv3, 'violation_detail', inv3)}"
print(f"  {G}✓ Tests pass, hashes intact{Z}")

final = (project / "src" / "auth.py").read_text()
assert final == NEW_CONTENT, "file changed unexpectedly"
print(f"\n  {G}{B}✓ WRITE KEPT — file has the new content, no rollback{Z}")


# ── cleanup ───────────────────────────────────────────────────────────────────
shutil.rmtree(project)

print(f"""
{'═'*60}
{B}Summary{Z}
  Scenario 1  test failure    {R}→ rollback ✓{Z}
  Scenario 2  hash tamper     {R}→ rollback ✓{Z}
  Scenario 3  clean write     {G}→ kept     ✓{Z}
{'═'*60}
""")
