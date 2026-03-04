"""Tests for SIPChecker — all three layers.

Runs without any LLM calls. Pure AST + diff parsing.
"""

from __future__ import annotations

import pytest
from datetime import datetime

from gate.models import CapabilityToken, IntentDeclaration, ToolCall
from gate.sip_checker import SIPChecker, _detect_category, _touched_files, _ast_side_effect_violations


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def make_token(
    write_scope: list[str] | None = None,
    forbidden: list[str] | None = None,
) -> CapabilityToken:
    return CapabilityToken(
        task_id="test-task",
        natural_language_goal="fix the null check",
        read_scope=["src/**"],
        write_scope=write_scope or ["src/auth.py"],
        forbidden=forbidden or ["secrets/**", ".env"],
        allowed_edit_categories=["modify", "add", "delete", "refactor"],
        allowed_new_files=False,
        allowed_new_dependencies=False,
        retry_budget=3,
        ttl_minutes=30,
        created_at=datetime.utcnow(),
        must_pass_tests=[],
        must_not_change={},
    )


def make_tool_call(
    diff: str,
    edit_category: str = "modify",
) -> ToolCall:
    return ToolCall(
        tool_type="write",
        proposed_diff=diff,
        intent=IntentDeclaration(
            intent="fix null check",
            affected_scope=["src/auth.py::validate_user"],
            edit_category=edit_category,
            expected_postcondition="validate_user returns False for None input",
        ),
    )


# ---------------------------------------------------------------------------
# Sample diffs
# ---------------------------------------------------------------------------

DIFF_MODIFY_IN_SCOPE = """\
--- a/src/auth.py
+++ b/src/auth.py
@@ -10,6 +10,9 @@
 def validate_user(user):
-    return user.is_active
+    if user is None:
+        return False
+    return user.is_active
"""

DIFF_OUT_OF_SCOPE = """\
--- a/src/auth.py
+++ b/src/auth.py
@@ -10,3 +10,4 @@
 def validate_user(user):
+    return True

--- a/src/models.py
+++ b/src/models.py
@@ -5,3 +5,4 @@
 class User:
+    admin: bool = False
"""

DIFF_ADD_ONLY = """\
--- a/src/auth.py
+++ b/src/auth.py
@@ -20,3 +20,7 @@
 # end of file
+
+def logout(user):
+    user.session = None
+    return True
"""

DIFF_DELETE_ONLY = """\
--- a/src/auth.py
+++ b/src/auth.py
@@ -10,6 +10,3 @@
 def validate_user(user):
-    if user is None:
-        return False
-    return user.is_active
"""

DIFF_WITH_SUBPROCESS = """\
--- a/src/auth.py
+++ b/src/auth.py
@@ -1,4 +1,6 @@
+import subprocess
+
 def validate_user(user):
-    return user.is_active
+    subprocess.run(["ls"])
+    return user.is_active
"""

DIFF_WITH_OS_SYSTEM = """\
--- a/src/auth.py
+++ b/src/auth.py
@@ -1,4 +1,6 @@
+import os
+
 def validate_user(user):
-    return user.is_active
+    os.system("rm -rf /")
+    return user.is_active
"""

DIFF_WITH_REQUESTS = """\
--- a/src/auth.py
+++ b/src/auth.py
@@ -1,4 +1,6 @@
+import requests
+
 def validate_user(user):
-    return user.is_active
+    requests.get("http://example.com")
+    return user.is_active
"""

DIFF_WITH_OS_ENVIRON = """\
--- a/src/auth.py
+++ b/src/auth.py
@@ -1,4 +1,6 @@
+import os
+
 def validate_user(user):
-    return user.is_active
+    secret = os.environ["SECRET_KEY"]
+    return user.is_active
"""

DIFF_CLEAN_MODIFY = """\
--- a/src/auth.py
+++ b/src/auth.py
@@ -10,4 +10,7 @@
 def validate_user(user):
-    return user.is_active
+    if user is None:
+        return False
+    return user.is_active
"""

# ---------------------------------------------------------------------------
# Layer 1: Scope check
# ---------------------------------------------------------------------------

class TestLayer1Scope:
    def test_in_scope_passes(self):
        checker = SIPChecker()
        token = make_token(write_scope=["src/auth.py"])
        tc = make_tool_call(DIFF_MODIFY_IN_SCOPE)
        assert checker.check(tc, token) is None

    def test_out_of_scope_rejected(self):
        checker = SIPChecker()
        token = make_token(write_scope=["src/auth.py"])  # src/models.py not in scope
        tc = make_tool_call(DIFF_OUT_OF_SCOPE)
        result = checker.check(tc, token)
        assert result is not None
        assert result.layer_failed == 1
        assert result.is_hard_stop is False
        assert "src/models.py" in result.violation_detail

    def test_suggestion_mentions_extra_file(self):
        checker = SIPChecker()
        token = make_token(write_scope=["src/auth.py"])
        tc = make_tool_call(DIFF_OUT_OF_SCOPE)
        result = checker.check(tc, token)
        assert "src/models.py" in result.kernel_suggestion


# ---------------------------------------------------------------------------
# Layer 2: Category check
# ---------------------------------------------------------------------------

class TestLayer2Category:
    def test_add_category_correct(self):
        checker = SIPChecker()
        token = make_token()
        tc = make_tool_call(DIFF_ADD_ONLY, edit_category="add")
        assert checker.check(tc, token) is None

    def test_delete_category_correct(self):
        checker = SIPChecker()
        token = make_token()
        tc = make_tool_call(DIFF_DELETE_ONLY, edit_category="delete")
        assert checker.check(tc, token) is None

    def test_modify_declared_but_add_detected(self):
        checker = SIPChecker()
        token = make_token()
        tc = make_tool_call(DIFF_ADD_ONLY, edit_category="modify")
        result = checker.check(tc, token)
        assert result is not None
        assert result.layer_failed == 2
        assert "add" in result.violation_detail
        assert result.is_hard_stop is False

    def test_add_declared_but_modify_detected(self):
        checker = SIPChecker()
        token = make_token()
        tc = make_tool_call(DIFF_CLEAN_MODIFY, edit_category="add")
        result = checker.check(tc, token)
        assert result is not None
        assert result.layer_failed == 2


# ---------------------------------------------------------------------------
# Layer 3: Side-effect check (AST, hard stops)
# ---------------------------------------------------------------------------

class TestLayer3SideEffects:
    def test_clean_diff_no_violations(self):
        violations = _ast_side_effect_violations(DIFF_CLEAN_MODIFY, [])
        assert violations == []

    def test_subprocess_detected(self):
        violations = _ast_side_effect_violations(DIFF_WITH_SUBPROCESS, [])
        assert any("subprocess" in v for v in violations)

    def test_os_system_detected(self):
        violations = _ast_side_effect_violations(DIFF_WITH_OS_SYSTEM, [])
        assert any("os" in v for v in violations)

    def test_requests_import_detected(self):
        violations = _ast_side_effect_violations(DIFF_WITH_REQUESTS, [])
        assert any("requests" in v for v in violations)

    def test_os_environ_detected(self):
        violations = _ast_side_effect_violations(DIFF_WITH_OS_ENVIRON, [])
        assert any("environ" in v for v in violations)

    def test_hard_stop_on_subprocess(self):
        checker = SIPChecker()
        token = make_token()
        tc = make_tool_call(DIFF_WITH_SUBPROCESS, edit_category="modify")
        result = checker.check(tc, token)
        assert result is not None
        assert result.layer_failed == 3
        assert result.is_hard_stop is True

    def test_hard_stop_on_requests(self):
        checker = SIPChecker()
        token = make_token()
        tc = make_tool_call(DIFF_WITH_REQUESTS, edit_category="modify")
        result = checker.check(tc, token)
        assert result is not None
        assert result.is_hard_stop is True

    def test_retries_remaining_set(self):
        checker = SIPChecker()
        token = make_token()
        token.retry_budget = 2
        tc = make_tool_call(DIFF_WITH_SUBPROCESS, edit_category="modify")
        result = checker.check(tc, token)
        assert result.retries_remaining == 2  # set from token, not decremented here


# ---------------------------------------------------------------------------
# Helper unit tests
# ---------------------------------------------------------------------------

class TestHelpers:
    def test_touched_files_single(self):
        files = _touched_files(DIFF_MODIFY_IN_SCOPE)
        assert "src/auth.py" in files

    def test_touched_files_multiple(self):
        files = _touched_files(DIFF_OUT_OF_SCOPE)
        assert "src/auth.py" in files
        assert "src/models.py" in files

    def test_detect_add(self):
        assert _detect_category(DIFF_ADD_ONLY) == "add"

    def test_detect_delete(self):
        assert _detect_category(DIFF_DELETE_ONLY) == "delete"

    def test_detect_modify(self):
        assert _detect_category(DIFF_CLEAN_MODIFY) == "modify"

    def test_empty_diff_graceful(self):
        assert _detect_category("") == "modify"
        assert _touched_files("") == []
        assert _ast_side_effect_violations("", []) == []
