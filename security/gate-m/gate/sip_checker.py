"""Structural Intent Preservation (SIP) checker.

Three layers:
  1. Scope check  — all touched files ∈ token.write_scope
  2. Category check — detected edit category matches declared intent
  3. Side-effect check — AST-based detection of dangerous additions (hard stops)
"""

from __future__ import annotations

import ast
import fnmatch
from typing import Optional

import whatthepatch

from .models import CapabilityToken, IntentDeclaration, RejectionResult, ToolCall


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _matches_any_glob(path: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(path, p) for p in patterns)


def _parse_diff(unified_diff: str) -> list[whatthepatch.patch.Change]:
    """Return list of (Change) objects from whatthepatch."""
    patches = list(whatthepatch.parse_patch(unified_diff))
    return patches


def _touched_files(unified_diff: str) -> list[str]:
    """Return list of file paths modified by the diff.

    Falls back to line scanning when whatthepatch misses files (e.g. when
    consecutive diffs lack a blank-line separator).
    """
    # Primary: whatthepatch
    files: list[str] = []
    for patch in whatthepatch.parse_patch(unified_diff):
        if patch.header and patch.header.new_path:
            path = patch.header.new_path
            if path.startswith(("a/", "b/")):
                path = path[2:]
            if path and path != "/dev/null":
                files.append(path)
        elif patch.header and patch.header.old_path:
            path = patch.header.old_path
            if path.startswith(("a/", "b/")):
                path = path[2:]
            if path and path != "/dev/null":
                files.append(path)

    # Fallback: scan for "+++ " lines directly (handles malformed multi-diffs)
    if not files:
        for line in unified_diff.splitlines():
            if line.startswith("+++ "):
                path = line[4:].strip()
                if path.startswith(("a/", "b/")):
                    path = path[2:]
                if path and path != "/dev/null":
                    files.append(path)
        return list(dict.fromkeys(files))  # deduplicate, preserve order

    # If whatthepatch found files but the fallback finds more, merge
    fallback: list[str] = []
    for line in unified_diff.splitlines():
        if line.startswith("+++ "):
            path = line[4:].strip()
            if path.startswith(("a/", "b/")):
                path = path[2:]
            if path and path != "/dev/null":
                fallback.append(path)

    merged = list(dict.fromkeys(files + fallback))
    return merged


def _detect_category(unified_diff: str) -> str:
    """Detect edit category from a unified diff.

    Returns one of: "add", "modify", "delete", "refactor"
    """
    patches = list(whatthepatch.parse_patch(unified_diff))
    if not patches:
        return "modify"

    total_added = 0
    total_removed = 0
    for patch in patches:
        if not patch.changes:
            continue
        for change in patch.changes:
            # whatthepatch Change: (old, new, line)
            # old=None → added line; new=None → removed line; both → context
            if change.old is None and change.new is not None:
                total_added += 1
            elif change.new is None and change.old is not None:
                total_removed += 1

    if total_added > 0 and total_removed == 0:
        return "add"
    if total_removed > 0 and total_added == 0:
        return "delete"
    # Heuristic: if files span multiple patches it might be a refactor
    if len(patches) > 1 and total_added > 0 and total_removed > 0:
        return "refactor"
    return "modify"


# ---------------------------------------------------------------------------
# AST-based side-effect detection
# ---------------------------------------------------------------------------

_HARD_STOP_MODULES = {
    "subprocess", "os",    # os.system / os.popen / exec* covered below
    "socket", "requests", "httpx", "urllib",
}

_HARD_STOP_OS_ATTRS = {"system", "popen", "execl", "execle", "execlp", "execlpe",
                       "execv", "execve", "execvp", "execvpe", "spawnl", "spawnle",
                       "spawnlp", "spawnlpe", "spawnv", "spawnve", "spawnvp", "spawnvpe"}

_NETWORK_MODULES = {"socket", "requests", "httpx", "urllib", "aiohttp", "urllib3"}


class _SideEffectVisitor(ast.NodeVisitor):
    """Walk an AST and collect side-effect violations."""

    def __init__(self, forbidden_paths: list[str]) -> None:
        self.violations: list[str] = []
        self.forbidden_paths = forbidden_paths

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            top = alias.name.split(".")[0]
            if top in _HARD_STOP_MODULES or top in _NETWORK_MODULES:
                self.violations.append(f"import of dangerous module: {alias.name}")
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module:
            top = node.module.split(".")[0]
            if top in _HARD_STOP_MODULES or top in _NETWORK_MODULES:
                self.violations.append(f"from-import of dangerous module: {node.module}")
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        # subprocess.*
        if isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                if node.func.value.id == "subprocess":
                    self.violations.append(f"subprocess call: subprocess.{node.func.attr}")
                elif node.func.value.id == "os" and node.func.attr in _HARD_STOP_OS_ATTRS:
                    self.violations.append(f"os shell/exec call: os.{node.func.attr}")
        # exec() / eval() builtins
        if isinstance(node.func, ast.Name) and node.func.id in ("exec", "eval"):
            self.violations.append(f"builtin {node.func.id}() call")
        # os.environ / os.getenv
        if isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                if node.func.value.id == "os" and node.func.attr in ("getenv", "environ.get"):
                    self.violations.append(f"env var read: os.{node.func.attr}")
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        # Catch os.environ["KEY"] patterns (Subscript on os.environ)
        if isinstance(node.value, ast.Name) and node.value.id == "os" and node.attr == "environ":
            self.violations.append("env var access via os.environ")
        self.generic_visit(node)


def _extract_added_lines(unified_diff: str) -> str:
    """Return added lines from a unified diff, dedented so AST can parse them."""
    lines: list[str] = []
    for line in unified_diff.splitlines():
        if line.startswith("+") and not line.startswith("+++"):
            lines.append(line[1:])  # strip leading +
    return "\n".join(lines)


def _parse_candidates(source: str) -> ast.AST | None:
    """Try multiple parse strategies on a source fragment. Return AST or None."""
    for candidate in (
        source,
        "def _gate_wrapper():\n" + "\n".join("    " + l for l in source.splitlines()),
        "\n".join(l.lstrip() for l in source.splitlines()),
    ):
        try:
            return ast.parse(candidate)
        except SyntaxError:
            continue
    return None


def _ast_side_effect_violations(unified_diff: str, forbidden_paths: list[str]) -> list[str]:
    """Parse added lines with AST and return list of violation strings.

    Strategy:
      1. Try parsing all added lines as a whole (three sub-strategies).
      2. If that fails (mixed-indentation snippets are common in diffs),
         split by blank lines into contiguous chunks, dedent each chunk,
         and parse independently. This catches imports/calls buried deep
         in exception handlers, decorators, class bodies, etc.
    """
    source = _extract_added_lines(unified_diff)
    if not source.strip():
        return []

    violations: list[str] = []

    # ── Strategy A: parse whole source ─────────────────────────────────────
    tree = _parse_candidates(source)
    if tree is not None:
        v = _SideEffectVisitor(forbidden_paths)
        v.visit(tree)
        return v.violations

    # ── Strategy B: chunk-based parsing ────────────────────────────────────
    # Split extracted lines into contiguous non-blank chunks, dedent each,
    # and scan independently. Catches mixed-indentation diffs (e.g. an
    # import at column 0 followed by indented body lines).
    #
    # Within each chunk, further split at zero-indent boundaries: an import
    # at column 0 followed immediately by indented body code (no blank line)
    # is common in diffs and would otherwise fail to parse as a whole.
    lines = source.splitlines()
    chunks: list[list[str]] = []
    current: list[str] = []
    for line in lines:
        if line.strip():
            current.append(line)
        else:
            if current:
                chunks.append(current)
                current = []
    if current:
        chunks.append(current)

    def _sub_chunks(chunk: list[str]) -> list[list[str]]:
        """Split a chunk so that each zero-indent line is its own sub-chunk.

        This handles the common diff pattern:
          +import requests        ← col 0
          +    try:               ← indented — belongs to different logical scope
          +        requests.post(...)

        Without splitting, the whole block fails to parse because a top-level
        import followed immediately by an indented body is not valid Python.
        By isolating the import line we can parse it and catch the violation.
        """
        subs: list[list[str]] = []
        indented: list[str] = []
        for line in chunk:
            indent = len(line) - len(line.lstrip()) if line.strip() else 999
            if indent == 0:
                # Flush any accumulated indented lines first
                if indented:
                    subs.append(indented)
                    indented = []
                # Each zero-indent line is its own sub-chunk
                subs.append([line])
            else:
                indented.append(line)
        if indented:
            subs.append(indented)
        return subs

    seen: set[str] = set()
    for chunk in chunks:
        for sub in _sub_chunks(chunk):
            min_indent = min(
                len(l) - len(l.lstrip()) for l in sub if l.strip()
            )
            dedented = "\n".join(l[min_indent:] for l in sub)
            tree = _parse_candidates(dedented)
            if tree is None:
                continue
            v = _SideEffectVisitor(forbidden_paths)
            v.visit(tree)
            for violation in v.violations:
                if violation not in seen:
                    seen.add(violation)
                    violations.append(violation)

    return violations


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class SIPChecker:
    def check(self, tool_call: ToolCall, token: CapabilityToken) -> Optional[RejectionResult]:
        """Run all three SIP layers. Return first failure or None if clean."""

        diff = tool_call.proposed_diff or ""

        # ------------------------------------------------------------------ #
        # Layer 1 — SCOPE CHECK (includes forbidden check for writes)
        # ------------------------------------------------------------------ #
        touched = _touched_files(diff)

        # Hard block: any touched file matches forbidden patterns
        forbidden_hits = [
            f for f in touched
            if any(fnmatch.fnmatch(f, p) for p in token.forbidden)
        ]
        if forbidden_hits:
            hits = ", ".join(forbidden_hits)
            return RejectionResult(
                rejection_reason="Write targets forbidden path",
                layer_failed=1,
                violation_detail=f"Forbidden paths touched: {hits}",
                kernel_suggestion=(
                    f"The file(s) {hits} match a forbidden pattern "
                    f"{token.forbidden}. These paths are hard-blocked for writes."
                ),
                retries_remaining=token.retry_budget,
                is_hard_stop=True,
            )

        out_of_scope = [f for f in touched if f not in token.write_scope]
        if out_of_scope:
            extra = ", ".join(out_of_scope)
            return RejectionResult(
                rejection_reason="Files touched outside write_scope",
                layer_failed=1,
                violation_detail=f"Out-of-scope files: {extra}",
                kernel_suggestion=(
                    f"You touched {extra}, which is not in write_scope. "
                    "Either add them to the token's write_scope or split into "
                    "separate tool calls that only touch allowed files."
                ),
                retries_remaining=token.retry_budget,
                is_hard_stop=False,
            )

        # ------------------------------------------------------------------ #
        # Layer 2 — CATEGORY CHECK
        # ------------------------------------------------------------------ #
        if tool_call.intent:
            detected = _detect_category(diff)
            declared = tool_call.intent.edit_category
            if detected != declared:
                return RejectionResult(
                    rejection_reason="Edit category mismatch",
                    layer_failed=2,
                    violation_detail=(
                        f"Declared category '{declared}' but diff looks like '{detected}'"
                    ),
                    kernel_suggestion=(
                        f"Your diff is categorized as '{detected}' but you declared "
                        f"'{declared}'. Update your IntentDeclaration.edit_category "
                        f"to '{detected}' or restructure the diff to match '{declared}'."
                    ),
                    retries_remaining=token.retry_budget,
                    is_hard_stop=False,
                )

        # ------------------------------------------------------------------ #
        # Layer 3 — SIDE EFFECT CHECK (AST, hard stops)
        # ------------------------------------------------------------------ #
        violations = _ast_side_effect_violations(diff, token.forbidden)
        if violations:
            detail = "; ".join(violations)
            return RejectionResult(
                rejection_reason="Dangerous side effect detected in diff",
                layer_failed=3,
                violation_detail=detail,
                kernel_suggestion=(
                    "Remove the flagged statement(s) from the diff. "
                    "If network/subprocess access is genuinely needed, "
                    "declare it explicitly in the CapabilityToken and obtain "
                    "a new token with expanded permissions."
                ),
                retries_remaining=token.retry_budget,
                is_hard_stop=True,
            )

        return None  # all checks passed
