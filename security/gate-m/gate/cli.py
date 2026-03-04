"""CLI entrypoint for GATE-M.

Usage:
  gate-m start --goal "fix null check in auth.py" \\
               --write-scope src/auth.py \\
               --read-scope "src/**" "tests/**" \\
               --tests tests/unit/auth_test.py \\
               --project-root /path/to/project

  gate-m execute <tool_call_json>

Reads GROQ_API_KEY and GEMINI_API_KEY from environment.
"""

from __future__ import annotations

import dataclasses
import json
import os
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Inline arg parsing (no argparse dependency complexity)
# ---------------------------------------------------------------------------

def _usage() -> None:
    print(__doc__)
    sys.exit(1)


def cmd_start(args: list[str]) -> None:
    import argparse
    from datetime import datetime

    from .models import CapabilityToken
    from .token import build_must_not_change

    parser = argparse.ArgumentParser(prog="gate-m start")
    parser.add_argument("--goal", required=True)
    parser.add_argument("--write-scope", nargs="+", default=[])
    parser.add_argument("--read-scope", nargs="+", default=[])
    parser.add_argument("--forbidden", nargs="*", default=[])
    parser.add_argument("--tests", nargs="*", default=[])
    parser.add_argument("--protect", nargs="*", default=[], help="Files whose hash must not change")
    parser.add_argument("--project-root", default=os.getcwd())
    parser.add_argument("--ttl", type=int, default=30)
    parser.add_argument("--retry-budget", type=int, default=3)
    parser.add_argument("--allow-new-files", action="store_true")
    parser.add_argument("--allow-new-deps", action="store_true")
    ns = parser.parse_args(args)

    token = CapabilityToken.create(
        natural_language_goal=ns.goal,
        read_scope=ns.read_scope,
        write_scope=ns.write_scope,
        forbidden=ns.forbidden,
        allowed_edit_categories=["modify", "add", "delete", "refactor"],
        allowed_new_files=ns.allow_new_files,
        allowed_new_dependencies=ns.allow_new_deps,
        retry_budget=ns.retry_budget,
        ttl_minutes=ns.ttl,
        must_pass_tests=ns.tests,
        must_not_change=build_must_not_change(ns.protect),
    )

    # Persist token to .gate_session in project root
    session_file = Path(ns.project_root) / ".gate_session"
    token_dict = dataclasses.asdict(token)
    token_dict["created_at"] = token.created_at.isoformat()
    token_dict["project_root"] = ns.project_root
    session_file.write_text(json.dumps(token_dict, indent=2))

    print(json.dumps(token_dict, indent=2))
    print(f"\nSession token written to: {session_file}")
    print(f"Task ID: {token.task_id}")


def _load_session(project_root: str | None = None) -> tuple[dict, str]:
    root = project_root or os.getcwd()
    session_file = Path(root) / ".gate_session"
    if not session_file.exists():
        print("No active session. Run 'gate-m start' first.", file=sys.stderr)
        sys.exit(1)
    data = json.loads(session_file.read_text())
    return data, data.get("project_root", root)


def cmd_execute(args: list[str]) -> None:
    import argparse
    from datetime import datetime

    from .kernel import GATEKernel
    from .models import CapabilityToken, IntentDeclaration, ToolCall

    parser = argparse.ArgumentParser(prog="gate-m execute")
    parser.add_argument("tool_call_json")
    parser.add_argument("--project-root", default=None)
    ns = parser.parse_args(args)

    groq_key = os.environ.get("GROQ_API_KEY", "")
    gemini_key = os.environ.get("GEMINI_API_KEY", "")

    token_dict, project_root = _load_session(ns.project_root)

    # Reconstruct CapabilityToken
    token_dict["created_at"] = datetime.fromisoformat(token_dict["created_at"])
    token_dict.pop("project_root", None)
    token = CapabilityToken(**token_dict)

    kernel = GATEKernel(
        token=token,
        project_root=project_root,
        groq_key=groq_key,
        gemini_key=gemini_key,
    )

    raw = json.loads(ns.tool_call_json)

    # Build IntentDeclaration if present
    intent = None
    if raw.get("intent"):
        intent = IntentDeclaration(**raw["intent"])

    tool_call = ToolCall(
        tool_type=raw["tool_type"],
        path=raw.get("path"),
        command=raw.get("command"),
        intent=intent,
        proposed_diff=raw.get("proposed_diff"),
    )

    result = kernel.execute_tool(tool_call)
    print(json.dumps(dataclasses.asdict(result), indent=2))
    kernel.shutdown()


def cmd_invariants(args: list[str]) -> None:
    """Run post-write invariant checks for a given snapshot_id."""
    import argparse
    from datetime import datetime

    from .kernel import GATEKernel
    from .models import CapabilityToken

    parser = argparse.ArgumentParser(prog="gate-m invariants")
    parser.add_argument("snapshot_id")
    parser.add_argument("--project-root", default=None)
    ns = parser.parse_args(args)

    groq_key = os.environ.get("GROQ_API_KEY", "")
    gemini_key = os.environ.get("GEMINI_API_KEY", "")

    token_dict, project_root = _load_session(ns.project_root)
    token_dict["created_at"] = datetime.fromisoformat(token_dict["created_at"])
    token_dict.pop("project_root", None)
    token = CapabilityToken(**token_dict)

    kernel = GATEKernel(token=token, project_root=project_root,
                        groq_key=groq_key, gemini_key=gemini_key)
    result = kernel.run_invariant_checks(ns.snapshot_id)
    print(json.dumps(dataclasses.asdict(result), indent=2))
    kernel.shutdown()


def main() -> None:
    if len(sys.argv) < 2:
        _usage()

    subcmd = sys.argv[1]
    rest = sys.argv[2:]

    if subcmd == "start":
        cmd_start(rest)
    elif subcmd == "execute":
        cmd_execute(rest)
    elif subcmd == "invariants":
        cmd_invariants(rest)
    else:
        print(f"Unknown subcommand: {subcmd}", file=sys.stderr)
        _usage()


if __name__ == "__main__":
    main()
