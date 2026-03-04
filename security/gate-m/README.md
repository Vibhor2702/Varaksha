# GATE-M

**G**uarded **A**gent **T**ool **E**xecution — **M**istake Model

A Linux-only, framework-agnostic kernel wrapper that sits between an AI agent and the filesystem. GATE-M intercepts every tool call the agent makes, enforces capability-scoped permissions, and invokes an LLM verifier only when a diff is large enough to warrant it (>20 lines changed).

**Design philosophy:** agents make mistakes, not malicious decisions. GATE-M is a mistake-prevention layer, not a sandbox. It assumes good intent and provides structured correction so the agent can retry correctly.

---

## How it works

```
Agent submits ToolCall
        │
        ▼
  GATEKernel.execute_tool()
        │
        ├─ READ  ──► forbidden? hard stop │ out of scope? soft reject │ else approve
        │
        └─ WRITE
              │
              ├─ 1. Snapshot (git stash or file copy)  ← before anything
              │
              ├─ 2. SIPChecker — no LLM, pure logic
              │       L1 Scope:       touched files ∈ write_scope?
              │       L2 Category:    declared "modify" but diff is "add"?
              │       L3 Side-effects: subprocess/socket/os.environ added? (AST only)
              │
              ├─ 3. LLM Verifier — only if diff > 20 lines
              │       Groq llama-3.3-70b (primary) → Gemini 2.0 flash (fallback)
              │       Timeout 10s → fail open + log warning
              │
              └─ 4. ApprovalResult returned — agent applies the write
                     Agent then calls run_invariant_checks():
                       - sha256 of must_not_change files
                       - pytest must_pass_tests
                       - on failure: auto rollback to snapshot
```

The kernel **never applies writes itself**. It approves or rejects. The agent writes, then calls the invariant checker.

---

## Security properties (verified by benchmark)

| Property | Result |
|---|---|
| Attack detection rate | **100%** (25/25 adversarial cases) |
| False positive rate | **0%** (8/8 legitimate diffs pass) |
| Scope bypass via path traversal | Blocked at L1 |
| Import aliasing (`import subprocess as sp`) | Blocked at L3 |
| Payload buried in exception handler | Blocked at L3 |
| Payload buried at line 40 | Blocked at L3 |
| `exec()` / `eval()` builtins | Blocked at L3 (hard stop) |
| Writing to `.env`, `.git/**` | Blocked at L1 (hard stop) |
| Agent weakening its own test file | Blocked at L1 |
| Malicious large diff never reaches LLM | L3 fires first, saves ~350ms |

---

## Layers

| Layer | What it checks | Hard stop? | Latency |
|---|---|---|---|
| L1 Scope | Touched files ∈ write_scope; forbidden patterns | Sometimes | <0.1ms |
| L2 Category | Declared edit type matches actual diff shape | No | <0.1ms |
| L3 AST Side-effects | subprocess, socket, requests, os.environ, exec, eval | **Yes** | ~0.1–0.3ms |
| L4 Invariant | SHA-256 of protected files; test suite passes | **Yes** | varies |
| L5 LLM Verifier | Intent alignment for large diffs (>20 lines) | No | ~300–500ms |

**Hard stops** bypass the retry budget and notify the user immediately. Soft rejects consume one retry and return a structured correction telling the agent exactly what to fix.

---

## Installation

```bash
git clone <repo>
cd GATE-M
pip install -e ".[dev]"
```

**Dependencies:** `inotify-simple`, `whatthepatch`, `httpx`, `pytest`

**Requirements:** Linux only (inotify + `sys.addaudithook`), Python 3.11+

**API keys** (for L5 verifier):
```bash
cp .env.example .env
# fill in GROQ_API_KEY and GEMINI_API_KEY
```
- Groq: [console.groq.com](https://console.groq.com) — free tier, 14,400 req/day
- Gemini: [aistudio.google.com/app/apikey](https://aistudio.google.com/app/apikey) — free tier

---

## Usage

### CLI

```bash
# 1. Start a session — declares what the agent is allowed to do
gate-m start \
  --goal "fix null check in validate_user" \
  --write-scope src/auth.py \
  --read-scope "src/**" "tests/**" \
  --forbidden "secrets/**" ".env" \
  --tests tests/unit/test_auth.py \
  --project-root /path/to/project

# 2. Agent submits a tool call, gets approve/reject
gate-m execute '{
  "tool_type": "write",
  "path": "src/auth.py",
  "proposed_diff": "--- a/src/auth.py\n+++ b/src/auth.py\n...",
  "intent": {
    "intent": "add null guard to validate_user",
    "affected_scope": ["src/auth.py::validate_user"],
    "edit_category": "modify",
    "expected_postcondition": "returns False for None input"
  }
}'

# 3. After agent applies the write, run invariant checks
gate-m invariants <snapshot_id>
```

Reads `GROQ_API_KEY` and `GEMINI_API_KEY` from environment.

### Python API

```python
from gate import GATEKernel, CapabilityToken, ToolCall, IntentDeclaration

token = CapabilityToken.create(
    natural_language_goal="fix null check in validate_user",
    read_scope=["src/**", "tests/**"],
    write_scope=["src/auth.py"],
    forbidden=["secrets/**", ".env"],
    must_pass_tests=["tests/test_auth.py"],
    must_not_change={"src/config.py": "<sha256>"},  # from token.build_must_not_change()
)

kernel = GATEKernel(
    token=token,
    project_root="/path/to/project",
    groq_key=os.environ["GROQ_API_KEY"],
    gemini_key=os.environ["GEMINI_API_KEY"],
)

result = kernel.execute_tool(ToolCall(
    tool_type="write",
    path="src/auth.py",
    proposed_diff=unified_diff_string,
    intent=IntentDeclaration(
        intent="add null guard",
        affected_scope=["src/auth.py::validate_user"],
        edit_category="modify",
        expected_postcondition="returns False for None",
    ),
))

if result.approved:
    # apply the write yourself
    Path("src/auth.py").write_text(new_content)
    inv = kernel.run_invariant_checks(result.snapshot_id)
    if not inv.approved:
        print("rolled back:", inv.violation_detail)
```

---

## CapabilityToken fields

| Field | Type | Description |
|---|---|---|
| `natural_language_goal` | str | Human-readable task description, passed to LLM verifier |
| `read_scope` | list[str] | Glob patterns the agent may read |
| `write_scope` | list[str] | **Exact file paths** the agent may write (no globs) |
| `forbidden` | list[str] | Glob patterns hard-blocked for both reads and writes |
| `allowed_edit_categories` | list[str] | `modify`, `add`, `delete`, `refactor` |
| `allowed_new_files` | bool | Whether creating new files is permitted |
| `allowed_new_dependencies` | bool | Whether adding imports/packages is permitted |
| `retry_budget` | int | Max soft rejections before escalation (default 3) |
| `ttl_minutes` | int | Token lifetime (default 30) |
| `must_pass_tests` | list[str] | pytest paths run post-write; failure = rollback |
| `must_not_change` | dict[str,str] | `{filepath: sha256}` — protected files |

---

## Project structure

```
gate/
├── kernel.py       # GATEKernel — main dispatch, snapshot, invariant checks
├── sip_checker.py  # 3-layer SIP enforcement (scope, category, AST side-effects)
├── os_watcher.py   # sys.addaudithook (in-process) + inotify daemon (out-of-process)
├── snapshot.py     # Git stash or file-copy snapshots + rollback
├── verifier.py     # Groq + Gemini LLM verifier (large diffs only)
├── corrector.py    # Structured rejection message builder
├── token.py        # CapabilityToken validation + SHA-256 helpers
├── models.py       # All shared dataclasses
└── cli.py          # gate-m CLI entrypoint

tests/
├── test_sip_checker.py   # 21 unit tests — diff parsing, all 3 SIP layers
├── test_security.py      # 66 adversarial tests — evasion, traversal, injection
└── test_integration.py   # 23 full kernel tests — lifecycle, rollback, TTL, test gate

benchmark.py           # 12-scenario integration benchmark with live LLM
security_benchmark.py  # 33-case security benchmark, 30x repetitions, P50/P95/P99
playground/            # Sample project used by benchmarks
```

---

## Running tests

```bash
# Unit + integration + security tests
python -m pytest tests/ -v

# Basic integration benchmark (uses live LLM if keys set)
export $(grep -v '^#' .env | xargs)
python benchmark.py

# Full security benchmark (30 runs/case, P50/P95/P99 latencies, attack detection rates)
export $(grep -v '^#' .env | xargs)
python security_benchmark.py
```

---

## OS-level watching

Two modes, selected automatically at startup:

### Mode 1 — fanotify FAN_OPEN_PERM (requires `CAP_SYS_ADMIN` / root)

```
agent calls open("src/evil.py", O_WRONLY)
  → kernel fires FAN_OPEN_PERM — syscall is HELD
  → C thread (gate_watcher.so) reads event
  → prefix filter: outside project_root? → FAN_ALLOW immediately (no Python call)
  → inside project_root? → calls Python verdict callback via ctypes
  → Python checks forbidden / write_scope / read_scope
  → C sends FAN_ALLOW or FAN_DENY
  → kernel resumes or fails the syscall — atomically
```

The write either happens or is blocked. There is no window between detection and prevention. Build the C layer with:

```bash
make -C gate/watcher
```

### Mode 2 — audit hook + inotify (fallback, no privileges needed)

- **`sys.addaudithook()`**: fires before `open()` in-process Python calls, can log violations
- **inotify**: daemon thread watching `IN_CLOSE_WRITE`, `IN_CREATE`, `IN_DELETE` — post-hoc, catches out-of-process writes

OSWatcher tries fanotify first and prints which mode is active:
```
[GATE-M] watcher: fanotify FAN_OPEN_PERM (atomic blocking) on /path/to/project
# or
[GATE-M] watcher: fanotify unavailable (errno 1: Operation not permitted) → using inotify fallback
[GATE-M] watcher: audit hook + inotify (post-hoc) on /path/to/project
```

---

## What GATE-M does NOT do

- **No sandboxing** — no container, no seccomp, no namespace isolation
- **No malice detection** — it's a mistake model, not a threat model
- **No prompt injection sanitization**
- **No cross-platform** — Linux only (inotify + audit hook)
- **No behavioral fingerprinting**

If you need isolation guarantees against an actively adversarial agent, run it in a container. GATE-M is the layer that catches an honest-but-confused agent before it breaks things.

---

## Known limitations

- **AST parsing only catches Python code** — a diff that writes a malicious shell script to `deploy.sh` will pass L3 (the script isn't Python). Mitigation: put shell scripts in `write_scope` only if genuinely needed, and use `must_pass_tests` to gate on correctness.
- **write_scope is exact-match only** — globs are supported in `read_scope` and `forbidden` but `write_scope` requires exact file paths. This is intentional: glob write scopes are too easy to exploit.
- **LLM verifier can be wrong** — it fails open on timeout and may approve a bad diff on a bad day. L1–L3 are the real security boundary; the verifier is a correctness check, not a security gate.
- **Retry budget can be gamed** — an agent that always sends hard-stop diffs doesn't consume the budget (by design). But it also never gets approved, so it's stuck.
