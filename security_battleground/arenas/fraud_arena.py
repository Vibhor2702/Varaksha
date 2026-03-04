"""
fraud_arena.py — sends fraud attack payloads to the Varaksha gateway
and records whether each transaction received the expected verdict.
"""
from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

log = logging.getLogger("battleground.fraud_arena")

GATEWAY_URL = "http://127.0.0.1:8080/v1/tx"
REQUEST_TIMEOUT = 20.0  # seconds


@dataclass
class TestResult:
    test_id: str
    arena: str = "fraud"
    attack_type: str = ""
    description: str = ""
    expected_verdict: str = ""
    actual_verdict: str = ""
    risk_score: float = 0.0
    latency_ms: float = 0.0
    pass_or_fail: str = "FAIL"
    error: str = ""


def _verdict_passes(expected: str, actual: str) -> bool:
    """
    Pass logic:
      ALLOW   → actual must be ALLOW (strict: clean txn must not be flagged)
      FLAG    → actual in FLAG or BLOCK (any non-ALLOW detection counts)
      BLOCK   → actual must be BLOCK
    """
    if expected == "ALLOW":
        return actual == "ALLOW"
    if expected == "FLAG":
        return actual in ("FLAG", "BLOCK")
    if expected == "BLOCK":
        return actual == "BLOCK"
    return actual == expected


def run(attacks_path: Path) -> list[TestResult]:
    """Execute all fraud attacks and return results."""
    with attacks_path.open() as f:
        attacks: list[dict] = json.load(f)

    results: list[TestResult] = []
    log.info("Fraud Arena — %d attacks queued → %s", len(attacks), GATEWAY_URL)

    for attack in attacks:
        result = TestResult(
            test_id=attack["attack_id"],
            attack_type=attack["attack_type"],
            description=attack["description"],
            expected_verdict=attack["expected_verdict"],
        )

        log.info(
            "  [%s] %s — expected: %s",
            attack["attack_id"],
            attack["description"][:60],
            attack["expected_verdict"],
        )

        # ── Warmup sequence (e.g. for fan-out tests) ─────────────────────────
        # Send preliminary transactions to prime in-process trackers (e.g.
        # ReceiverDiversityTracker in agent01).  Warmup verdicts are ignored
        # for scoring but errors are logged so failures are visible.
        for i, warmup_payload in enumerate(attack.get("warmup_sequence", [])):
            try:
                warmup_resp = httpx.post(
                    GATEWAY_URL, json=warmup_payload, timeout=REQUEST_TIMEOUT
                )
                log.debug(
                    "  [%s] warmup %d/%d → HTTP %d",
                    attack["attack_id"], i + 1,
                    len(attack["warmup_sequence"]),
                    warmup_resp.status_code,
                )
            except Exception as exc:
                log.warning("  [%s] warmup %d error: %s", attack["attack_id"], i + 1, exc)

        try:
            t0 = time.perf_counter()
            resp = httpx.post(
                GATEWAY_URL,
                json=attack["payload"],
                timeout=REQUEST_TIMEOUT,
            )
            result.latency_ms = (time.perf_counter() - t0) * 1000

            if resp.status_code == 200:
                body: dict[str, Any] = resp.json()
                result.actual_verdict = body.get("verdict", "UNKNOWN")
                result.risk_score = body.get("risk_score", 0.0)
                result.pass_or_fail = (
                    "PASS" if _verdict_passes(result.expected_verdict, result.actual_verdict) else "FAIL"
                )
            else:
                result.actual_verdict = f"HTTP_{resp.status_code}"
                result.error = resp.text[:200]
                result.pass_or_fail = "FAIL"

        except httpx.ConnectError:
            result.error = "Gateway not reachable — is varaksha-gw.exe running on :8080?"
            result.actual_verdict = "UNREACHABLE"
            result.pass_or_fail = "FAIL"
        except Exception as exc:
            result.error = str(exc)
            result.actual_verdict = "ERROR"
            result.pass_or_fail = "FAIL"

        verdict_symbol = "✓" if result.pass_or_fail == "PASS" else "✗"
        log.info(
            "  %s  actual: %-6s  risk: %.4f  latency: %.0fms",
            verdict_symbol,
            result.actual_verdict,
            result.risk_score,
            result.latency_ms,
        )
        results.append(result)

    passed = sum(1 for r in results if r.pass_or_fail == "PASS")
    attacks_detected = sum(
        1 for r in results
        if r.expected_verdict != "ALLOW" and r.pass_or_fail == "PASS"
    )
    false_positives = sum(
        1 for r in results
        if r.expected_verdict == "ALLOW" and r.pass_or_fail == "FAIL"
    )
    log.info(
        "Fraud Arena complete — %d/%d passed | %d attacks detected | %d false positives",
        passed, len(results), attacks_detected, false_positives,
    )
    return results
