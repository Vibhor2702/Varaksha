"""
injection_arena.py — tests prompt/code injection payloads against the
Varaksha injection detection stack (FAISS semantic index + hardcoded patterns).

Operates entirely offline — no HTTP calls required.
"""
from __future__ import annotations

import json
import logging
import os
import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

log = logging.getLogger("battleground.injection_arena")

# FAISS index lives at data/models relative to project root
_ROOT = Path(__file__).resolve().parents[2]
_INDEX_PATH   = Path(os.getenv("INJECTION_INDEX_PATH",   str(_ROOT / "data/models/injection_index.faiss")))
_STRINGS_PATH = Path(os.getenv("INJECTION_STRINGS_PATH", str(_ROOT / "data/models/injection_strings.json")))

COSINE_THRESHOLD = float(os.getenv("COSINE_THRESHOLD", "0.78"))

# Hardcoded pattern anchors (mirrors adversarial_scan.py HARDCODED_PATTERNS)
_HARDCODED: list[re.Pattern] = [
    re.compile(r"ignore\s+(previous|all|prior)\s+instructions?", re.I),
    re.compile(r"(you are|act as|pretend|roleplay).{0,30}(DAN|admin|root|no.restrict)", re.I),
    re.compile(r"(system|assistant)\s*:\s*(override|bypass|disable)", re.I),
    re.compile(r"admin\s*(override|code|key|auth)", re.I),
    re.compile(r"<\s*script[\s>]", re.I),
    re.compile(r"(drop\s+table|select\s+\*\s+from|insert\s+into|update\s+\w+\s+set)", re.I),
    re.compile(r"(eval|exec|subprocess|os\.system)\s*\(", re.I),
]


@dataclass
class TestResult:
    test_id: str
    arena: str = "injection"
    attack_type: str = ""
    description: str = ""
    expected_result: str = ""
    actual_result: str = ""
    cosine_score: float = 0.0
    hardcoded_match: bool = False
    latency_ms: float = 0.0
    pass_or_fail: str = "FAIL"
    error: str = ""


def _check_hardcoded(text: str) -> bool:
    return any(p.search(text) for p in _HARDCODED)


def _faiss_score(text: str) -> Optional[float]:
    """Return max cosine similarity against the injection FAISS index, or None if unavailable."""
    try:
        import faiss  # type: ignore
        import numpy as np
        from sentence_transformers import SentenceTransformer  # type: ignore
    except ImportError:
        return None

    if not _INDEX_PATH.exists() or not _STRINGS_PATH.exists():
        return None

    try:
        model = _faiss_score._model  # type: ignore  # cached
    except AttributeError:
        log.info("  Loading sentence-transformer model (first run)…")
        from sentence_transformers import SentenceTransformer
        _faiss_score._model = SentenceTransformer("all-MiniLM-L6-v2")  # type: ignore
        model = _faiss_score._model  # type: ignore

    try:
        index = faiss.read_index(str(_INDEX_PATH))
        vec = model.encode([text], convert_to_numpy=True).astype("float32")
        # Normalize for cosine
        faiss.normalize_L2(vec)
        distances, _ = index.search(vec, 1)
        return float(distances[0][0])  # inner product = cosine after normalization
    except Exception as exc:
        log.debug("FAISS scan error: %s", exc)
        return None


def run(attacks_path: Path) -> list[TestResult]:
    """Evaluate all injection payloads."""
    with attacks_path.open() as f:
        attacks: list[dict] = json.load(f)

    results: list[TestResult] = []
    log.info("Injection Arena — %d payloads to scan", len(attacks))
    log.info("  FAISS index: %s", "found" if _INDEX_PATH.exists() else "MISSING — using pattern-only mode")

    for attack in attacks:
        result = TestResult(
            test_id=attack["attack_id"],
            attack_type=attack["attack_type"],
            description=attack.get("description", ""),
            expected_result=attack["expected_result"],
        )
        memo: str = attack["memo"]

        log.info(
            "  [%s] %-50s  expected: %s",
            attack["attack_id"],
            repr(memo[:50]),
            attack["expected_result"],
        )

        try:
            t0 = time.perf_counter()
            hardcoded = _check_hardcoded(memo)
            cos = _faiss_score(memo)
            result.latency_ms = (time.perf_counter() - t0) * 1000

            result.hardcoded_match = hardcoded
            result.cosine_score = cos if cos is not None else 0.0

            # Detection decision: either hardcoded pattern OR FAISS similarity above threshold
            detected = hardcoded or (cos is not None and cos >= COSINE_THRESHOLD)
            result.actual_result = "DETECTED" if detected else "CLEAN"

            # Pass if actual matches expected
            result.pass_or_fail = "PASS" if result.actual_result == result.expected_result else "FAIL"

        except Exception as exc:
            result.error = str(exc)
            result.actual_result = "ERROR"
            result.pass_or_fail = "FAIL"

        verdict_symbol = "✓" if result.pass_or_fail == "PASS" else "✗"
        log.info(
            "  %s  result: %-9s  cosine: %.4f  pattern: %s  latency: %.1fms",
            verdict_symbol,
            result.actual_result,
            result.cosine_score,
            "HIT" if result.hardcoded_match else "miss",
            result.latency_ms,
        )
        results.append(result)

    detected_count = sum(
        1 for r in results
        if r.expected_result == "DETECTED" and r.pass_or_fail == "PASS"
    )
    total_attacks = sum(1 for r in results if r.expected_result == "DETECTED")
    log.info("Injection Arena complete — %d/%d injections blocked", detected_count, total_attacks)
    return results
