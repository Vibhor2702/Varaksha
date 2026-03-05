"""
agent03_decision.py — Weighted Risk Decision + Deterministic Narrative
======================================================================
Aggregates scores from Agents 01 and 02 using the weighted formula from
TEAM_RUST_BRIEF.md and produces the final ALLOW / FLAG / BLOCK verdict
plus a court-ready narrative.

Weighted formula:
    final_score = 0.35×anomaly + 0.35×graph + 0.15×velocity + 0.15×mule_hub

Narrative generation:
    Deterministic signed template — no external AI calls.
    Only scores, patterns, and law section codes appear in the output.
    No UPI IDs, IPs, or user-identifiable data are used.

Inputs (JSON POST /v1/decide):
    CombinedContext { agent01_verdict, agent02_verdict }

Outputs (JSON body):
    FinalVerdict { tx_id, final_score, verdict, narrative, law_refs,
                   gate_final_sig, key_fingerprint }
"""

from __future__ import annotations

import json
import logging
import os
import time
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

try:
    import varaksha_gateway as vg
    RUST_CRYPTO_AVAILABLE = True
except ImportError:
    RUST_CRYPTO_AVAILABLE = False
    logging.warning("varaksha_gateway not found — mock-crypto mode")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
log = logging.getLogger("agent03")

# ─── Config ───────────────────────────────────────────────────────────────────

SIGNING_KEY         = os.getenv("AGENT03_SIGNING_KEY_HEX", "")
AGENT02_VERIFY_KEY  = os.getenv("AGENT02_VERIFYING_KEY_HEX", "")

# Final decision thresholds
BLOCK_THRESHOLD = 0.65
FLAG_THRESHOLD  = 0.45

# BNS / IT Act law mapping (source: IndiaCode official)
LAW_REFS: dict[str, dict[str, str]] = {
    "CIRCULAR":        {"section": "BNS §111",       "description": "Organised crime — money mule circuit", "max_sentence": "Life + min ₹5L fine"},
    "FAN_OUT":         {"section": "BNS §318(4)",     "description": "Cheating (financial fraud)",          "max_sentence": "7 yrs + fine"},
    "HIGH_ANOMALY":    {"section": "IT Act §66C/66D", "description": "Identity theft / online fraud",       "max_sentence": "3 yrs + ₹1L fine"},
    "HIGH_VELOCITY":   {"section": "PMLA §3",         "description": "Money laundering",                    "max_sentence": "7 yrs + ₹5L fine"},
    "PROMPT_INJECTION":{"section": "IT Act §66",      "description": "Computer-related offence",            "max_sentence": "3 yrs + fine"},
}

# ─── Pydantic models ──────────────────────────────────────────────────────────

class Agent01Verdict(BaseModel):
    tx_id:           str
    anomaly_score:   float
    velocity_score:  int
    zscore:          float
    aggregate_score: float
    verdict:         str
    narrative:       str
    gate_a_sig:      str
    key_fingerprint: str
    latency_ms:      float

class Agent02Verdict(BaseModel):
    tx_id:              str
    fan_out_score:      float
    circular_score:     float
    hub_score:          float
    graph_score:        float
    patterns_detected:  list[str]
    sgx_note:           str
    gate_b_sig:         str
    key_fingerprint:    str
    latency_ms:         float

class CombinedContext(BaseModel):
    agent01: Agent01Verdict
    agent02: Agent02Verdict

class FinalVerdict(BaseModel):
    tx_id:           str
    final_score:     float = Field(ge=0.0, le=1.0)
    verdict:         str       # ALLOW | FLAG | BLOCK
    narrative:       str       # zero-PII court-ready explanation
    law_refs:        list[dict]
    gate_final_sig:  str
    key_fingerprint: str
    latency_ms:      float

# ─── Core scoring ─────────────────────────────────────────────────────────────

def compute_final_score(a1: Agent01Verdict, a2: Agent02Verdict) -> float:
    """
    Weighted formula from TEAM_RUST_BRIEF.md:
        0.35×anomaly  + 0.35×graph  + 0.15×velocity_norm  + 0.15×mule_hub
    """
    velocity_norm = min(a1.velocity_score / 100.0, 1.0)
    score = (
        0.35 * a1.anomaly_score
        + 0.35 * a2.graph_score
        + 0.15 * velocity_norm
        + 0.15 * a2.hub_score
    )
    return round(min(max(score, 0.0), 1.0), 4)


def map_law_refs(patterns: list[str], anomaly: float, velocity: int) -> list[dict]:
    refs = []
    seen = set()

    def add(key: str) -> None:
        if key not in seen and key in LAW_REFS:
            seen.add(key)
            refs.append(LAW_REFS[key])

    for p in patterns:
        if p.startswith("CIRCULAR"):
            add("CIRCULAR")
        elif p.startswith("FAN_OUT"):
            add("FAN_OUT")
        elif p.startswith("PROMPT_INJECTION") or "inject" in p.lower():
            add("PROMPT_INJECTION")

    if anomaly >= 0.72:
        add("HIGH_ANOMALY")
    if velocity >= 80:
        add("HIGH_VELOCITY")

    return refs

# ─── Deterministic narrative (signed, reproducible) ──────────────────────────

def _template_narrative(
    verdict: str,
    final_score: float,
    patterns: list[str],
    law_refs: list[dict],
) -> str:
    law_str = "; ".join(f"{r['section']} ({r['description']})" for r in law_refs) or "none identified"
    pat_str = ", ".join(patterns) or "none"
    return (
        f"Varaksha verdict: {verdict} (risk score {final_score:.3f}). "
        f"Patterns detected: {pat_str}. "
        f"Applicable law: {law_str}. "
        f"This output is cryptographically signed and reproducible for court submission."
    )

def generate_narrative(
    verdict: str,
    final_score: float,
    patterns: list[str],
    law_refs: list[dict],
    a1: Agent01Verdict,
    a2: Agent02Verdict,
) -> str:
    """Deterministic signed template — no external AI calls, no data leaves the server."""
    return _template_narrative(verdict, final_score, patterns, law_refs)

# ─── Signature helpers ────────────────────────────────────────────────────────

def verify_agent02_sig(v: Agent02Verdict) -> bool:
    if not RUST_CRYPTO_AVAILABLE or not AGENT02_VERIFY_KEY:
        return True
    payload = v.model_dump(exclude={"gate_b_sig"})
    return vg.verify_payload(json.dumps(payload, sort_keys=True), v.gate_b_sig, AGENT02_VERIFY_KEY)

def sign_verdict(d: dict) -> str:
    if not RUST_CRYPTO_AVAILABLE or not SIGNING_KEY:
        return "mock-sig-agent03"
    return vg.sign_payload(json.dumps(d, sort_keys=True), SIGNING_KEY)

# ─── FastAPI ──────────────────────────────────────────────────────────────────

app = FastAPI(
    title="Varaksha Agent 03 — Decision & Narrative",
    description="Final risk score, verdict, and zero-PII court-ready narrative.",
    version="0.1.0",
)

@app.post("/v1/decide", response_model=FinalVerdict)
async def decide(ctx: CombinedContext) -> FinalVerdict:
    t0 = time.perf_counter()

    # 1. Verify Agent 02 gate signature
    if not verify_agent02_sig(ctx.agent02):
        log.warning("tx_id=%s Agent 02 gate_b_sig invalid", ctx.agent01.tx_id)
        raise HTTPException(status_code=400, detail="gate_b_sig_invalid")

    # 2. Final weighted score
    final_score = compute_final_score(ctx.agent01, ctx.agent02)

    # 3. Verdict
    if final_score >= BLOCK_THRESHOLD:
        verdict = "BLOCK"
    elif final_score >= FLAG_THRESHOLD:
        verdict = "FLAG"
    else:
        verdict = "ALLOW"

    # 4. Law references
    law_refs = map_law_refs(
        ctx.agent02.patterns_detected,
        ctx.agent01.anomaly_score,
        ctx.agent01.velocity_score,
    )

    # 5. Deterministic signed narrative (zero-PII, no external calls)
    narrative = generate_narrative(
        verdict, final_score, ctx.agent02.patterns_detected,
        law_refs, ctx.agent01, ctx.agent02,
    )

    log.info(
        "tx_id=%s final_score=%.4f verdict=%s law_refs=%d",
        ctx.agent01.tx_id, final_score, verdict, len(law_refs),
    )

    latency_ms = round((time.perf_counter() - t0) * 1000, 2)
    fp = SIGNING_KEY[:32] if SIGNING_KEY else "agent03-mock-fp"

    out = {
        "tx_id":          ctx.agent01.tx_id,
        "final_score":    final_score,
        "verdict":        verdict,
        "narrative":      narrative,
        "law_refs":       law_refs,
        "gate_final_sig": "",
        "key_fingerprint": fp,
        "latency_ms":     latency_ms,
    }
    out["gate_final_sig"] = sign_verdict(out)
    return FinalVerdict(**out)

@app.get("/health")
async def health() -> dict:
    return {
        "status":    "ok",
        "agent":     "decision",
        "narrative": "deterministic_template",
    }
