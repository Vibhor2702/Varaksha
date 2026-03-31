"""
feed_bridge.py — FastAPI bridge between open banking sources and Varaksha pipeline.

Exposes the API surface the Next.js frontend expects:
  POST /v1/tx                     → score a transaction (wraps Rust /inference)
  GET  /v1/stream                 → SSE live transaction feed (synthetic + live)
  GET  /v1/open-banking/stream    → SSE open banking feed (Setu + Plaid)
  GET  /v1/open-banking/sources   → list configured banking sources + status
  GET  /health                    → liveness check

Architecture:
  Browser → Python bridge (this file) → Rust gateway (/inference)
                                       ↗
  Setu AA → normalizer ──────────────
  Plaid   → normalizer ──────────────

The bridge does three things the Rust gateway can't do alone:
  1. Accepts the rich 24-feature payload from the frontend (/v1/tx)
  2. Calls /update_cache on Rust (HMAC-signed) with the feature vector
  3. Calls /inference on Rust (API key) and returns the verdict

Railway deployment: set root directory to services/open_banking
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
import time
import random
from datetime import datetime, timezone
from typing import AsyncIterator

import httpx
from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from normalizer import NormalizedTransaction
from setu_adapter import SetuAdapter
from plaid_adapter import PlaidAdapter

# ── Logging ───────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").strip().upper(),
    format="%(asctime)s %(levelname)s %(name)s — %(message)s",
)
logger = logging.getLogger("feed_bridge")

# ── Configuration ─────────────────────────────────────────────────────────────

RUST_GATEWAY_URL    = os.getenv("RUST_GATEWAY_URL",  "http://localhost:8080")
VARAKSHA_API_KEY    = os.getenv("VARAKSHA_API_KEY",  "dev-api-key-changeme")
VARAKSHA_UPDATE_SECRET = os.getenv("VARAKSHA_UPDATE_SECRET", "dev-update-secret-changeme")

# ── FastAPI app ───────────────────────────────────────────────────────────────

app = FastAPI(
    title="Varaksha Python Bridge",
    description="Open banking adapter + Rust gateway proxy for the Varaksha frontend",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # tighten in production to your Cloudflare Pages domain
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

# ── Shared adapter instances ──────────────────────────────────────────────────

setu_adapter  = SetuAdapter()
plaid_adapter = PlaidAdapter()

# ── HMAC helper for /update_cache ─────────────────────────────────────────────

def _hmac_sign(body: bytes, secret: str) -> str:
    return hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()

# ── Rust gateway calls ────────────────────────────────────────────────────────

async def _update_cache(client: httpx.AsyncClient, device_id_raw: str, features: list[float]) -> bool:
    """Push feature vector to Rust /update_cache (HMAC signed)."""
    import hashlib as _hs
    hashed_id = _hs.sha256(device_id_raw.encode()).hexdigest()
    payload = {"hashed_device_id": hashed_id, "features": features}
    body    = json.dumps(payload).encode()
    sig     = _hmac_sign(body, VARAKSHA_UPDATE_SECRET)

    try:
        resp = await client.post(
            f"{RUST_GATEWAY_URL}/update_cache",
            content=body,
            headers={
                "Content-Type": "application/json",
                "X-Varaksha-Signature": sig,
            },
            timeout=5,
        )
        return resp.status_code == 200
    except Exception as e:
        logger.warning("update_cache_err: %s", e)
        return False


async def _run_inference(
    client: httpx.AsyncClient,
    transaction_id: str,
    device_id_raw: str,
    amount: float,
) -> dict:
    """Call Rust /inference and return the response dict."""
    payload = {
        "transaction_id": transaction_id,
        "raw_device_id":  device_id_raw,
        "amount":         amount,
    }
    resp = await client.post(
        f"{RUST_GATEWAY_URL}/inference",
        json=payload,
        headers={
            "Content-Type":       "application/json",
            "X-Varaksha-Api-Key": VARAKSHA_API_KEY,
        },
        timeout=8,
    )
    resp.raise_for_status()
    return resp.json()


async def _score_transaction(nt: NormalizedTransaction) -> dict:
    """
    Full pipeline:
      1. Build 24-feature vector
      2. Push to Rust /update_cache
      3. Call Rust /inference
      4. Return enriched result dict
    """
    features = nt.to_feature_vector()
    t0 = time.monotonic()

    async with httpx.AsyncClient() as client:
        await _update_cache(client, nt.raw_device_id, features)
        try:
            result = await _run_inference(
                client, nt.transaction_id, nt.raw_device_id, nt.amount_inr
            )
        except httpx.HTTPStatusError as e:
            logger.warning("inference_http_err status=%s", e.response.status_code)
            result = _fallback_score(nt)
        except Exception as e:
            logger.warning("inference_err: %s", e)
            result = _fallback_score(nt)

    latency_ms = int((time.monotonic() - t0) * 1000)
    return {
        "source":           nt.source,
        "transaction_id":   nt.transaction_id,
        "sender_vpa":       nt.sender_vpa,
        "receiver_vpa":     nt.receiver_vpa,
        "amount_inr":       round(nt.amount_inr, 2),
        "merchant_category":nt.merchant_category,
        "verdict":          result.get("verdict", "ALLOW"),
        "risk_score":       round(result.get("risk_score", 0.1), 4),
        "lgbm_score":       round(result.get("lgbm_score", 0.1), 4),
        "anomaly_score":    round(result.get("anomaly_score", 0.05), 4),
        "graph_reason":     result.get("graph_reason"),
        "latency_ms":       result.get("execution_time_ms", latency_ms),
        "timestamp":        nt.timestamp.isoformat(),
        "tier":             result.get("tier", "cloud"),
    }


def _fallback_score(nt: NormalizedTransaction) -> dict:
    """Deterministic risk score used when Rust gateway is unreachable."""
    amount = nt.amount_inr
    # Simple heuristics for demo fallback
    if amount > 40_000 or "agent" in nt.receiver_vpa.lower() or "cash" in nt.receiver_vpa.lower():
        return {"verdict": "BLOCK", "risk_score": 0.91, "lgbm_score": 0.89, "anomaly_score": 0.85}
    if amount > 10_000 or "wallet" in nt.receiver_vpa.lower() or "crypto" in nt.receiver_vpa.lower():
        return {"verdict": "FLAG",  "risk_score": 0.62, "lgbm_score": 0.58, "anomaly_score": 0.45}
    return {"verdict": "ALLOW", "risk_score": 0.12 + (hash(nt.transaction_id) % 20) / 100,
            "lgbm_score": 0.10, "anomaly_score": 0.04}


# ─────────────────────────────────────────────────────────────────────────────
# Pydantic models
# ─────────────────────────────────────────────────────────────────────────────

class TxRequest(BaseModel):
    """Frontend /v1/tx payload — mirrors the existing frontend form."""
    vpa:                      str   = Field(..., description="Sender VPA")
    amount:                   float
    merchant_category:        str   = "FOOD"
    transaction_type:         str   = "DEBIT"
    device_type:              str   = "ANDROID"
    hour_of_day:              int   = 12
    day_of_week:              int   = 1
    transactions_last_1h:     int   = 1
    transactions_last_24h:    int   = 3
    amount_zscore:            float = 0.0
    gps_delta_km:             float = 0.0
    is_new_device:            bool  = False
    is_new_merchant:          bool  = False
    balance_drain_ratio:      float = 0.0
    account_age_days:         int   = 365
    previous_failed_attempts: int   = 0
    transfer_cashout_flag:    int   = 0


# ─────────────────────────────────────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    """Liveness check."""
    try:
        async with httpx.AsyncClient(timeout=3) as client:
            r = await client.get(f"{RUST_GATEWAY_URL}/health")
            rust_ok = r.status_code == 200
    except Exception:
        rust_ok = False
    return {"status": "ok", "rust_gateway": "up" if rust_ok else "unreachable"}


@app.post("/v1/tx")
async def score_transaction(payload: TxRequest):
    """
    Score a transaction from the frontend Intelligence Sandbox.
    Wraps Rust /inference with feature vector injection via /update_cache.
    """
    from normalizer import NormalizedTransaction as NT, AMOUNT_MEAN_INR, AMOUNT_STD_INR
    from datetime import datetime, timezone

    # Map frontend payload to 24-feature vector (feature_manifest schema)
    enc_device   = {"ANDROID": 0, "IOS": 2, "HARMONY": 1}.get(payload.device_type.upper(), 0)
    enc_txn_type = {"BILL PAYMENT": 0, "P2M": 1, "P2P": 2, "RECHARGE": 3}.get(payload.transaction_type.upper(), 2)

    features: list[float] = [
        float(payload.amount),                         # 0 amount
        float(payload.hour_of_day),                    # 1 hour_of_day
        float(payload.day_of_week),                    # 2 day_of_week
        1.0 if payload.day_of_week >= 5 else 0.0,      # 3 is_weekend
        1.0,                                            # 4 device_txn_count_10m
        float(payload.transactions_last_1h),            # 5 device_txn_count_1h
        float(payload.transactions_last_24h) // 4,     # 6 device_txn_count_6h
        float(payload.transactions_last_24h),           # 7 device_txn_count_24h
        float(payload.amount_zscore),                   # 8 device_amount_zscore_24h
        1.0,                                            # 9 receiver_unique_senders_10m
        1.0,                                            # 10 receiver_txn_count_1h
        float(payload.transactions_last_24h),           # 11 receiver_txn_count_24h
        1.0,                                            # 12 receiver_unique_senders_1h
        float(payload.amount_zscore),                   # 13 amount_zscore_global
        float(1 if payload.is_new_device else 0),       # 14 is_new_device
        float(1 if payload.is_new_merchant else 0),     # 15 is_new_receiver
        float(enc_txn_type),                            # 16 enc_transaction_type
        float(enc_device),                              # 17 enc_device_type
        0.0,                                            # 18 enc_network_type
        0.0,                                            # 19 enc_sender_bank
        0.0,                                            # 20 enc_receiver_bank
        0.0,                                            # 21 is_high_risk_corridor
        float(payload.transactions_last_24h),           # 22 txn_frequency
        1.0,                                            # 23 days_since_last_txn
    ]

    txn_id    = f"TXN-{int(time.time() * 1000)}"
    device_id = payload.vpa

    t0 = time.monotonic()
    async with httpx.AsyncClient() as client:
        await _update_cache(client, device_id, features)
        try:
            result = await _run_inference(client, txn_id, device_id, payload.amount)
        except Exception as e:
            logger.warning("tx_inference_err: %s", e)
            raise HTTPException(status_code=502, detail=str(e))

    latency_us = int((time.monotonic() - t0) * 1_000_000)
    return {
        "verdict":    result.get("verdict", "ALLOW"),
        "risk_score": result.get("risk_score", 0.1),
        "lgbm_score": result.get("lgbm_score", 0.1),
        "anomaly_score": result.get("anomaly_score", 0.05),
        "trace_id":   result.get("hashed_txn_id", txn_id),
        "vpa_hash":   result.get("hashed_txn_id", ""),
        "latency_us": latency_us,
        "graph_reason": result.get("graph_reason"),
        "tier":       result.get("tier", "cloud"),
    }


# ── SSE helpers ───────────────────────────────────────────────────────────────

def _sse_event(data: dict) -> str:
    return f"data: {json.dumps(data)}\n\n"


async def _synthetic_feed() -> AsyncIterator[str]:
    """Deterministic synthetic feed (fallback for /v1/stream)."""
    senders   = ["ravi.kumar@axisbank", "priya.sharma@okicici", "suresh.patel@ybl",
                  "anita.rao@axisbank",  "mohan.verma@okhdfc",  "kavitha.n@paytm"]
    receivers = ["kirana.store@okhdfc", "dmart.retail@ybl",    "fuel.pump@okaxis",
                  "swiggy.merchant@icici", "railway.prs@ybl",  "cashback.offer@okaxis"]
    amounts   = [120, 499, 1200, 4750, 890, 2400, 340, 7800, 1100, 60000, 310, 5500]
    cats      = ["FOOD", "UTILITY", "ECOM", "GAMBLING", "TRAVEL"]
    seq = 0
    while True:
        idx = seq % len(senders)
        amt = amounts[seq % len(amounts)]
        is_new_dev = (seq % 10 == 3)
        if amt > 50000 and is_new_dev:
            verdict, risk = "BLOCK", 0.91
        elif amt > 30000 or is_new_dev:
            verdict, risk = "FLAG", round(0.55 + (idx % 3) * 0.08, 2)
        else:
            verdict, risk = "ALLOW", round(0.08 + (idx % 7) * 0.05, 2)
        row = {
            "time":     datetime.now(timezone.utc).strftime("%H:%M:%S"),
            "sender":   senders[idx],
            "receiver": receivers[idx % len(receivers)],
            "amount":   amt,
            "category": cats[idx % len(cats)],
            "verdict":  verdict,
            "risk":     risk,
        }
        yield _sse_event(row)
        seq += 1
        await asyncio.sleep(2.2)


@app.get("/v1/stream")
async def live_stream(request: Request):
    """SSE live transaction feed consumed by Module B in the frontend."""
    async def generator():
        async for chunk in _synthetic_feed():
            if await request.is_disconnected():
                break
            yield chunk

    return StreamingResponse(
        generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@app.get("/v1/open-banking/stream")
async def open_banking_stream(
    request: Request,
    source: str = "both",   # "setu" | "plaid" | "both"
):
    """
    SSE stream of open banking transactions from Setu and/or Plaid,
    normalised and scored through the Varaksha ML pipeline.
    """

    async def generator():
        # Pre-load initial batch
        tasks = []
        if source in ("setu", "both"):
            tasks.append(setu_adapter.fetch_transactions(days=7))
        if source in ("plaid", "both"):
            tasks.append(plaid_adapter.fetch_transactions(days=7))

        batches = await asyncio.gather(*tasks, return_exceptions=True)
        for batch in batches:
            if isinstance(batch, Exception):
                logger.warning("ob_batch_err: %s", batch)
                continue
            for nt in batch:
                if await request.is_disconnected():
                    return
                try:
                    scored = await _score_transaction(nt)
                    yield _sse_event(scored)
                    await asyncio.sleep(0.4)  # gentle pace for initial load
                except Exception as e:
                    logger.debug("ob_score_err: %s", e)

        # Then stream new transactions as they arrive
        setu_gen  = setu_adapter.stream(poll_interval=8.0)
        plaid_gen = plaid_adapter.stream(poll_interval=10.0)

        async def score_and_yield(gen):
            async for nt in gen:
                if await request.is_disconnected():
                    return
                try:
                    scored = await _score_transaction(nt)
                    yield _sse_event(scored)
                except Exception as e:
                    logger.debug("ob_stream_score_err: %s", e)

        # Merge both sources with asyncio
        async def merge():
            setu_q:  asyncio.Queue = asyncio.Queue(maxsize=50)
            plaid_q: asyncio.Queue = asyncio.Queue(maxsize=50)

            async def feed_queue(gen, q):
                async for item in gen:
                    await q.put(item)
                await q.put(None)  # sentinel

            if source in ("setu", "both"):
                asyncio.create_task(feed_queue(setu_gen, setu_q))
            if source in ("plaid", "both"):
                asyncio.create_task(feed_queue(plaid_gen, plaid_q))

            queues = []
            if source in ("setu",  "both"): queues.append(setu_q)
            if source in ("plaid", "both"): queues.append(plaid_q)

            done = set()
            while len(done) < len(queues):
                for i, q in enumerate(queues):
                    if i in done:
                        continue
                    try:
                        item = q.get_nowait()
                        if item is None:
                            done.add(i)
                        else:
                            yield item
                    except asyncio.QueueEmpty:
                        pass
                await asyncio.sleep(0.5)

        async for nt in merge():
            if await request.is_disconnected():
                return
            try:
                scored = await _score_transaction(nt)
                yield _sse_event(scored)
            except Exception as e:
                logger.debug("ob_merge_err: %s", e)

    return StreamingResponse(
        generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@app.get("/v1/open-banking/sources")
async def open_banking_sources():
    """Return configured open banking sources and their status."""
    from setu_adapter import SETU_CLIENT_ID
    from plaid_adapter import PLAID_CLIENT_ID

    return {
        "sources": [
            {
                "id":          "setu",
                "name":        "Setu Account Aggregator",
                "country":     "India",
                "standard":    "RBI AA Framework (FIP/FIU)",
                "description": "India's open banking standard — provides UPI transaction history, bank statements, and real-time account data via consent-based access.",
                "live":        bool(SETU_CLIENT_ID),
                "mode":        "live" if SETU_CLIENT_ID else "synthetic",
                "data_format": "FIP JSON (AA standard)",
                "logo_hint":   "setu",
                "url":         "https://bridge.setu.co",
            },
            {
                "id":          "plaid",
                "name":        "Plaid Open Banking",
                "country":     "Global (17 countries)",
                "standard":    "PSD2 / Open Banking (12,000+ institutions)",
                "description": "International open banking network — normalised to UPI feature format to demonstrate Varaksha works across banking standards.",
                "live":        bool(PLAID_CLIENT_ID),
                "mode":        "live" if PLAID_CLIENT_ID else "synthetic",
                "data_format": "Plaid Transaction object",
                "logo_hint":   "plaid",
                "url":         "https://plaid.com",
            },
        ]
    }


# ── Entrypoint ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", "8000"))
    uvicorn.run("feed_bridge:app", host="0.0.0.0", port=port, reload=False, log_level="info")
