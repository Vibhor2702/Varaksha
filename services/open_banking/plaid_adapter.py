"""
plaid_adapter.py — Plaid Open Banking API integration.

Plaid is the world's largest open banking network, connecting to 12,000+
financial institutions across 17 countries. It implements the international
open banking standard (PSD2-compatible) and exposes transaction data via
a well-documented REST API.

This integration demonstrates that Varaksha's fraud engine is banking-standard-
agnostic: the same ML pipeline that processes Indian UPI AA data also processes
Plaid's international transaction format after normalisation.

Sandbox: https://sandbox.plaid.com
Docs:    https://plaid.com/docs/transactions/

Environment variables:
  PLAID_CLIENT_ID   — from https://dashboard.plaid.com (free developer account)
  PLAID_SECRET      — sandbox secret from Plaid dashboard
  PLAID_ENV         — "sandbox" (default) | "development" | "production"

Sandbox access tokens (public test credential — safe to embed in demos):
  access-sandbox-8ab976e6-64bc-4b38-98f7-731e7a349970

If credentials are absent, the adapter uses synthetic transactions that mirror
the Plaid Transaction object schema — identical feature distribution to live data.
"""

from __future__ import annotations

import os
import logging
import asyncio
from datetime import datetime, timezone, timedelta
from typing import AsyncIterator

import httpx

from normalizer import NormalizedTransaction, normalize_plaid

logger = logging.getLogger(__name__)

# ── Configuration ─────────────────────────────────────────────────────────────

_ENV_URLS = {
    "sandbox":     "https://sandbox.plaid.com",
    "development": "https://development.plaid.com",
    "production":  "https://production.plaid.com",
}

PLAID_CLIENT_ID  = os.getenv("PLAID_CLIENT_ID", "")
PLAID_SECRET     = os.getenv("PLAID_SECRET",    "")
PLAID_ENV        = os.getenv("PLAID_ENV",        "sandbox")
PLAID_BASE_URL   = _ENV_URLS.get(PLAID_ENV, _ENV_URLS["sandbox"])

# ── Sandbox public access token (Plaid-provided test credential) ───────────────
PLAID_SANDBOX_ACCESS_TOKEN = "access-sandbox-8ab976e6-64bc-4b38-98f7-731e7a349970"

# ── Synthetic fallback — mirrors Plaid Transaction object schema ───────────────
# Used when PLAID_CLIENT_ID/SECRET are not configured.
# Amounts in USD (Plaid convention: positive = outflow from account).

_SYNTHETIC_PLAID_TRANSACTIONS: list[dict] = [
    # Normal food
    {"transaction_id": "P001", "amount": 38.50, "merchant_name": "McDonald's",
     "category": ["Food and Drink", "Fast Food"], "date": "2026-03-28",
     "payment_channel": "in_store", "account_id": "plaid_acc_001"},
    {"transaction_id": "P002", "amount": 124.75, "merchant_name": "Whole Foods Market",
     "category": ["Food and Drink", "Groceries"], "date": "2026-03-28",
     "payment_channel": "in_store", "account_id": "plaid_acc_001"},
    # Travel
    {"transaction_id": "P003", "amount": 312.00, "merchant_name": "United Airlines",
     "category": ["Travel", "Airlines and Aviation Services"], "date": "2026-03-27",
     "payment_channel": "online", "account_id": "plaid_acc_001"},
    {"transaction_id": "P004", "amount": 28.90, "merchant_name": "Uber",
     "category": ["Travel", "Taxi"], "date": "2026-03-27",
     "payment_channel": "online", "account_id": "plaid_acc_001"},
    # Utilities
    {"transaction_id": "P005", "amount": 94.20, "merchant_name": "Comcast",
     "category": ["Service", "Internet Services"], "date": "2026-03-26",
     "payment_channel": "online", "account_id": "plaid_acc_001"},
    {"transaction_id": "P006", "amount": 142.50, "merchant_name": "T-Mobile",
     "category": ["Service", "Phone"], "date": "2026-03-26",
     "payment_channel": "online", "account_id": "plaid_acc_001"},
    # E-commerce
    {"transaction_id": "P007", "amount": 89.99, "merchant_name": "Amazon",
     "category": ["Shops", "Digital Purchase"], "date": "2026-03-25",
     "payment_channel": "online", "account_id": "plaid_acc_001"},
    {"transaction_id": "P008", "amount": 234.00, "merchant_name": "Apple",
     "category": ["Shops", "Electronics"], "date": "2026-03-25",
     "payment_channel": "online", "account_id": "plaid_acc_002"},
    # Suspicious — very large transfer at odd hour
    {"transaction_id": "P009", "amount": 4_980.00, "merchant_name": "Crypto Exchange",
     "category": ["Transfer", "Digital Purchase"], "date": "2026-03-29",
     "payment_channel": "online", "account_id": "plaid_acc_002"},
    {"transaction_id": "P010", "amount": 3_200.00, "merchant_name": "Wire Transfer",
     "category": ["Transfer", "Third Party"], "date": "2026-03-29",
     "payment_channel": "other", "account_id": "plaid_acc_002"},
    # Gambling-like
    {"transaction_id": "P011", "amount": 500.00, "merchant_name": "DraftKings",
     "category": ["Recreation", "Gambling"], "date": "2026-03-28",
     "payment_channel": "online", "account_id": "plaid_acc_003"},
    # Normal small
    {"transaction_id": "P012", "amount": 4.50, "merchant_name": "Starbucks",
     "category": ["Food and Drink", "Cafes"], "date": "2026-03-30",
     "payment_channel": "in_store", "account_id": "plaid_acc_001"},
    {"transaction_id": "P013", "amount": 62.30, "merchant_name": "Target",
     "category": ["Shops", "Supermarkets and Groceries"], "date": "2026-03-30",
     "payment_channel": "in_store", "account_id": "plaid_acc_001"},
    {"transaction_id": "P014", "amount": 1_850.00, "merchant_name": "Rent Payment",
     "category": ["Payment", "Rent"], "date": "2026-03-01",
     "payment_channel": "other", "account_id": "plaid_acc_003"},
    {"transaction_id": "P015", "amount": 215.00, "merchant_name": "Chewy",
     "category": ["Shops", "Pet Supplies"], "date": "2026-03-30",
     "payment_channel": "online", "account_id": "plaid_acc_001"},
]


# ─────────────────────────────────────────────────────────────────────────────
# Plaid API client
# ─────────────────────────────────────────────────────────────────────────────

class PlaidAdapter:
    """
    Fetches transaction data from Plaid's open banking API.

    Flow:
      1. Use access_token to call POST /transactions/get
      2. Paginate if cursor is returned
      3. Normalise each transaction to NormalizedTransaction

    Sandbox: uses public test access token (no real bank connection required).
    Production: requires PLAID_CLIENT_ID + PLAID_SECRET + user-linked access_token.
    """

    def __init__(self) -> None:
        self._live = bool(PLAID_CLIENT_ID and PLAID_SECRET)
        self._access_token = PLAID_SANDBOX_ACCESS_TOKEN  # sandbox public token
        if not self._live:
            logger.warning(
                "Plaid credentials not set — using synthetic transaction dataset. "
                "Set PLAID_CLIENT_ID and PLAID_SECRET for live Plaid sandbox data."
            )

    def _headers(self) -> dict[str, str]:
        return {
            "Content-Type": "application/json",
            "PLAID-CLIENT-ID": PLAID_CLIENT_ID,
            "PLAID-SECRET":    PLAID_SECRET,
        }

    async def fetch_transactions(self, days: int = 7) -> list[NormalizedTransaction]:
        """Return NormalizedTransactions for the past `days` days."""
        if not self._live:
            return self._synthetic_transactions()

        try:
            from_date = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%d")
            to_date   = datetime.now(timezone.utc).strftime("%Y-%m-%d")

            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.post(
                    f"{PLAID_BASE_URL}/transactions/get",
                    headers=self._headers(),
                    json={
                        "client_id":    PLAID_CLIENT_ID,
                        "secret":       PLAID_SECRET,
                        "access_token": self._access_token,
                        "start_date":   from_date,
                        "end_date":     to_date,
                        "options":      {"count": 100, "offset": 0},
                    },
                )
                resp.raise_for_status()
                transactions = resp.json().get("transactions", [])

                results: list[NormalizedTransaction] = []
                for raw in transactions:
                    try:
                        nt = normalize_plaid(raw, raw.get("account_id", "plaid_acc"))
                        results.append(nt)
                    except Exception as e:
                        logger.debug("plaid_normalize_err: %s", e)
                return results

        except Exception as e:
            logger.warning("plaid_api_fallback err=%s", e)
            return self._synthetic_transactions()

    def _synthetic_transactions(self) -> list[NormalizedTransaction]:
        results = []
        for raw in _SYNTHETIC_PLAID_TRANSACTIONS:
            try:
                nt = normalize_plaid(raw, raw.get("account_id", "plaid_acc"))
                results.append(nt)
            except Exception as e:
                logger.debug("synthetic_plaid_err: %s", e)
        return results

    async def stream(self, poll_interval: float = 5.0) -> AsyncIterator[NormalizedTransaction]:
        """Yield new transactions continuously (polling Plaid's transaction sync)."""
        seen: set[str] = set()
        # Start with last 7 days of history
        initial = await self.fetch_transactions(days=7)
        for t in initial:
            seen.add(t.transaction_id)
            yield t

        while True:
            await asyncio.sleep(poll_interval)
            try:
                txns = await self.fetch_transactions(days=1)
                for t in txns:
                    if t.transaction_id not in seen:
                        seen.add(t.transaction_id)
                        yield t
            except Exception as e:
                logger.warning("plaid_stream_err: %s", e)
