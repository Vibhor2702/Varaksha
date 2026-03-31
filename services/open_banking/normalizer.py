"""
normalizer.py — Maps raw banking API payloads to the Varaksha 24-feature vector.

Feature schema (from models/feature_manifest.json, n_features=24):
  0  amount
  1  hour_of_day
  2  day_of_week
  3  is_weekend
  4  device_txn_count_10m
  5  device_txn_count_1h
  6  device_txn_count_6h
  7  device_txn_count_24h
  8  device_amount_zscore_24h
  9  receiver_unique_senders_10m
 10  receiver_txn_count_1h
 11  receiver_txn_count_24h
 12  receiver_unique_senders_1h
 13  amount_zscore_global
 14  is_new_device
 15  is_new_receiver
 16  enc_transaction_type   (Bill Payment=0, P2M=1, P2P=2, Recharge=3)
 17  enc_device_type        (Android=0, Harmony OS=1, iOS=2)
 18  enc_network_type       (UNKNOWN=0)
 19  enc_sender_bank        (UNKNOWN=0)
 20  enc_receiver_bank      (UNKNOWN=0)
 21  is_high_risk_corridor
 22  txn_frequency
 23  days_since_last_txn

Supports two source formats:
  - Setu Account Aggregator (FIP JSON — India AA standard)
  - Plaid Transactions (international open banking)
"""

from __future__ import annotations

import re
import math
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Optional


# ── Global UPI amount distribution (from training corpus) ────────────────────
AMOUNT_MEAN_INR = 3_200.0
AMOUNT_STD_INR  = 8_500.0
USD_TO_INR      = 83.5   # approximate; override with live rate if available

N_FEATURES = 24

# ── UPI bank suffix → encoded index (extends UNKNOWN=0 default) ──────────────
BANK_ENC: dict[str, int] = {
    "UNKNOWN": 0,
}

# ── High-risk sender/receiver bank pairs (from feature_manifest.json) ─────────
HIGH_RISK_CORRIDORS: list[tuple[str, str]] = [
    # Add pairs from manifest's high_risk_corridors if present
]


# ─────────────────────────────────────────────────────────────────────────────
# Unified transaction record (source-agnostic)
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class NormalizedTransaction:
    """Source-agnostic representation of a banking transaction."""
    source: str                       # "setu" | "plaid"
    transaction_id: str
    raw_device_id: str                # account number / account_id used as device surrogate

    # Core fields
    sender_vpa: str
    receiver_vpa: str
    amount_inr: float
    timestamp: datetime
    merchant_category: str            # FOOD | UTILITY | ECOM | GAMBLING | TRAVEL | P2P
    transaction_type: str             # P2P | P2M | Bill Payment | Recharge
    device_type: str                  # Android | iOS | Harmony OS
    is_new_receiver: bool
    is_new_device: bool
    sender_bank: str
    receiver_bank: str

    # Context (computed from statement history if available)
    device_txn_count_24h: int = 5
    device_txn_count_6h:  int = 2
    device_txn_count_1h:  int = 1
    device_txn_count_10m: int = 1
    device_amount_zscore_24h: float = 0.0
    receiver_txn_count_24h: int = 1
    receiver_txn_count_1h:  int = 1
    receiver_unique_senders_1h:  int = 1
    receiver_unique_senders_10m: int = 1
    txn_frequency: int = 1
    days_since_last_txn: float = 1.0

    def to_feature_vector(self) -> list[float]:
        """Return the ordered 24-element feature vector for ONNX inference."""
        amount = self.amount_inr
        dt = self.timestamp
        hour = dt.hour
        dow  = dt.weekday()   # 0=Monday … 6=Sunday
        is_weekend = 1.0 if dow >= 5 else 0.0

        amount_zscore = (amount - AMOUNT_MEAN_INR) / max(AMOUNT_STD_INR, 1e-6)
        amount_zscore = max(-5.0, min(5.0, amount_zscore))

        enc_txn_type = {
            "Bill Payment": 0,
            "P2M": 1,
            "P2P": 2,
            "Recharge": 3,
        }.get(self.transaction_type, 2)   # default P2P

        enc_device = {
            "Android":    0,
            "Harmony OS": 1,
            "iOS":        2,
        }.get(self.device_type, 0)

        enc_sender_bank   = BANK_ENC.get(self.sender_bank,   0)
        enc_receiver_bank = BANK_ENC.get(self.receiver_bank, 0)

        is_high_risk = 1.0 if (
            (self.sender_bank, self.receiver_bank) in HIGH_RISK_CORRIDORS
        ) else 0.0

        return [
            float(amount),                               # 0
            float(hour),                                 # 1
            float(dow),                                  # 2
            float(is_weekend),                           # 3
            float(self.device_txn_count_10m),            # 4
            float(self.device_txn_count_1h),             # 5
            float(self.device_txn_count_6h),             # 6
            float(self.device_txn_count_24h),            # 7
            float(self.device_amount_zscore_24h),        # 8
            float(self.receiver_unique_senders_10m),     # 9
            float(self.receiver_txn_count_1h),           # 10
            float(self.receiver_txn_count_24h),          # 11
            float(self.receiver_unique_senders_1h),      # 12
            float(amount_zscore),                        # 13
            float(1 if self.is_new_device else 0),       # 14
            float(1 if self.is_new_receiver else 0),     # 15
            float(enc_txn_type),                         # 16
            float(enc_device),                           # 17
            0.0,                                         # 18  enc_network_type (UNKNOWN)
            float(enc_sender_bank),                      # 19
            float(enc_receiver_bank),                    # 20
            float(is_high_risk),                         # 21
            float(self.txn_frequency),                   # 22
            float(self.days_since_last_txn),             # 23
        ]


# ─────────────────────────────────────────────────────────────────────────────
# Setu Account Aggregator normalizer
# ─────────────────────────────────────────────────────────────────────────────

# Merchant-category patterns inferred from UPI narration text
_NARRATION_CATEGORY: list[tuple[re.Pattern, str]] = [
    (re.compile(r"ZOMATO|SWIGGY|FOOD|RESTAU|CAFE|HOTEL|BHOJAN", re.I), "FOOD"),
    (re.compile(r"ELECTRIC|WATER|GAS|BILL|BSNL|JIO|AIRTEL|DTH|RECHARGE", re.I), "UTILITY"),
    (re.compile(r"AMAZON|FLIPKART|MYNTRA|AJIO|MEESHO|SHOP|STORE|MART", re.I), "ECOM"),
    (re.compile(r"TRAVEL|IRCTC|RAILWAY|REDBUS|MAKEMYTRIP|OLA|UBER|RAPIDO", re.I), "TRAVEL"),
    (re.compile(r"GAMEZ?|RUMMY|DREAM11|MPL|LOTTERY|CASINO|BET", re.I),           "GAMBLING"),
]

def _category_from_narration(narration: str) -> str:
    for pattern, cat in _NARRATION_CATEGORY:
        if pattern.search(narration):
            return cat
    return "P2P"   # default: person-to-person

def _vpa_from_narration(narration: str, fallback_prefix: str) -> str:
    """Extract a VPA from a UPI narration string like 'UPI/vpa@bank/Remarks'."""
    m = re.search(r'UPI/([A-Za-z0-9._@-]+)/?' , narration)
    if m:
        return m.group(1).lower()
    # Synthesise a deterministic VPA from merchant hint
    slug = re.sub(r"[^a-z0-9]", "", narration.lower())[:12] or fallback_prefix
    return f"{slug}@upi"

def _bank_from_narration(narration: str) -> str:
    banks = {
        "AXIS":   "axisbank",
        "HDFC":   "okhdfc",
        "ICICI":  "okicici",
        "SBI":    "sbi",
        "KOTAK":  "kotak",
        "YES":    "yesbank",
        "PAYTM":  "paytm",
        "GPAY":   "okicici",
    }
    upper = narration.upper()
    for key, val in banks.items():
        if key in upper:
            return val
    return "UNKNOWN"


def normalize_setu(raw: dict, account_id: str, history: list[dict] | None = None) -> NormalizedTransaction:
    """
    Map a single Setu AA FIP transaction record to a NormalizedTransaction.

    Expected raw fields (FIP/FIU Account Statement format):
      amount, narration, date, currentBalance, type (DEBIT|CREDIT), mode
    """
    amount_raw = float(raw.get("amount", 0.0))
    is_debit   = raw.get("type", "DEBIT").upper() == "DEBIT"
    amount_inr = amount_raw if is_debit else 0.0  # only score outgoing flows

    narration  = raw.get("narration", raw.get("description", "UPI/"))
    date_str   = raw.get("date", raw.get("valueDate", datetime.now(timezone.utc).isoformat()))

    try:
        ts = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
    except Exception:
        ts = datetime.now(timezone.utc)

    category   = _category_from_narration(narration)
    txn_type   = "P2P" if category == "P2P" else "P2M"
    receiver_vpa = _vpa_from_narration(narration, "merchant")
    sender_bank  = _bank_from_narration(account_id)
    receiver_bank = _bank_from_narration(narration)

    # Compute velocity stats from statement history if provided
    dtx24, dtx6, dtx1, dtx10 = 5, 2, 1, 1
    if history:
        same_day = [h for h in history if h.get("date", "")[:10] == date_str[:10]]
        dtx24 = len(same_day)
        # Rough velocity approximations
        dtx6  = max(1, dtx24 // 4)
        dtx1  = max(1, dtx6 // 6)
        dtx10 = 1

    balance = float(raw.get("currentBalance", raw.get("balance", 50_000.0)))
    drain   = min(1.0, amount_inr / max(balance, 1.0)) if amount_inr > 0 else 0.0

    return NormalizedTransaction(
        source="setu",
        transaction_id=raw.get("txnId", raw.get("transactionId", f"setu-{hash(narration)}")),
        raw_device_id=account_id,
        sender_vpa=f"{account_id}@upi",
        receiver_vpa=receiver_vpa,
        amount_inr=amount_inr,
        timestamp=ts,
        merchant_category=category,
        transaction_type=txn_type,
        device_type="Android",    # AA transactions are mobile by definition
        is_new_receiver=False,    # Setu doesn't expose this; conservative default
        is_new_device=False,
        sender_bank=sender_bank,
        receiver_bank=receiver_bank,
        device_txn_count_24h=dtx24,
        device_txn_count_6h=dtx6,
        device_txn_count_1h=dtx1,
        device_txn_count_10m=dtx10,
        device_amount_zscore_24h=0.0,
        txn_frequency=dtx24,
        days_since_last_txn=1.0,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Plaid Transactions normalizer
# ─────────────────────────────────────────────────────────────────────────────

_PLAID_CATEGORY_MAP: dict[str, str] = {
    "Food and Drink":              "FOOD",
    "Restaurants":                 "FOOD",
    "Fast Food":                   "FOOD",
    "Travel":                      "TRAVEL",
    "Airlines and Aviation Services": "TRAVEL",
    "Taxi":                        "TRAVEL",
    "Utilities":                   "UTILITY",
    "Phone":                       "UTILITY",
    "Internet":                    "UTILITY",
    "Recreation":                  "GAMBLING",
    "Gambling":                    "GAMBLING",
    "Shops":                       "ECOM",
    "Digital Purchase":            "ECOM",
    "Clothing and Accessories":    "ECOM",
}

def _plaid_category(categories: list[str]) -> str:
    for cat in categories:
        mapped = _PLAID_CATEGORY_MAP.get(cat)
        if mapped:
            return mapped
    return "ECOM"

def _plaid_txn_type(payment_channel: str, categories: list[str]) -> str:
    if "Transfer" in categories or payment_channel == "other":
        return "P2P"
    if payment_channel == "online":
        return "P2M"
    return "P2M"


def normalize_plaid(raw: dict, account_id: str) -> NormalizedTransaction:
    """
    Map a single Plaid Transaction object to a NormalizedTransaction.

    Expected raw fields (Plaid Transaction object):
      transaction_id, amount (USD, positive=outflow), name, merchant_name,
      category (list[str]), date (YYYY-MM-DD), payment_channel, account_id
    """
    amount_usd = float(raw.get("amount", 0.0))
    amount_inr = abs(amount_usd) * USD_TO_INR   # Plaid: positive = outflow

    categories = raw.get("category", ["Shops"])
    date_str   = raw.get("date", datetime.now(timezone.utc).strftime("%Y-%m-%d"))

    try:
        ts = datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except Exception:
        ts = datetime.now(timezone.utc)

    merchant = (raw.get("merchant_name") or raw.get("name") or "merchant").lower()
    slug      = re.sub(r"[^a-z0-9]", "", merchant)[:14] or "merchant"
    receiver_vpa = f"{slug}@upi"   # synthesise a UPI-style VPA

    category  = _plaid_category(categories)
    txn_type  = _plaid_txn_type(raw.get("payment_channel", "in_store"), categories)
    device_os = "iOS" if "apple" in merchant else "Android"

    return NormalizedTransaction(
        source="plaid",
        transaction_id=raw.get("transaction_id", f"plaid-{hash(merchant)}-{date_str}"),
        raw_device_id=account_id,
        sender_vpa=f"user.{account_id[:8]}@upi",
        receiver_vpa=receiver_vpa,
        amount_inr=amount_inr,
        timestamp=ts,
        merchant_category=category,
        transaction_type=txn_type,
        device_type=device_os,
        is_new_receiver=False,
        is_new_device=False,
        sender_bank="UNKNOWN",
        receiver_bank="UNKNOWN",
    )
