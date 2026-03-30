#!/usr/bin/env python3
"""
Varaksha V2 - 00_generate_indian_physics.py

Purpose
-------
Generate a causally linked Indian UPI-like transaction stream with persistent entities,
chronological behavior, and explicit attack injections for fraud-model bootstrapping.

Key guarantees
--------------
- Exact output schema (20 columns) required by downstream V2 pipeline.
- Persistent customers and merchants across 30 days.
- Dynamic behavioral fields computed from prior customer state:
  - Transaction_Frequency
  - Days_Since_Last_Transaction
  - Transaction_Amount_Deviation
- Fraud is physics-driven, not random:
  - Mule Fan-In: 15 distinct senders to 1 receiver in <=10 minutes
  - Velocity Takeover: 20 txns from one customer in <=5 minutes

Default output
--------------
- CSV: ../datasets/generated/upi_raw.csv
"""

from __future__ import annotations

import argparse
import math
import random
import uuid
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Sequence

import numpy as np
import pandas as pd


SCHEMA: List[str] = [
    "Transaction_ID",
    "Date",
    "Time",
    "Merchant_ID",
    "Customer_ID",
    "Device_ID",
    "Transaction_Type",
    "Payment_Gateway",
    "Transaction_City",
    "Transaction_State",
    "IP_Address",
    "Transaction_Status",
    "Device_OS",
    "Transaction_Frequency",
    "Merchant_Category",
    "Transaction_Channel",
    "Transaction_Amount_Deviation",
    "Days_Since_Last_Transaction",
    "amount",
    "fraud",
]

CITIES = [
    "Mumbai", "Delhi", "Bengaluru", "Hyderabad", "Chennai", "Kolkata", "Pune",
    "Ahmedabad", "Jaipur", "Lucknow", "Kochi", "Bhopal", "Nagpur", "Patna", "Surat",
]

STATES = [
    "Maharashtra", "Delhi", "Karnataka", "Telangana", "Tamil Nadu", "West Bengal",
    "Gujarat", "Rajasthan", "Uttar Pradesh", "Kerala", "Madhya Pradesh", "Bihar",
]

PAYMENT_GATEWAYS = ["UPI Pay", "PhonePe", "Google Pay", "Paytm", "BHIM UPI"]
TXN_TYPES = ["P2P", "P2M", "Bill Payment", "Recharge"]
TXN_CHANNELS = ["Mobile App", "Web Browser", "QR Code", "SMS"]
DEVICE_OS_CHOICES = ["Android", "iOS", "Harmony OS"]
TXN_STATUS_POOL = ["SUCCESS"] * 6 + ["FAILED", "PENDING"]

MERCHANT_CATEGORIES = [
    "Grocery", "Food", "Shopping", "Transport", "Entertainment",
    "Healthcare", "Education", "Utilities", "Fuel", "Recharge",
]

CATEGORY_AMOUNT_RANGE = {
    "Grocery": (50, 900),
    "Food": (50, 1200),
    "Shopping": (120, 5000),
    "Transport": (20, 700),
    "Entertainment": (120, 3500),
    "Healthcare": (200, 8000),
    "Education": (500, 12000),
    "Utilities": (100, 9000),
    "Fuel": (100, 4000),
    "Recharge": (20, 1500),
}
P2P_RANGE = (50, 6000)


@dataclass
class Customer:
    customer_id: str
    device_id: str
    state: str
    city: str
    device_os: str
    ip_address: str
    category_pref: np.ndarray


@dataclass
class Merchant:
    merchant_id: str
    category: str
    state: str
    city: str


@dataclass
class CustomerState:
    txn_count: int = 0
    last_dt: datetime | None = None
    amount_sum: float = 0.0
    amount_sq_sum: float = 0.0


def log(msg: str) -> None:
    print(f"[PHYSICS] {msg}", flush=True)


def build_customers(n_customers: int, rng: random.Random, np_rng: np.random.Generator) -> List[Customer]:
    customers: List[Customer] = []
    for i in range(n_customers):
        customer_id = f"CUST_{i:05d}"
        device_id = f"DEV_{i:05d}"
        state = rng.choice(STATES)
        city = rng.choice(CITIES)
        device_os = rng.choice(DEVICE_OS_CHOICES)
        ip_address = f"192.168.{rng.randint(0, 255)}.{rng.randint(1, 254)}"

        weights = np_rng.random(len(MERCHANT_CATEGORIES))
        weights = weights / weights.sum()

        customers.append(
            Customer(
                customer_id=customer_id,
                device_id=device_id,
                state=state,
                city=city,
                device_os=device_os,
                ip_address=ip_address,
                category_pref=weights,
            )
        )
    return customers


def build_merchants(n_merchants: int, rng: random.Random) -> List[Merchant]:
    merchants: List[Merchant] = []
    for i in range(n_merchants):
        merchants.append(
            Merchant(
                merchant_id=f"MERCH_{i:05d}",
                category=rng.choice(MERCHANT_CATEGORIES),
                state=rng.choice(STATES),
                city=rng.choice(CITIES),
            )
        )
    return merchants


def hourly_intensity(hour: int) -> float:
    # Morning/evening peaks, night trough.
    if 0 <= hour <= 5:
        return 0.25
    if 6 <= hour <= 8:
        return 0.9
    if 9 <= hour <= 13:
        return 1.4
    if 14 <= hour <= 17:
        return 1.1
    if 18 <= hour <= 21:
        return 1.6
    return 0.8


def sample_amount(category: str, txn_type: str, rng: random.Random) -> float:
    lo, hi = P2P_RANGE if txn_type == "P2P" else CATEGORY_AMOUNT_RANGE.get(category, (50, 3000))

    # Skew toward small values while keeping long-tail spend.
    u = rng.random()
    skew = u ** 2.2
    amount = lo + (hi - lo) * skew
    return round(float(amount), 2)


def spoof_ip(rng: random.Random) -> str:
    return f"10.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


def spoof_os(current_os: str, rng: random.Random) -> str:
    options = [x for x in DEVICE_OS_CHOICES if x != current_os]
    return rng.choice(options) if options else current_os


def amount_deviation(amount: float, st: CustomerState) -> float:
    if st.txn_count < 2:
        return 0.0
    mean = st.amount_sum / st.txn_count
    var = max((st.amount_sq_sum / st.txn_count) - (mean * mean), 0.0)
    std = math.sqrt(var)
    if std <= 1e-9:
        return 0.0
    return (amount - mean) / std


def build_row(
    dt: datetime,
    customer: Customer,
    merchant_id: str,
    merchant_category: str,
    amount: float,
    fraud: int,
    customer_state: Dict[str, CustomerState],
    rng: random.Random,
    ip_override: str | None = None,
    os_override: str | None = None,
) -> Dict[str, object]:
    st = customer_state[customer.customer_id]

    # Compute behavior from PRIOR state only.
    txn_frequency = st.txn_count
    days_since_last = 0.0
    if st.last_dt is not None:
        days_since_last = (dt - st.last_dt).total_seconds() / 86400.0
    amt_dev = amount_deviation(amount, st)

    txn_type = rng.choice(TXN_TYPES)

    row: Dict[str, object] = {
        "Transaction_ID": f"TXN_{uuid.uuid4().hex[:12].upper()}",
        "Date": dt.strftime("%Y-%m-%d"),
        "Time": dt.strftime("%H:%M:%S"),
        "Merchant_ID": merchant_id,
        "Customer_ID": customer.customer_id,
        "Device_ID": customer.device_id,
        "Transaction_Type": txn_type,
        "Payment_Gateway": rng.choice(PAYMENT_GATEWAYS),
        "Transaction_City": customer.city,
        "Transaction_State": customer.state,
        "IP_Address": ip_override if ip_override is not None else customer.ip_address,
        "Transaction_Status": rng.choice(TXN_STATUS_POOL),
        "Device_OS": os_override if os_override is not None else customer.device_os,
        "Transaction_Frequency": int(txn_frequency),
        "Merchant_Category": merchant_category,
        "Transaction_Channel": rng.choice(TXN_CHANNELS),
        "Transaction_Amount_Deviation": round(float(amt_dev), 6),
        "Days_Since_Last_Transaction": round(float(days_since_last), 6),
        "amount": round(float(amount), 2),
        "fraud": int(fraud),
    }

    # Update state AFTER building row.
    st.txn_count += 1
    st.last_dt = dt
    st.amount_sum += amount
    st.amount_sq_sum += amount * amount

    return row


def inject_mule_fan_in(
    rows: List[Dict[str, object]],
    event_dt: datetime,
    customers: Sequence[Customer],
    mule_merchants: Sequence[Merchant],
    customer_state: Dict[str, CustomerState],
    rng: random.Random,
) -> int:
    mule = rng.choice(mule_merchants)
    senders = rng.sample(list(customers), 15)

    injected = 0
    for i, sender in enumerate(senders):
        dt = event_dt + timedelta(seconds=i * 35)  # 15 txns in <=10 minutes
        row = build_row(
            dt=dt,
            customer=sender,
            merchant_id=mule.merchant_id,
            merchant_category=mule.category,
            amount=50_000.0,
            fraud=1,
            customer_state=customer_state,
            rng=rng,
        )
        rows.append(row)
        injected += 1
    return injected


def inject_velocity_takeover(
    rows: List[Dict[str, object]],
    event_dt: datetime,
    customers: Sequence[Customer],
    merchants: Sequence[Merchant],
    customer_state: Dict[str, CustomerState],
    rng: random.Random,
) -> int:
    victim = rng.choice(list(customers))
    attacker_ip = spoof_ip(rng)
    attacker_os = spoof_os(victim.device_os, rng)

    injected = 0
    for i in range(20):
        dt = event_dt + timedelta(seconds=i * 15)  # 20 txns in 5 minutes
        merch = rng.choice(list(merchants))
        amount = round(rng.uniform(1200, 9000), 2)

        row = build_row(
            dt=dt,
            customer=victim,
            merchant_id=merch.merchant_id,
            merchant_category=merch.category,
            amount=amount,
            fraud=1,
            customer_state=customer_state,
            rng=rng,
            ip_override=attacker_ip,
            os_override=attacker_os,
        )
        rows.append(row)
        injected += 1
    return injected


def build_attack_plan(
    sim_days: int,
    extra_fraud_rate: float,
    target_rows: int,
    rng: random.Random,
) -> dict[tuple[int, int], list[str]]:
    """
    Create a physics attack schedule:
    - Base cadence (mule fan-in + velocity takeover)
    - Dynamic extra attacks sized from requested fraud-rate bump
    """
    plan: dict[tuple[int, int], list[str]] = defaultdict(list)

    # Base deterministic cadence.
    for day in range(1, sim_days, 3):
        plan[(day, 14)].append("fan_in")
    for day in range(2, sim_days, 3):
        plan[(day, 10)].append("velocity")

    if extra_fraud_rate <= 0.0:
        return plan

    extra_rows_target = int(round(extra_fraud_rate * target_rows))
    remaining = max(0, extra_rows_target)

    # Favor business hours where coordinated attacks are more plausible in volume.
    candidate_hours = [9, 10, 11, 12, 14, 15, 16, 18, 19, 20, 21, 22]

    while remaining > 0:
        day = rng.randrange(sim_days)
        hour = rng.choice(candidate_hours)

        # Mix both typologies to avoid a single-pattern fraud population.
        attack_type = "fan_in" if rng.random() < 0.5 else "velocity"
        plan[(day, hour)].append(attack_type)
        remaining -= 15 if attack_type == "fan_in" else 20

    return plan


def count_planned_attack_rows(plan: dict[tuple[int, int], list[str]]) -> int:
    total = 0
    for attacks in plan.values():
        for attack in attacks:
            total += 15 if attack == "fan_in" else 20
    return total


def simulate(
    n_customers: int,
    n_merchants: int,
    sim_days: int,
    target_rows: int,
    extra_fraud_rate: float,
    seed: int,
) -> pd.DataFrame:
    rng = random.Random(seed)
    np_rng = np.random.default_rng(seed)

    log("Building persistent entities...")
    customers = build_customers(n_customers, rng, np_rng)
    merchants = build_merchants(n_merchants, rng)
    mule_merchants = merchants[: max(10, n_merchants // 20)]

    customer_state: Dict[str, CustomerState] = {
        c.customer_id: CustomerState() for c in customers
    }

    sim_start = datetime(2026, 1, 1, 0, 0, 0)

    attack_plan = build_attack_plan(sim_days, extra_fraud_rate, target_rows, rng)
    planned_attack_rows = count_planned_attack_rows(attack_plan)

    normal_target = max(target_rows - planned_attack_rows, target_rows // 2)
    base_per_hour = normal_target / float(sim_days * 24)

    rows: List[Dict[str, object]] = []
    normal_rows = 0
    fanin_rows = 0
    velocity_rows = 0

    log(
        f"Simulating {sim_days} days | customers={n_customers:,} | merchants={n_merchants:,} | "
        f"target_rows={target_rows:,} | extra_fraud_rate={extra_fraud_rate:.4f} | "
        f"planned_attack_rows={planned_attack_rows:,}"
    )

    for day in range(sim_days):
        if day % 5 == 0:
            log(f"  day={day:02d}, rows={len(rows):,}")

        for hour in range(24):
            dt_base = sim_start + timedelta(days=day, hours=hour)
            lam = base_per_hour * hourly_intensity(hour)
            n_hour = int(np_rng.poisson(lam))

            for _ in range(n_hour):
                c = rng.choice(customers)
                cat_idx = int(np_rng.choice(len(MERCHANT_CATEGORIES), p=c.category_pref))
                preferred_cat = MERCHANT_CATEGORIES[cat_idx]

                # Prefer merchants in customer's preferred category.
                cat_merchants = [m for m in merchants if m.category == preferred_cat]
                m = rng.choice(cat_merchants) if cat_merchants else rng.choice(merchants)

                txn_type = rng.choice(TXN_TYPES)
                amount = sample_amount(m.category, txn_type, rng)

                dt = dt_base + timedelta(minutes=rng.randint(0, 59), seconds=rng.randint(0, 59))
                row = build_row(
                    dt=dt,
                    customer=c,
                    merchant_id=m.merchant_id,
                    merchant_category=m.category,
                    amount=amount,
                    fraud=0,
                    customer_state=customer_state,
                    rng=rng,
                )
                rows.append(row)
                normal_rows += 1

            for attack in attack_plan.get((day, hour), []):
                if attack == "fan_in":
                    fanin_rows += inject_mule_fan_in(
                        rows=rows,
                        event_dt=dt_base,
                        customers=customers,
                        mule_merchants=mule_merchants,
                        customer_state=customer_state,
                        rng=rng,
                    )
                else:
                    velocity_rows += inject_velocity_takeover(
                        rows=rows,
                        event_dt=dt_base,
                        customers=customers,
                        merchants=merchants,
                        customer_state=customer_state,
                        rng=rng,
                    )

    df = pd.DataFrame(rows)

    # Strict chronological order for downstream left-closed rolling features.
    dt_series = pd.to_datetime(df["Date"] + " " + df["Time"], errors="coerce")
    df = df.assign(_dt=dt_series).sort_values("_dt", kind="mergesort").drop(columns=["_dt"]).reset_index(drop=True)

    # Enforce exact column order.
    missing = [c for c in SCHEMA if c not in df.columns]
    if missing:
        raise ValueError(f"Schema generation failed, missing columns: {missing}")
    df = df[SCHEMA]

    log(
        f"Finished | total={len(df):,} | normal={normal_rows:,} | fanin={fanin_rows:,} | "
        f"velocity={velocity_rows:,} | fraud_rate={df['fraud'].mean() * 100:.3f}%"
    )
    return df


def parse_args() -> argparse.Namespace:
    script_dir = Path(__file__).resolve().parent
    default_out = script_dir.parent / "datasets" / "generated" / "upi_raw.csv"

    p = argparse.ArgumentParser(description="Generate causally linked Indian UPI physics dataset.")
    p.add_argument("--customers", type=int, default=10_000, help="Number of persistent customers.")
    p.add_argument("--merchants", type=int, default=500, help="Number of persistent merchants.")
    p.add_argument("--days", type=int, default=30, help="Simulation window in days.")
    p.add_argument("--target-rows", type=int, default=250_000, help="Approximate total row target.")
    p.add_argument(
        "--extra-fraud-rate",
        type=float,
        default=0.0,
        help="Additional fraud fraction injected via attack physics (e.g. 0.02 for +2%%).",
    )
    p.add_argument("--seed", type=int, default=42, help="Random seed for deterministic builds.")
    p.add_argument("--out-csv", type=Path, default=default_out, help="Output CSV path.")
    p.add_argument("--out-parquet", type=Path, default=None, help="Optional parquet output path.")
    return p.parse_args()


def main() -> None:
    args = parse_args()

    if args.customers < 1000:
        raise ValueError("Use at least 1000 customers to maintain realistic network diversity.")
    if args.merchants < 100:
        raise ValueError("Use at least 100 merchants to maintain realistic merchant graph spread.")
    if args.days < 7:
        raise ValueError("Use at least 7 simulation days for stable behavioral windows.")

    args.out_csv.parent.mkdir(parents=True, exist_ok=True)
    if args.out_parquet is not None:
        args.out_parquet.parent.mkdir(parents=True, exist_ok=True)

    df = simulate(
        n_customers=args.customers,
        n_merchants=args.merchants,
        sim_days=args.days,
        target_rows=args.target_rows,
        extra_fraud_rate=args.extra_fraud_rate,
        seed=args.seed,
    )

    df.to_csv(args.out_csv, index=False)
    log(f"Saved CSV -> {args.out_csv} ({df.shape[0]:,} x {df.shape[1]})")

    if args.out_parquet is not None:
        df.to_parquet(args.out_parquet, index=False)
        log(f"Saved Parquet -> {args.out_parquet}")


if __name__ == "__main__":
    main()
