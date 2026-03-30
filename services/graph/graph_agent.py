#!/usr/bin/env python3
"""
Varaksha L3 — Graph Agent
services/graph/graph_agent.py

Builds a directed transaction graph on a sliding window of the last N
transactions, detects four BIS Project Hertha mule-ring typologies, and
pushes per-VPA risk deltas to the Rust gateway via HMAC-SHA256-signed webhook.

Typologies and risk deltas:
  fan_out  — one sender pushing to many receivers          +0.35
  fan_in   — many senders pushing to one receiver          +0.30
  cycle    — A → B → C → A  (money laundering loop)        +0.50
  scatter  — high out-degree, out > 2 × in-degree          +0.20

Multiple typologies for a single VPA are summed and clamped to 1.0.

CLI usage:
  python -m services.graph.graph_agent \\
    --parquet path/to/varaksha_train_clean.parquet \\
    --window-size 5000 \\
    --endpoint http://localhost:8080/graph_update \\
    --dry-run
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import hmac
import json
import os
import time
import urllib.error
import urllib.request
from collections import deque
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Tuple

import networkx as nx
import polars as pl

DEFAULT_ENDPOINT = "http://localhost:8080/graph_update"
DEFAULT_WINDOW_SIZE = 5000
DEFAULT_BATCH_SIZE = 128

# Detection thresholds (BIS Project Hertha taxonomy)
FAN_OUT_MIN_RECEIVERS = 3     # sender → ≥3 distinct receivers
FAN_IN_MIN_SENDERS = 5        # ≥5 distinct senders → one receiver
CYCLE_MAX_LENGTH = 5          # only detect short cycles (prevents O(n!) on large graphs)
SCATTER_RATIO = 2.0           # out_degree > SCATTER_RATIO * in_degree

# Risk deltas
DELTA_FAN_OUT = 0.35
DELTA_FAN_IN = 0.30
DELTA_CYCLE = 0.50
DELTA_SCATTER = 0.20


# ---------------------------------------------------------------------------
# PII helpers
# ---------------------------------------------------------------------------

def _hash_vpa(vpa: str) -> str:
    """SHA-256 hash of a VPA string — no raw identifier leaves this module."""
    return hashlib.sha256(vpa.encode("utf-8")).hexdigest()


def _sign_payload(secret: str, body: bytes) -> str:
    """HMAC-SHA256 signature over raw body bytes."""
    return hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()


# ---------------------------------------------------------------------------
# Graph Agent
# ---------------------------------------------------------------------------

class GraphAgent:
    """
    Sliding-window transaction graph with mule-ring typology detection.

    The graph is a directed multigraph:
      - Nodes  : hashed VPAs (SHA-256 hex strings)
      - Edges  : transactions, annotated with amount and timestamp
    """

    def __init__(
        self,
        window_size: int = DEFAULT_WINDOW_SIZE,
        endpoint: str = DEFAULT_ENDPOINT,
        secret: Optional[str] = None,
    ) -> None:
        self.window_size = window_size
        self.endpoint = endpoint
        self.secret = secret or os.environ.get("VARAKSHA_GRAPH_SECRET", "")

        # Directed multigraph: allows multiple transactions between the same pair.
        self.graph: nx.MultiDiGraph = nx.MultiDiGraph()

        # Sliding window of (sender_hash, receiver_hash) to support eviction.
        self._window: deque[Tuple[str, str, int]] = deque()  # (src, dst, edge_key)

    # ------------------------------------------------------------------
    # Ingestion
    # ------------------------------------------------------------------

    def ingest(
        self,
        sender_vpa: str,
        receiver_vpa: str,
        amount: float,
        timestamp: str = "",
    ) -> None:
        """
        Add one transaction edge to the graph.
        Evicts the oldest edge when the window is full.
        Both VPAs are hashed before storage — raw strings never enter the graph.
        """
        src = _hash_vpa(sender_vpa)
        dst = _hash_vpa(receiver_vpa)

        key = self.graph.add_edge(src, dst, amount=amount, timestamp=timestamp)
        self._window.append((src, dst, key))

        # Evict oldest edge if window is full.
        if len(self._window) > self.window_size:
            old_src, old_dst, old_key = self._window.popleft()
            if self.graph.has_edge(old_src, old_dst, key=old_key):
                self.graph.remove_edge(old_src, old_dst, key=old_key)
            # Remove isolated nodes to keep the graph lean.
            for node in (old_src, old_dst):
                if node in self.graph and self.graph.degree(node) == 0:
                    self.graph.remove_node(node)

    def ingest_batch(self, rows: Iterable[Dict[str, Any]]) -> None:
        """
        Ingest an iterable of row dicts.
        Expected keys: sender_vpa / sender_bank (fallback), receiver_vpa /
        receiver_bank (fallback), amount (INR), timestamp.
        """
        for row in rows:
            sender = str(row.get("sender_vpa") or row.get("sender_bank") or "unknown_sender")
            receiver = str(row.get("receiver_vpa") or row.get("receiver_bank") or "unknown_receiver")
            amount = float(row.get("amount (INR)") or row.get("amount") or 0.0)
            ts = str(row.get("timestamp") or "")
            self.ingest(sender, receiver, amount, ts)

    # ------------------------------------------------------------------
    # Pattern detection
    # ------------------------------------------------------------------

    def detect_patterns(self) -> List[Dict[str, Any]]:
        """
        Run all four typology detectors and return merged, clamped risk deltas.

        Returns:
            List of dicts: [{"vpa_hash": str, "risk_delta": float, "reason": str}]
            Only nodes with risk_delta > 0 are included.
        """
        scores: Dict[str, float] = {}
        reasons: Dict[str, List[str]] = {}

        def _add(node: str, delta: float, label: str) -> None:
            scores[node] = scores.get(node, 0.0) + delta
            reasons.setdefault(node, []).append(label)

        for node, delta, label in self._detect_fan_out():
            _add(node, delta, label)
        for node, delta, label in self._detect_fan_in():
            _add(node, delta, label)
        for node, delta, label in self._detect_cycle():
            _add(node, delta, label)
        for node, delta, label in self._detect_scatter():
            _add(node, delta, label)

        results: List[Dict[str, Any]] = []
        for vpa_hash, total_delta in scores.items():
            clamped = min(total_delta, 1.0)
            reason_str = "+".join(sorted(set(reasons.get(vpa_hash, []))))
            results.append({
                "vpa_hash": vpa_hash,
                "risk_delta": round(clamped, 4),
                "reason": reason_str,
            })

        return results

    def _detect_fan_out(self) -> Iterator[Tuple[str, float, str]]:
        """Sender with ≥ FAN_OUT_MIN_RECEIVERS distinct receiver nodes."""
        for node in self.graph.nodes():
            distinct_receivers = len(set(self.graph.successors(node)))
            if distinct_receivers >= FAN_OUT_MIN_RECEIVERS:
                yield node, DELTA_FAN_OUT, "fan_out"

    def _detect_fan_in(self) -> Iterator[Tuple[str, float, str]]:
        """Receiver with ≥ FAN_IN_MIN_SENDERS distinct sender nodes."""
        for node in self.graph.nodes():
            distinct_senders = len(set(self.graph.predecessors(node)))
            if distinct_senders >= FAN_IN_MIN_SENDERS:
                yield node, DELTA_FAN_IN, "fan_in"

    def _detect_cycle(self) -> Iterator[Tuple[str, float, str]]:
        """
        Nodes participating in simple cycles of length ≤ CYCLE_MAX_LENGTH.
        Uses NetworkX simple_cycles(); limits cycle length to avoid combinatorial
        explosion on large graphs.
        """
        try:
            for cycle in nx.simple_cycles(self.graph, length_bound=CYCLE_MAX_LENGTH):
                if len(cycle) >= 2:
                    for node in cycle:
                        yield node, DELTA_CYCLE, "cycle"
        except Exception:
            # Defensive: nx.simple_cycles is generator-based; any graph error is skipped.
            pass

    def _detect_scatter(self) -> Iterator[Tuple[str, float, str]]:
        """
        Nodes where out_degree > SCATTER_RATIO × in_degree AND in_degree ≥ 1.
        A node that only sends (in_degree == 0) is a leaf, not a scatterer.
        """
        for node in self.graph.nodes():
            out_deg = self.graph.out_degree(node)
            in_deg = self.graph.in_degree(node)
            if in_deg >= 1 and out_deg > SCATTER_RATIO * in_deg:
                yield node, DELTA_SCATTER, "scatter"

    # ------------------------------------------------------------------
    # Push to Rust gateway
    # ------------------------------------------------------------------

    def _build_payload(self, delta: Dict[str, Any]) -> bytes:
        return json.dumps({
            "vpa_hash": delta["vpa_hash"],
            "risk_delta": delta["risk_delta"],
            "reason": delta["reason"],
            "timestamp": int(time.time()),
        }, separators=(",", ":")).encode("utf-8")

    def _post_delta(
        self, delta: Dict[str, Any], timeout_s: float = 2.0
    ) -> Tuple[bool, str]:
        body = self._build_payload(delta)
        headers: Dict[str, str] = {"Content-Type": "application/json"}
        if self.secret:
            sig = _sign_payload(self.secret, body)
            headers["X-Varaksha-Signature"] = f"sha256={sig}"

        req = urllib.request.Request(
            self.endpoint,
            data=body,
            headers=headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout_s) as resp:
                return True, str(resp.status)
        except urllib.error.HTTPError as e:
            return False, f"HTTP {e.code}"
        except Exception as e:
            return False, str(e)

    async def push_all_deltas(
        self,
        deltas: List[Dict[str, Any]],
        batch_size: int = DEFAULT_BATCH_SIZE,
        timeout_s: float = 2.0,
    ) -> Dict[str, int]:
        """Push all deltas to Rust gateway in async batches."""
        ok = failed = 0
        for i in range(0, len(deltas), batch_size):
            batch = deltas[i : i + batch_size]
            results = await asyncio.gather(
                *(asyncio.to_thread(self._post_delta, d, timeout_s) for d in batch)
            )
            for success, _ in results:
                if success:
                    ok += 1
                else:
                    failed += 1
        return {"ok": ok, "failed": failed}

    async def run_cycle(
        self,
        batch_size: int = DEFAULT_BATCH_SIZE,
        timeout_s: float = 2.0,
    ) -> Dict[str, Any]:
        """Detect patterns then push all deltas in one call."""
        deltas = self.detect_patterns()
        if not deltas:
            return {"detected": 0, "ok": 0, "failed": 0}
        push_stats = await self.push_all_deltas(deltas, batch_size, timeout_s)
        return {"detected": len(deltas), **push_stats}

    # ------------------------------------------------------------------
    # Parquet loader
    # ------------------------------------------------------------------

    @classmethod
    def from_parquet(
        cls,
        parquet_path: Path,
        window_size: int = DEFAULT_WINDOW_SIZE,
        endpoint: str = DEFAULT_ENDPOINT,
        secret: Optional[str] = None,
        sender_col: str = "sender_bank",
        receiver_col: str = "receiver_bank",
        amount_col: str = "amount (INR)",
        timestamp_col: str = "timestamp",
    ) -> "GraphAgent":
        """
        Build a GraphAgent pre-loaded with up to window_size rows from a parquet.
        Rows are sorted chronologically before ingestion so the window holds
        the most-recent window_size transactions.
        """
        agent = cls(window_size=window_size, endpoint=endpoint, secret=secret)

        df = (
            pl.scan_parquet(str(parquet_path))
            .select([sender_col, receiver_col, amount_col, timestamp_col])
            .sort(timestamp_col)
            .tail(window_size)
            .collect()
        )

        for row in df.iter_rows(named=True):
            agent.ingest(
                sender_vpa=str(row[sender_col]),
                receiver_vpa=str(row[receiver_col]),
                amount=float(row[amount_col] or 0.0),
                timestamp=str(row[timestamp_col] or ""),
            )

        return agent

    # ------------------------------------------------------------------
    # Diagnostics
    # ------------------------------------------------------------------

    def stats(self) -> Dict[str, Any]:
        return {
            "nodes": self.graph.number_of_nodes(),
            "edges": self.graph.number_of_edges(),
            "window_used": len(self._window),
            "window_capacity": self.window_size,
        }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Varaksha Graph Agent")
    p.add_argument(
        "--parquet",
        type=Path,
        default=Path(
            "datasets_copy/PRODUCTION_DATASETS/upi_transactions_2024/varaksha_train_clean.parquet"
        ),
        help="Path to parquet file for graph construction.",
    )
    p.add_argument(
        "--window-size",
        type=int,
        default=DEFAULT_WINDOW_SIZE,
        help="Sliding window size (number of transactions).",
    )
    p.add_argument(
        "--endpoint",
        type=str,
        default=DEFAULT_ENDPOINT,
        help="Rust gateway graph_update endpoint URL.",
    )
    p.add_argument(
        "--secret",
        type=str,
        default=None,
        help="HMAC secret (overrides VARAKSHA_GRAPH_SECRET env var).",
    )
    p.add_argument(
        "--sender-col",
        type=str,
        default="sender_bank",
        help="Column name to use as sender VPA.",
    )
    p.add_argument(
        "--receiver-col",
        type=str,
        default="receiver_bank",
        help="Column name to use as receiver VPA.",
    )
    p.add_argument(
        "--batch-size",
        type=int,
        default=DEFAULT_BATCH_SIZE,
        help="Concurrent push batch size.",
    )
    p.add_argument(
        "--timeout",
        type=float,
        default=2.0,
        help="HTTP request timeout per push (seconds).",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Detect and print deltas; do not push to gateway.",
    )
    return p.parse_args()


async def _main() -> None:
    args = _parse_args()

    if not args.parquet.exists():
        raise FileNotFoundError(f"Parquet not found: {args.parquet}")

    print(f"[graph_agent] Loading parquet: {args.parquet}")
    agent = GraphAgent.from_parquet(
        parquet_path=args.parquet,
        window_size=args.window_size,
        endpoint=args.endpoint,
        secret=args.secret,
        sender_col=args.sender_col,
        receiver_col=args.receiver_col,
    )

    s = agent.stats()
    print(
        f"[graph_agent] Graph built: {s['nodes']} nodes, {s['edges']} edges "
        f"({s['window_used']} / {s['window_capacity']} window slots used)"
    )

    deltas = agent.detect_patterns()
    print(f"[graph_agent] Typologies detected: {len(deltas)}")

    if deltas:
        print("\n  vpa_hash (first 12)       risk_delta  reason")
        print("  " + "-" * 55)
        for d in sorted(deltas, key=lambda x: -x["risk_delta"])[:20]:
            print(f"  {d['vpa_hash'][:12]}...  {d['risk_delta']:.4f}      {d['reason']}")

    if args.dry_run:
        print("\n[graph_agent] Dry-run mode — skipping push.")
        return

    if not agent.secret:
        print("\n[graph_agent] WARNING: VARAKSHA_GRAPH_SECRET not set. Pushing unsigned.")

    print(f"\n[graph_agent] Pushing {len(deltas)} deltas to {args.endpoint} ...")
    stats = await agent.push_all_deltas(deltas, args.batch_size, args.timeout)
    print(
        f"[graph_agent] Push complete: ok={stats['ok']}, failed={stats['failed']}"
    )


if __name__ == "__main__":
    asyncio.run(_main())
