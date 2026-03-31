#!/usr/bin/env python3
"""
Varaksha L3 — Graph Agent

Upgraded graph agent that maps cleanly to the Rust gateway contract and
produces adaptive topology risk deltas (not purely hardcoded constants).

Key upgrades:
  - Rust payload compatibility (`_timestamp` field expected by `/graph_update`)
  - Adaptive severity scoring per typology
  - Deterministic demo mode for judge-facing live proof
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
from collections import defaultdict, deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

import networkx as nx
import polars as pl

DEFAULT_ENDPOINT = "http://localhost:8080/graph_update"
DEFAULT_WINDOW_SIZE = 5000
DEFAULT_BATCH_SIZE = 128

# Detection thresholds
FAN_OUT_MIN_RECEIVERS = 3
FAN_IN_MIN_SENDERS = 5
CYCLE_MAX_LENGTH = 5
SCATTER_RATIO = 2.0

# Baseline risk contributions (severity-scaled later)
DELTA_FAN_OUT = 0.35
DELTA_FAN_IN = 0.30
DELTA_CYCLE = 0.50
DELTA_SCATTER = 0.20

MAX_GRAPH_DELTA = 1.0


def _hash_vpa(vpa: str) -> str:
    return hashlib.sha256(vpa.encode("utf-8")).hexdigest()


def _sign_payload(secret: str, body: bytes) -> str:
    return hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()


def _clamp01(value: float) -> float:
    return max(0.0, min(1.0, value))


@dataclass
class DetectionEvent:
    node: str
    delta: float
    label: str
    evidence: str


class GraphAgent:
    def __init__(
        self,
        window_size: int = DEFAULT_WINDOW_SIZE,
        endpoint: str = DEFAULT_ENDPOINT,
        secret: Optional[str] = None,
        fan_out_min_receivers: int = FAN_OUT_MIN_RECEIVERS,
        fan_in_min_senders: int = FAN_IN_MIN_SENDERS,
        cycle_max_length: int = CYCLE_MAX_LENGTH,
        scatter_ratio: float = SCATTER_RATIO,
    ) -> None:
        self.window_size = window_size
        self.endpoint = endpoint
        self.secret = secret or os.environ.get("VARAKSHA_GRAPH_SECRET", "")

        self.fan_out_min_receivers = fan_out_min_receivers
        self.fan_in_min_senders = fan_in_min_senders
        self.cycle_max_length = cycle_max_length
        self.scatter_ratio = scatter_ratio

        self.graph: nx.MultiDiGraph = nx.MultiDiGraph()
        self._window: deque[Tuple[str, str, int]] = deque()

    def ingest(self, sender_vpa: str, receiver_vpa: str, amount: float, timestamp: str = "") -> None:
        src = _hash_vpa(sender_vpa)
        dst = _hash_vpa(receiver_vpa)
        key = self.graph.add_edge(src, dst, amount=amount, timestamp=timestamp)
        self._window.append((src, dst, key))

        if len(self._window) > self.window_size:
            old_src, old_dst, old_key = self._window.popleft()
            if self.graph.has_edge(old_src, old_dst, key=old_key):
                self.graph.remove_edge(old_src, old_dst, key=old_key)
            for node in (old_src, old_dst):
                if node in self.graph and self.graph.degree(node) == 0:
                    self.graph.remove_node(node)

    def ingest_batch(self, rows: Iterable[Dict[str, Any]]) -> None:
        for row in rows:
            sender = str(row.get("sender_vpa") or row.get("sender_bank") or row.get("from_vpa") or "unknown_sender")
            receiver = str(row.get("receiver_vpa") or row.get("receiver_bank") or row.get("to_vpa") or "unknown_receiver")
            amount = float(row.get("amount (INR)") or row.get("amount") or 0.0)
            ts = str(row.get("timestamp") or "")
            self.ingest(sender, receiver, amount, ts)

    def _severity_scaled_delta(self, base_delta: float, severity: float) -> float:
        # Keep minimum signal at 60% of base and boost up to 100% of base.
        scaled = base_delta * (0.6 + 0.4 * _clamp01(severity))
        return _clamp01(scaled)

    def _node_neighbors(self) -> Tuple[Dict[str, Set[str]], Dict[str, Set[str]]]:
        succ: Dict[str, Set[str]] = {}
        pred: Dict[str, Set[str]] = {}
        for node in self.graph.nodes():
            succ[node] = set(self.graph.successors(node))
            pred[node] = set(self.graph.predecessors(node))
        return succ, pred

    def _detect_fan_out(self, succ: Dict[str, Set[str]]) -> List[DetectionEvent]:
        events: List[DetectionEvent] = []
        for node, receivers in succ.items():
            distinct_receivers = len(receivers)
            if distinct_receivers >= self.fan_out_min_receivers:
                excess = distinct_receivers - self.fan_out_min_receivers + 1
                severity = _clamp01(excess / max(1, self.fan_out_min_receivers))
                delta = self._severity_scaled_delta(DELTA_FAN_OUT, severity)
                events.append(
                    DetectionEvent(
                        node=node,
                        delta=delta,
                        label="fan_out",
                        evidence=f"fan_out(n={distinct_receivers},sev={severity:.2f})",
                    )
                )
        return events

    def _detect_fan_in(self, pred: Dict[str, Set[str]]) -> List[DetectionEvent]:
        events: List[DetectionEvent] = []
        for node, senders in pred.items():
            distinct_senders = len(senders)
            if distinct_senders >= self.fan_in_min_senders:
                excess = distinct_senders - self.fan_in_min_senders + 1
                severity = _clamp01(excess / max(1, self.fan_in_min_senders))
                delta = self._severity_scaled_delta(DELTA_FAN_IN, severity)
                events.append(
                    DetectionEvent(
                        node=node,
                        delta=delta,
                        label="fan_in",
                        evidence=f"fan_in(n={distinct_senders},sev={severity:.2f})",
                    )
                )
        return events

    def _detect_cycle(self) -> List[DetectionEvent]:
        events: List[DetectionEvent] = []
        cycle_counts: Dict[str, int] = defaultdict(int)
        shortest_cycle_len: Dict[str, int] = {}

        try:
            for cycle in nx.simple_cycles(self.graph, length_bound=self.cycle_max_length):
                if len(cycle) < 2:
                    continue
                for node in cycle:
                    cycle_counts[node] += 1
                    shortest_cycle_len[node] = min(shortest_cycle_len.get(node, 1_000_000), len(cycle))
        except Exception:
            return events

        for node, count in cycle_counts.items():
            min_len = shortest_cycle_len.get(node, self.cycle_max_length)
            len_strength = _clamp01((self.cycle_max_length - min_len + 1) / max(1, self.cycle_max_length))
            count_strength = _clamp01(count / 3.0)
            severity = 0.5 * len_strength + 0.5 * count_strength
            delta = self._severity_scaled_delta(DELTA_CYCLE, severity)
            events.append(
                DetectionEvent(
                    node=node,
                    delta=delta,
                    label="cycle",
                    evidence=f"cycle(k={count},min_len={min_len},sev={severity:.2f})",
                )
            )
        return events

    def _detect_scatter(self, succ: Dict[str, Set[str]], pred: Dict[str, Set[str]]) -> List[DetectionEvent]:
        events: List[DetectionEvent] = []
        for node in self.graph.nodes():
            out_deg = len(succ.get(node, set()))
            in_deg = len(pred.get(node, set()))
            if in_deg < 1:
                continue
            if out_deg > self.scatter_ratio * in_deg:
                ratio = out_deg / max(1.0, in_deg)
                severity = _clamp01((ratio / max(self.scatter_ratio, 0.1) - 1.0) / 2.0)
                delta = self._severity_scaled_delta(DELTA_SCATTER, severity)
                events.append(
                    DetectionEvent(
                        node=node,
                        delta=delta,
                        label="scatter",
                        evidence=f"scatter(out={out_deg},in={in_deg},sev={severity:.2f})",
                    )
                )
        return events

    def detect_patterns(self) -> List[Dict[str, Any]]:
        scores: Dict[str, float] = defaultdict(float)
        evidence: Dict[str, List[str]] = defaultdict(list)

        succ, pred = self._node_neighbors()
        events: List[DetectionEvent] = []
        events.extend(self._detect_fan_out(succ))
        events.extend(self._detect_fan_in(pred))
        events.extend(self._detect_cycle())
        events.extend(self._detect_scatter(succ, pred))

        for ev in events:
            scores[ev.node] += ev.delta
            evidence[ev.node].append(ev.evidence)

        results: List[Dict[str, Any]] = []
        for vpa_hash, total_delta in scores.items():
            if total_delta <= 0.0:
                continue
            clamped = min(total_delta, MAX_GRAPH_DELTA)
            reason_str = "+".join(sorted(set(evidence.get(vpa_hash, []))))
            results.append({
                "vpa_hash": vpa_hash,
                "risk_delta": round(clamped, 4),
                "reason": reason_str,
            })
        return results

    def _build_payload(self, delta: Dict[str, Any]) -> bytes:
        # Rust GraphUpdateRequest expects `_timestamp`.
        payload = {
            "vpa_hash": delta["vpa_hash"],
            "risk_delta": delta["risk_delta"],
            "reason": delta["reason"],
            "_timestamp": int(time.time()),
        }
        return json.dumps(payload, separators=(",", ":")).encode("utf-8")

    def _post_delta(self, delta: Dict[str, Any], timeout_s: float = 2.0) -> Tuple[bool, str]:
        body = self._build_payload(delta)
        headers: Dict[str, str] = {"Content-Type": "application/json"}
        if self.secret:
            sig = _sign_payload(self.secret, body)
            headers["X-Varaksha-Signature"] = f"sha256={sig}"

        req = urllib.request.Request(self.endpoint, data=body, headers=headers, method="POST")
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
        ok = failed = 0
        for i in range(0, len(deltas), batch_size):
            batch = deltas[i : i + batch_size]
            results = await asyncio.gather(*(asyncio.to_thread(self._post_delta, d, timeout_s) for d in batch))
            for success, _ in results:
                if success:
                    ok += 1
                else:
                    failed += 1
        return {"ok": ok, "failed": failed}

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

    @classmethod
    def from_demo_seed(
        cls,
        seed_vpa: str,
        endpoint: str = DEFAULT_ENDPOINT,
        secret: Optional[str] = None,
    ) -> "GraphAgent":
        """
        Deterministic suspicious subgraph for live demos.
        Creates fan-in, fan-out, cycle and scatter pressure around `seed_vpa`.
        """
        agent = cls(window_size=500, endpoint=endpoint, secret=secret)
        ts = int(time.time())

        # Fan-in to seed.
        for i in range(1, 9):
            agent.ingest(f"sender_{i}@upi", seed_vpa, 1000 + i * 50, str(ts + i))

        # Fan-out from seed.
        for i in range(1, 6):
            agent.ingest(seed_vpa, f"receiver_{i}@upi", 900 + i * 30, str(ts + 20 + i))

        # Short cycle including seed.
        agent.ingest(seed_vpa, "loop_a@upi", 5000, str(ts + 40))
        agent.ingest("loop_a@upi", "loop_b@upi", 4800, str(ts + 41))
        agent.ingest("loop_b@upi", seed_vpa, 4700, str(ts + 42))

        # Scatter pressure.
        agent.ingest("anchor_in@upi", seed_vpa, 1500, str(ts + 50))
        for i in range(6, 12):
            agent.ingest(seed_vpa, f"scatter_{i}@upi", 700 + i * 20, str(ts + 60 + i))

        return agent

    def stats(self) -> Dict[str, Any]:
        return {
            "nodes": self.graph.number_of_nodes(),
            "edges": self.graph.number_of_edges(),
            "window_used": len(self._window),
            "window_capacity": self.window_size,
        }


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Varaksha Graph Agent")
    p.add_argument(
        "--parquet",
        type=Path,
        default=Path("datasets_copy/PRODUCTION_DATASETS/upi_transactions_2024/varaksha_train_clean.parquet"),
        help="Path to parquet file for graph construction.",
    )
    p.add_argument("--window-size", type=int, default=DEFAULT_WINDOW_SIZE)
    p.add_argument("--endpoint", type=str, default=DEFAULT_ENDPOINT)
    p.add_argument("--secret", type=str, default=None)
    p.add_argument("--sender-col", type=str, default="sender_bank")
    p.add_argument("--receiver-col", type=str, default="receiver_bank")
    p.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE)
    p.add_argument("--timeout", type=float, default=2.0)
    p.add_argument("--dry-run", action="store_true")
    p.add_argument(
        "--demo-seed-vpa",
        type=str,
        default=None,
        help="Build deterministic suspicious graph around this VPA instead of loading parquet.",
    )
    return p.parse_args()


async def _main() -> None:
    args = _parse_args()

    if args.demo_seed_vpa:
        print(f"[graph_agent] Demo mode around seed VPA: {args.demo_seed_vpa}")
        agent = GraphAgent.from_demo_seed(seed_vpa=args.demo_seed_vpa, endpoint=args.endpoint, secret=args.secret)
    else:
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
    print(f"[graph_agent] Deltas detected: {len(deltas)}")

    if deltas:
        print("\n  vpa_hash (first 12)       risk_delta  reason")
        print("  " + "-" * 85)
        for d in sorted(deltas, key=lambda x: -x["risk_delta"])[:20]:
            print(f"  {d['vpa_hash'][:12]}...  {d['risk_delta']:.4f}      {d['reason']}")

    if args.dry_run:
        print("\n[graph_agent] Dry-run mode — skipping push.")
        return

    if not agent.secret:
        print("\n[graph_agent] WARNING: VARAKSHA_GRAPH_SECRET not set. Pushing unsigned.")

    print(f"\n[graph_agent] Pushing {len(deltas)} deltas to {args.endpoint} ...")
    stats = await agent.push_all_deltas(deltas, args.batch_size, args.timeout)
    print(f"[graph_agent] Push complete: ok={stats['ok']}, failed={stats['failed']}")


if __name__ == "__main__":
    asyncio.run(_main())
