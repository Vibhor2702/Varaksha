"""
agent02_graph.py — Graph-Based Mule Network Analyst
=====================================================
Receives the AgentVerdict from Agent 01, builds/queries an in-memory
NetworkX graph of pseudonymized transaction flow, and detects:

  • Fan-out fraud:   one sender → ≥4 distinct receivers within 1 hour
  • Circular flow:   A → B → C → A within 24 hours (money-mule circuit)
  • Hub accounts:    high betweenness centrality outliers

SGX NOTE: In a production TEE deployment, the graph would run inside an
Intel SGX enclave via Gramine-SGX so the pseudonymized edges remain
confidential even from the host OS. On this 14th-gen Intel machine SGX
is NOT available, so we label this "[SGX simulation]" throughout.
The logic is identical; only the memory isolation is absent.

Inputs (JSON POST /v1/graph):
    AgentVerdict from Agent 01

Outputs (JSON body):
    GraphVerdict {
        tx_id, fan_out_score, circular_score, hub_score,
        graph_score, patterns_detected, gate_b_sig, key_fingerprint
    }
"""

from __future__ import annotations

import json
import logging
import os
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any

import networkx as nx
import numpy as np
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
log = logging.getLogger("agent02")

# ─── Config ───────────────────────────────────────────────────────────────────

SIGNING_KEY   = os.getenv("AGENT02_SIGNING_KEY_HEX", "")
VERIFYING_KEY = os.getenv("AGENT01_VERIFYING_KEY_HEX", "")

FAN_OUT_THRESHOLD        = 4     # distinct receivers from same sender within 1h
CIRCULAR_WINDOW_HOURS    = 24
HUB_CENTRALITY_THRESHOLD = 0.35  # betweenness centrality
GRAPH_TTL_SECONDS        = 24 * 3600  # prune edges older than 24h

# ─── Pydantic models ──────────────────────────────────────────────────────────

class AgentVerdict(BaseModel):
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
    # Extra fields passed through from gateway SanitizedTx
    pseudo_sender:   str | None = None
    pseudo_receiver: str | None = None
    timestamp:       str | None = None


class GraphVerdict(BaseModel):
    tx_id:              str
    fan_out_score:      float = Field(ge=0.0, le=1.0)
    circular_score:     float = Field(ge=0.0, le=1.0)
    hub_score:          float = Field(ge=0.0, le=1.0)
    graph_score:        float = Field(ge=0.0, le=1.0)
    patterns_detected:  list[str]
    sgx_note:           str
    gate_b_sig:         str
    key_fingerprint:    str
    latency_ms:         float


# ─── Edge record ─────────────────────────────────────────────────────────────

@dataclass
class Edge:
    sender:   str
    receiver: str
    ts:       float = field(default_factory=time.time)


# ─── Persistent graph (in-process, [SGX simulation] boundary) ────────────────

class TransactionGraph:
    """
    [SGX simulation] — in production this class runs inside a Gramine-SGX
    enclave.  The pseudonymized edges are invisible to the host OS.
    On this hardware (14th-gen Intel, no SGX) the enclave boundary is absent;
    the memory protection is software-only.
    """

    def __init__(self) -> None:
        self._graph: nx.DiGraph = nx.DiGraph()
        self._edge_log: deque[Edge] = deque()
        self._sender_receivers: dict[str, dict[str, list[float]]] = defaultdict(
            lambda: defaultdict(list)
        )

    def add_edge(self, sender: str, receiver: str) -> None:
        now = time.time()
        self._graph.add_edge(sender, receiver, ts=now)
        self._edge_log.append(Edge(sender, receiver, now))
        self._sender_receivers[sender][receiver].append(now)
        self._prune_old_edges()

    def _prune_old_edges(self) -> None:
        cutoff = time.time() - GRAPH_TTL_SECONDS
        while self._edge_log and self._edge_log[0].ts < cutoff:
            old = self._edge_log.popleft()
            # Remove from sender_receivers
            times = self._sender_receivers.get(old.sender, {}).get(old.receiver, [])
            self._sender_receivers[old.sender][old.receiver] = [
                t for t in times if t > cutoff
            ]

    def fan_out_score(self, sender: str) -> tuple[float, list[str]]:
        """Fraction of receivers from this sender in last 1h vs FAN_OUT_THRESHOLD."""
        now = time.time()
        cutoff = now - 3600.0
        recent_receivers = {
            recv
            for recv, times in self._sender_receivers.get(sender, {}).items()
            if any(t > cutoff for t in times)
        }
        count = len(recent_receivers)
        score = min(count / FAN_OUT_THRESHOLD, 1.0)
        patterns: list[str] = []
        if count >= FAN_OUT_THRESHOLD:
            patterns.append(f"FAN_OUT:{sender[:8]}→{count}_receivers_1h")
        return float(score), patterns

    def circular_score(self, sender: str, receiver: str) -> tuple[float, list[str]]:
        """
        BFS for A→B→…→A within CIRCULAR_WINDOW_HOURS.
        Returns (score, [pattern_labels]).
        """
        patterns: list[str] = []
        try:
            if nx.has_path(self._graph, receiver, sender):
                path = nx.shortest_path(self._graph, receiver, sender)
                patterns.append(
                    f"CIRCULAR:{'→'.join(n[:8] for n in path)}"
                )
                return 1.0, patterns
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            pass
        return 0.0, []

    def hub_score(self, node: str) -> float:
        """Betweenness centrality of a node — high = money-mule hub."""
        if len(self._graph.nodes) < 3:
            return 0.0
        try:
            bc = nx.betweenness_centrality(self._graph, normalized=True)
            return float(np.clip(bc.get(node, 0.0) / HUB_CENTRALITY_THRESHOLD, 0.0, 1.0))
        except Exception:
            return 0.0


tx_graph = TransactionGraph()

# ─── Signature helpers ────────────────────────────────────────────────────────

def verify_agent01_sig(verdict: AgentVerdict) -> bool:
    if not RUST_CRYPTO_AVAILABLE or not VERIFYING_KEY:
        return True
    payload = verdict.model_dump(exclude={"gate_a_sig"})
    return vg.verify_payload(json.dumps(payload, sort_keys=True), verdict.gate_a_sig, VERIFYING_KEY)


def sign_verdict(d: dict) -> str:
    if not RUST_CRYPTO_AVAILABLE or not SIGNING_KEY:
        return "mock-sig-agent02"
    return vg.sign_payload(json.dumps(d, sort_keys=True), SIGNING_KEY)


# ─── FastAPI ──────────────────────────────────────────────────────────────────

app = FastAPI(
    title="Varaksha Agent 02 — Graph Analyst [SGX simulation]",
    description=(
        "NetworkX mule-network detector. Receives AgentVerdict from Agent 01. "
        "In production: runs inside Gramine-SGX enclave. "
        "On this machine: simulation mode only — memory isolation absent."
    ),
    version="0.1.0",
)


@app.post("/v1/graph", response_model=GraphVerdict)
async def analyse_graph(verdict: AgentVerdict) -> GraphVerdict:
    t0 = time.perf_counter()

    # 1. Verify Agent 01 gate signature
    if not verify_agent01_sig(verdict):
        log.warning("tx_id=%s Agent 01 gate_a_sig invalid — reject", verdict.tx_id)
        raise HTTPException(status_code=400, detail="gate_a_sig_invalid")

    sender   = verdict.pseudo_sender   or "unknown_sender"
    receiver = verdict.pseudo_receiver or "unknown_receiver"

    # 2. Add this edge to the graph
    tx_graph.add_edge(sender, receiver)

    # 3. Compute graph features
    fan_score,  fan_patterns  = tx_graph.fan_out_score(sender)
    circ_score, circ_patterns = tx_graph.circular_score(sender, receiver)
    hub_s                     = tx_graph.hub_score(sender)

    patterns = fan_patterns + circ_patterns
    if hub_s >= 0.8:
        patterns.append(f"HUB:{sender[:8]}_centrality_high")

    # 4. Aggregate graph score
    graph_score = round(float(np.clip(
        0.40 * circ_score + 0.35 * fan_score + 0.25 * hub_s, 0.0, 1.0
    )), 4)

    log.info(
        "tx_id=%s fan=%.2f circ=%.2f hub=%.2f graph=%.3f patterns=%s",
        verdict.tx_id, fan_score, circ_score, hub_s, graph_score, patterns,
    )

    latency_ms = round((time.perf_counter() - t0) * 1000, 2)
    fp = SIGNING_KEY[:32] if SIGNING_KEY else "agent02-mock-fp"

    out = {
        "tx_id":             verdict.tx_id,
        "fan_out_score":     round(fan_score, 4),
        "circular_score":    round(circ_score, 4),
        "hub_score":         round(hub_s, 4),
        "graph_score":       graph_score,
        "patterns_detected": patterns,
        "sgx_note":          "[SGX simulation] — enclave boundary absent on 14th-gen Intel (no SGX hardware)",
        "gate_b_sig":        "",
        "key_fingerprint":   fp,
        "latency_ms":        latency_ms,
    }
    out["gate_b_sig"] = sign_verdict(out)
    return GraphVerdict(**out)


@app.get("/health")
async def health() -> dict:
    return {
        "status": "ok",
        "agent": "graph_analyst",
        "graph_nodes": len(tx_graph._graph.nodes),
        "graph_edges": len(tx_graph._graph.edges),
        "sgx_mode":    "simulation",
    }
