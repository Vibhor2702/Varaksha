"""
pipeline.py — LangGraph Orchestration
=======================================
Wires Agents 01 → 02 → 03 through typed state, with gate verification
at every transition.  The gateway calls this orchestrator at
POST /v1/orchestrate.

Graph topology:
    START → profile → graph_analyse → decide → END

Each edge is a Gate: the receiving agent re-verifies the previous agent's
Ed25519 signature before accepting the state.  An invalid signature short-
circuits to a BLOCK verdict without executing the next agent.

This module is also importable as a library (e.g., by the Streamlit demo).
"""

from __future__ import annotations

import logging
import os
from typing import Annotated, TypedDict

import httpx
from langgraph.graph import END, START, StateGraph

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
log = logging.getLogger("pipeline")

# ─── Service URLs ─────────────────────────────────────────────────────────────

AGENT01_URL = os.getenv("AGENT01_URL", "http://127.0.0.1:8001/v1/profile")
AGENT02_URL = os.getenv("AGENT02_URL", "http://127.0.0.1:8002/v1/graph")
AGENT03_URL = os.getenv("AGENT03_URL", "http://127.0.0.1:8003/v1/decide")

# ─── Pipeline State ───────────────────────────────────────────────────────────

class PipelineState(TypedDict):
    """Typed state threaded through every LangGraph node."""
    sanitized_tx:   dict           # from Rust gateway (SanitizedTx)
    agent01_result: dict | None    # AgentVerdict
    agent02_result: dict | None    # GraphVerdict
    final_verdict:  dict | None    # FinalVerdict
    error:          str | None     # set on any failure — short-circuits to BLOCK


# ─── Nodes ────────────────────────────────────────────────────────────────────

async def node_profile(state: PipelineState) -> PipelineState:
    """Call Agent 01 — transaction anomaly profiling."""
    if state.get("error"):
        return state

    tx = state["sanitized_tx"]
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(AGENT01_URL, json=tx)
        if resp.status_code != 200:
            raise ValueError(f"Agent 01 HTTP {resp.status_code}: {resp.text[:200]}")
        result = resp.json()
        log.info("tx_id=%s Agent01 verdict=%s anomaly=%.3f",
                 tx.get("tx_id"), result.get("verdict"), result.get("anomaly_score"))
        state["agent01_result"] = result
    except Exception as e:
        log.error("Agent 01 failed: %s", e)
        state["error"] = f"agent01_error: {e}"
    return state


async def node_graph_analyse(state: PipelineState) -> PipelineState:
    """Call Agent 02 — graph-based mule detection."""
    if state.get("error"):
        return state

    a1 = state["agent01_result"]
    # Merge sender/receiver from original sanitized_tx so Agent 02 can build graph
    payload = {**a1, **{
        "pseudo_sender":   state["sanitized_tx"].get("pseudo_sender"),
        "pseudo_receiver": state["sanitized_tx"].get("pseudo_receiver"),
        "timestamp":       state["sanitized_tx"].get("timestamp"),
    }}
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(AGENT02_URL, json=payload)
        if resp.status_code != 200:
            raise ValueError(f"Agent 02 HTTP {resp.status_code}: {resp.text[:200]}")
        result = resp.json()
        log.info("tx_id=%s Agent02 graph_score=%.3f patterns=%s",
                 a1.get("tx_id"), result.get("graph_score"), result.get("patterns_detected"))
        state["agent02_result"] = result
    except Exception as e:
        log.error("Agent 02 failed: %s", e)
        state["error"] = f"agent02_error: {e}"
    return state


async def node_decide(state: PipelineState) -> PipelineState:
    """Call Agent 03 — weighted final decision + narrative."""
    if state.get("error"):
        return state

    ctx = {"agent01": state["agent01_result"], "agent02": state["agent02_result"]}
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(AGENT03_URL, json=ctx)
        if resp.status_code != 200:
            raise ValueError(f"Agent 03 HTTP {resp.status_code}: {resp.text[:200]}")
        result = resp.json()
        log.info("tx_id=%s FINAL verdict=%s score=%.4f",
                 result.get("tx_id"), result.get("verdict"), result.get("final_score"))
        state["final_verdict"] = result
    except Exception as e:
        log.error("Agent 03 failed: %s", e)
        state["error"] = f"agent03_error: {e}"
    return state


# ─── Edge condition ───────────────────────────────────────────────────────────

def route_on_error(state: PipelineState) -> str:
    """Short-circuit to END (with BLOCK) on any pipeline error."""
    if state.get("error"):
        # Synthesise a BLOCK verdict for the error path
        tx_id = state["sanitized_tx"].get("tx_id", "unknown")
        state["final_verdict"] = {
            "tx_id":          tx_id,
            "final_score":    1.0,
            "verdict":        "BLOCK",
            "narrative":      f"Pipeline error — transaction blocked for safety. Error: {state['error']}",
            "law_refs":       [],
            "gate_final_sig": "error-path",
            "key_fingerprint": "error-path",
            "latency_ms":     0.0,
        }
        return END
    return "graph_analyse"


def route_after_graph(state: PipelineState) -> str:
    if state.get("error"):
        tx_id = state["sanitized_tx"].get("tx_id", "unknown")
        state["final_verdict"] = {
            "tx_id":          tx_id,
            "final_score":    1.0,
            "verdict":        "BLOCK",
            "narrative":      f"Pipeline error at graph stage — blocked for safety. Error: {state['error']}",
            "law_refs":       [],
            "gate_final_sig": "error-path",
            "key_fingerprint": "error-path",
            "latency_ms":     0.0,
        }
        return END
    return "decide"


# ─── Build the graph ──────────────────────────────────────────────────────────

def build_pipeline() -> StateGraph:
    g = StateGraph(PipelineState)

    g.add_node("profile",        node_profile)
    g.add_node("graph_analyse",  node_graph_analyse)
    g.add_node("decide",         node_decide)

    g.add_edge(START, "profile")
    g.add_conditional_edges("profile",       route_on_error,   {"graph_analyse": "graph_analyse", END: END})
    g.add_conditional_edges("graph_analyse", route_after_graph, {"decide": "decide",              END: END})
    g.add_edge("decide", END)

    return g


# Compiled graph — import this in demo/app.py and the gateway
pipeline = build_pipeline().compile()


# ─── FastAPI wrapper (optional — gateway can call this instead of agents directly) ──

from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(
    title="Varaksha Pipeline Orchestrator",
    description="LangGraph pipeline: Agent 01 → 02 → 03 with gate verification.",
    version="0.1.0",
)

class OrchestrateRequest(BaseModel):
    sanitized_tx: dict

@app.post("/v1/orchestrate")
async def orchestrate(req: OrchestrateRequest) -> dict:
    initial: PipelineState = {
        "sanitized_tx":   req.sanitized_tx,
        "agent01_result": None,
        "agent02_result": None,
        "final_verdict":  None,
        "error":          None,
    }
    result = await pipeline.ainvoke(initial)
    return result.get("final_verdict", {
        "verdict": "BLOCK",
        "narrative": "Pipeline produced no verdict — blocked for safety.",
    })

@app.get("/health")
async def health() -> dict:
    return {"status": "ok", "component": "pipeline_orchestrator"}
