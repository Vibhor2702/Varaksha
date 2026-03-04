"""
demo/app.py — Varaksha Streamlit Demo Harness
==============================================
Interactive demo for ISEA Phase-III judges.

Shows:
  1. Send a synthetic (no real PII) transaction through the full pipeline
  2. Live verdict + risk score + narrative
  3. Download the signed PDF report
  4. Architecture diagram + gate signature trail

Run with:
    streamlit run demo/app.py

Requires:
  • All agents running (ports 8001–8003) OR pipeline orchestrator on 8000
  • .env file with OPENAI_API_KEY (or leave blank for template narratives)
  • pip install -r agents/requirements.txt
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import httpx
import streamlit as st
from dotenv import load_dotenv

load_dotenv()

# ─── Config ───────────────────────────────────────────────────────────────────

PIPELINE_URL = os.getenv("PIPELINE_URL", "http://127.0.0.1:8000/v1/orchestrate")
GATEWAY_URL  = os.getenv("GATEWAY_URL",  "http://127.0.0.1:8080/v1/tx")
REPORTS_DIR  = Path("reports")

# ─── Page setup ───────────────────────────────────────────────────────────────

st.set_page_config(
    page_title="Varaksha — UPI Fraud Detection Demo",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Brand CSS
st.markdown("""
<style>
    body { font-family: 'Inter', sans-serif; }
    .stApp { background-color: #0f0f1a; color: #e5e7eb; }
    .verdict-block  { background: #1e1b4b; border-left: 4px solid #dc2626; padding: 12px 16px; border-radius: 6px; }
    .verdict-flag   { background: #1e1b4b; border-left: 4px solid #f59e0b; padding: 12px 16px; border-radius: 6px; }
    .verdict-allow  { background: #1e1b4b; border-left: 4px solid #16a34a; padding: 12px 16px; border-radius: 6px; }
    .metric-card    { background: #1a1a2e; padding: 12px; border-radius: 8px; text-align: center; }
    code { background: #1e293b; padding: 2px 6px; border-radius: 3px; font-size: 12px; }
</style>
""", unsafe_allow_html=True)

# ─── Sidebar ──────────────────────────────────────────────────────────────────

with st.sidebar:
    st.image("https://img.shields.io/badge/Varaksha-v0.1.0-7c3aed?style=flat-square")
    st.markdown("### System Status")

    def ping(url: str, label: str) -> None:
        try:
            r = httpx.get(url.replace("/v1/tx", "/health").replace("/v1/orchestrate", "/health"), timeout=2.0)
            st.success(f"✅ {label}")
        except Exception:
            st.error(f"❌ {label} (offline)")

    ping(GATEWAY_URL,  "Rust Gateway :8080")
    ping(f"http://127.0.0.1:8000/health", "Pipeline :8000")
    ping(f"http://127.0.0.1:8001/health", "Agent 01 :8001")
    ping(f"http://127.0.0.1:8002/health", "Agent 02 :8002")
    ping(f"http://127.0.0.1:8003/health", "Agent 03 :8003")

    st.markdown("---")
    st.markdown("""
**Security notes**
- All UPI IDs → HMAC-SHA256 pseudonyms
- Amount → Laplace DP noise (ε=1.0)
- GPS → great-circle km only
- Ed25519 signatures at every gate
- SGX: simulation on this hardware
""")

# ─── Main UI ─────────────────────────────────────────────────────────────────

st.title("🛡️ Varaksha — UPI Fraud Detection Demo")
st.caption("Production-grade Rust gateway + LangGraph agent pipeline. Zero PII in AI context.")

tab_demo, tab_arch, tab_bench = st.tabs(["🔍 Live Demo", "🏗️ Architecture", "⚔️ Bench Results"])

# ── TAB 1: Live Demo ─────────────────────────────────────────────────────────

with tab_demo:
    st.subheader("Submit a Transaction")
    st.info(
        "All values below are SYNTHETIC — no real UPI IDs or personal data. "
        "The system will pseudonymize them before any AI processing."
    )

    col1, col2 = st.columns(2)

    with col1:
        sender_upi   = st.text_input("Sender UPI ID (demo)",   value="alice@okaxis")
        receiver_upi = st.text_input("Receiver UPI ID (demo)", value="bob@paytm")
        amount       = st.number_input("Amount (₹)", min_value=1.0, max_value=10_00_000.0,
                                        value=12_500.0, step=100.0)

    with col2:
        merchant_cat = st.selectbox(
            "Merchant Category",
            ["groceries", "utilities", "fuel", "rent", "healthcare",
             "wire_transfer", "food", "unknown"],
        )
        upi_network      = st.selectbox("UPI Network", ["NPCI", "HDFC", "ICICI", "SBI"])
        is_first         = st.checkbox("First transfer between these parties", value=False)
        include_gps      = st.checkbox("Include GPS coordinates (will be hashed to distance only)", value=True)

    if include_gps:
        c1, c2 = st.columns(2)
        with c1:
            sender_lat = st.number_input("Sender Lat", value=19.076090)
            sender_lon = st.number_input("Sender Lon", value=72.877426)
        with c2:
            recv_lat = st.number_input("Receiver Lat", value=28.613939)
            recv_lon = st.number_input("Receiver Lon", value=77.209023)
    else:
        sender_lat = sender_lon = recv_lat = recv_lon = None

    upi_note = st.text_input("UPI Note / Memo", value="Rent for March")

    if st.button("🚀 Submit Transaction", type="primary"):
        payload = {
            "sender_upi_id":    sender_upi,
            "receiver_upi_id":  receiver_upi,
            "amount_inr":       amount,
            "merchant_category": merchant_cat,
            "upi_network":      upi_network,
            "is_first_transfer": is_first,
        }
        if include_gps and all(v is not None for v in [sender_lat, sender_lon, recv_lat, recv_lon]):
            payload.update({
                "sender_lat": sender_lat, "sender_lon": sender_lon,
                "receiver_lat": recv_lat, "receiver_lon": recv_lon,
            })

        with st.spinner("Processing through Rust gateway → Agent 01 → 02 → 03…"):
            t0 = time.perf_counter()
            try:
                resp = httpx.post(GATEWAY_URL, json=payload, timeout=15.0)
                elapsed = (time.perf_counter() - t0) * 1000
                resp.raise_for_status()
                result = resp.json()
            except httpx.HTTPStatusError as e:
                st.error(f"Gateway error {e.response.status_code}: {e.response.text[:300]}")
                st.stop()
            except Exception as e:
                st.error(f"Connection error: {e}")
                st.stop()

        verdict = result.get("verdict", "UNKNOWN")
        score   = result.get("risk_score", result.get("final_score", 0.0))

        # Verdict banner
        css_class = {
            "BLOCK": "verdict-block",
            "FLAG":  "verdict-flag",
            "ALLOW": "verdict-allow",
        }.get(verdict, "verdict-allow")
        icon = {"BLOCK": "🚫", "FLAG": "⚠️", "ALLOW": "✅"}.get(verdict, "❓")

        st.markdown(f"""
<div class="{css_class}">
  <h2 style="margin:0">{icon} {verdict}</h2>
  <p style="margin:4px 0 0 0; color:#9ca3af">Risk score: <b>{score:.4f}</b> · Pipeline: {elapsed:.0f} ms</p>
</div>
""", unsafe_allow_html=True)

        st.markdown("---")

        # Metrics row
        mc1, mc2, mc3, mc4 = st.columns(4)
        mc1.metric("Final Score",   f"{score:.4f}")
        mc2.metric("Tx ID",         result.get("tx_id", "—")[:12] + "…")
        mc3.metric("Gate FP",       result.get("gate_fingerprint", result.get("key_fingerprint", "—"))[:12] + "…")
        mc4.metric("Latency",       f"{elapsed:.0f} ms")

        # Narrative
        narrative = result.get("narrative", "")
        if narrative:
            st.markdown("**System Narrative**")
            st.info(narrative)

        # Law refs
        law_refs = result.get("law_refs", [])
        if law_refs:
            st.markdown("**Applicable Law Sections**")
            for r in law_refs:
                st.markdown(f"- **{r.get('section')}** — {r.get('description')} (max: {r.get('max_sentence')})")

        # Gate signature trail
        with st.expander("🔐 Cryptographic Trail"):
            st.code(json.dumps(result, indent=2), language="json")

        # PDF download
        if verdict in ("BLOCK", "FLAG"):
            try:
                sys.path.insert(0, str(Path(__file__).parent.parent / "agents"))
                from legal_report import generate_report
                pdf_path = generate_report(result, output_dir=str(REPORTS_DIR))
                pdf_bytes = pdf_path.read_bytes()
                st.download_button(
                    "📄 Download Signed PDF Report",
                    data=pdf_bytes,
                    file_name=pdf_path.name,
                    mime="application/pdf",
                )
            except Exception as e:
                st.warning(f"PDF generation error: {e}")

# ── TAB 2: Architecture ───────────────────────────────────────────────────────

with tab_arch:
    st.subheader("Pipeline Architecture")
    st.markdown("""
```
Client → [Rust Gateway :8080]
           │  Rate-limit check (DashMap sliding window)
           │  HMAC-SHA256 pseudonymize UPI IDs
           │  Laplace DP noise on amount (ε=1.0)
           │  GPS → great-circle km (no raw coords)
           │  Ed25519 sign SanitizedTx
           ▼
         [Gate A]  ← Ed25519 verify
           │
         [Agent 01: IsolationForest Profiler :8001]
           │  IsolationForest anomaly score (PaySim-trained)
           │  Sliding-window velocity counter
           │  Z-score on amount
           │  Ed25519 sign AgentVerdict
           ▼
         [Gate B]  ← Ed25519 verify
           │
         [Agent 02: Graph Analyst :8002]  [SGX simulation]
           │  NetworkX DiGraph: fan-out, circular flow, hub centrality
           │  Ed25519 sign GraphVerdict
           ▼
         [Gate C]  ← Ed25519 verify
           │
         [Agent 03: Decision :8003]
           │  Weighted score: 0.35×anomaly + 0.35×graph + 0.15×velocity + 0.15×hub
           │  Law mapping: BNS §318(4), §111, IT Act §66C, PMLA §3
           │  GPT-4o-mini zero-PII narrative
           │  Ed25519 sign FinalVerdict
           ▼
         ALLOW / FLAG / BLOCK + court-ready PDF
```
""")

    st.markdown("**Adversarial scan (pre-pipeline)**")
    st.markdown("""
- Regex sweep (instant, 10+ patterns)
- FAISS cosine similarity vs deepset/prompt-injections index
- KL-divergence vs legitimate UPI memo corpus
""")

# ── TAB 3: Bench Results ──────────────────────────────────────────────────────

with tab_bench:
    st.subheader("Adversarial Benchmark (varaksha-bench)")
    st.markdown("""
Run `varaksha-bench --target http://localhost:8080 --report ./report.pdf` after
compiling with `cargo build --features bench-mode`.

The bench crate sends 200 payloads across 5 MITRE ATLAS attack classes and
expects ≥95% block rate to pass CI.

| Attack Class | MITRE ATLAS | OWASP ML | Severity |
|---|---|---|---|
| Data Poisoning | AML.T0020 | ML05 | HIGH |
| Model Evasion | AML.T0015 | ML04 | CRITICAL |
| Prompt Injection | AML.T0051 | ML06 | CRITICAL |
| Membership Inference | AML.T0024 | ML03 | MEDIUM |
| Model Inversion | AML.T0024.001 | ML03 | MEDIUM |

**bench-mode safety:** The `/test/art-harness` route is compiled-in ONLY when
`--features bench-mode` is passed to cargo. Production binaries are built with
`cargo build --release` (no flags) and have no ART endpoint.
""")

    # Show last bench JSON if it exists
    bench_json = Path("varaksha-bench-report.json")
    if bench_json.exists():
        st.markdown("**Last benchmark run:**")
        data = json.loads(bench_json.read_text())
        st.metric("Block Rate", f"{data.get('block_rate_pct', 0):.1f}%")
        st.metric("Total Attacks", data.get("total_attacks", 0))
        st.metric("Blocked", data.get("total_blocked", 0))
        with st.expander("Full JSON"):
            st.json(data)
    else:
        st.info("No bench report found. Run varaksha-bench to generate one.")
