# Varaksha V2 — Privacy-Preserving Collaborative UPI Fraud Intelligence Network

> **Hackathon:** Secure AI Software & Systems Hackathon — Blue Team: NPCI UPI Fraud Detection  
> **Branch:** `test` | **Status:** Active Development

---

## What Is Varaksha?

Varaksha ("protection" in Sanskrit) is a multi-layer, privacy-first fraud intelligence network for UPI payments. It combines a real-time Rust cache, a multi-model ML ensemble, a graph-based money-mule detector, a prompt-injection guard, and an accessible multilingual alert system — all wired together into a Streamlit analyst dashboard.

The system is designed so that **no raw VPA (Virtual Payment Address / phone number) ever leaves the first processing step** — everything downstream operates on SHA-256 hashes only.

---

## Architecture

```
 ┌─────────────────────────────────────────────────────────────────────────────┐
 │                         VARAKSHA V2 — SYSTEM OVERVIEW                      │
 └─────────────────────────────────────────────────────────────────────────────┘

  UPI Payment App / Bank
         │  POST /v1/tx  {vpa, amount_paise, merchant_category, device_id, ts}
         ▼
 ┌───────────────────────────────────────────────────────────────────────────┐
 │  LAYER 2 — Rust Gateway  (Actix-Web 4, port 8082)                        │
 │                                                                           │
 │  1. SHA-256 hash the raw VPA → vpa_hash  (PII boundary — raw VPA stops)  │
 │  2. DashMap lookup: vpa_hash → (risk_score, reason, ttl)                 │
 │     • O(1) shard-locked read — target < 1 ms                             │
 │  3. score_to_verdict():   < 0.40 → ALLOW                                 │
 │                        0.40–0.75 → FLAG  (biometric step-up)             │
 │                           ≥ 0.75 → BLOCK                                 │
 │  4. Return TxResponse {vpa_hash, verdict, risk_score, trace_id,          │
 │                         latency_us}  in < 5 ms P99                       │
 └──────────────┬────────────────────────────────────────────────────────────┘
                │ async (out of hot path)
      ┌─────────┴──────────┐
      │                    │
      ▼                    ▼
 ┌──────────────┐   ┌──────────────────────────────────────────────────────┐
 │  LAYER 1     │   │  LAYER 3 — Graph Agent  (NetworkX, BIS Aurora model) │
 │  ML Engine   │   │                                                      │
 │  Python      │   │  Builds a directed transaction graph in memory.      │
 │              │   │  Detects four money-mule typologies:                 │
 │  Models:     │   │  • Fan-out  : 1 source → many destinations           │
 │  ┌─────────┐ │   │  • Fan-in   : many sources → 1 destination           │
 │  │ RF      │ │   │  • Cycle    : A→B→C→A  (layering / ring)             │
 │  │ XGBoost │ │   │  • Scatter  : high out-degree (structuring)          │
 │  │ LightGBM│ │   │                                                      │
 │  │ IsoFrst │ │   │  On detection → POST /v1/webhook/update_cache        │
 │  │ Voting  │ │   │  with HMAC-SHA256 signed payload → Rust DashMap      │
 │  └─────────┘ │   │  updated with risk_score ≥ 0.75 for flagged VPAs    │
 │              │   └──────────────────────────────────────────────────────┘
 │  SMOTE on    │              │
 │  train split │              │ (score feeds back into Layer 2 cache)
 │  only        │              │
 │              │              ▼
 │  SHAP        │   ┌──────────────────────────────────────────────────────┐
 │  explainer   │   │  LAYER 0 — PromptGuard                               │
 │  per blocked │   │  TF-IDF + LogisticRegression (JailbreakBench data)   │
 │  transaction │   │  Checks merchant_name / device_id / graph flags      │
 └──────────────┘   │  for prompt injection before LLM narration           │
                    └──────────────────────────────────────────────────────┘
                                       │
                                       ▼
                    ┌──────────────────────────────────────────────────────┐
                    │  LAYER 4 — Personalised Alert Agent                  │
                    │  (agent03_accessible_alert.py)                       │
                    │                                                      │
                    │  Inputs from bank app: language, age_group,          │
                    │  education  →  UserProfile                           │
                    │                                                      │
                    │  Pipeline:                                           │
                    │  1. Build law citations (IT Act §66D, BNS §318(4),   │
                    │     PMLA §3/§4, RBI Master Direction 2025)           │
                    │     with real India Code / RBI / cybercrime URLs     │
                    │  2. Generate vocabulary-adapted English report       │
                    │     reading_level: simple / standard / detailed      │
                    │  3. Translate via deep-translator (Google Translate  │
                    │     free, no API key) → 69 languages dynamically     │
                    │  4. Generate MP3 via gTTS (primary) + edge-tts       │
                    │     (fallback) — both free, no API key               │
                    └──────────────────────────────────────────────────────┘
                                       │
                                       ▼
                    ┌──────────────────────────────────────────────────────┐
                    │  LAYER 5 — Streamlit Dashboard  (services/demo/app.py)│
                    │  Section 1: Real-time consortium risk cache feed     │
                    │  Section 2: Money-mule graph (Plotly network viz)    │
                    │  Section 3: Personalised multilingual alert panel    │
                    │  Section 4: Global SHAP explainability (model audit) │
                    └──────────────────────────────────────────────────────┘
```

### Data flow in one sentence
> A payment arrives → Rust hashes the VPA and does a sub-millisecond cache lookup → verdict returned; in the background, the Python ML engine + graph agent continuously score known-bad VPAs and push updates into the cache via a signed webhook; if blocked, Layer 4 generates a personalised, translated, audio-enabled fraud report with real law links for the affected user.

---

## Layer Details

### Layer 0 — PromptGuard
- **File:** `services/local_engine/prompt_guard.py`
- **Problem:** LLMs used for alert narration are vulnerable to prompt injection embedded in merchant names or device IDs.
- **Solution:** TF-IDF (unigram+bigram, 8 000 features) → CalibratedLogisticRegression trained on the JailbreakBench dataset (546 rows). Sub-millisecond inference, inline before every LLM call.
- **API:** `is_injection(text: str) -> bool` / `get_risk_score(text: str) -> float`

### Layer 1 — ML Ensemble Engine
- **File:** `services/local_engine/train_ensemble.py`
- **Models:** RandomForest + XGBoost + LightGBM (3-model soft-vote ensemble) + IsolationForest (anomaly detection)
- **Imbalance handling:** SMOTE applied to **training split only** — test set always reflects real class distribution
- **Threshold optimisation:** PR curve sweep → F2-maximising threshold (fixes the paper's 65% recall at default 0.5)
- **SHAP explainability:** TreeExplainer for RF + XGB; beeswarm summary PNGs saved to `data/explainability/`; `explain_transaction()` returns top-6 feature contributions per blocked transaction (court-ready audit trail)
- **Training paths:**  
  1. Synthetic fallback (no CSV needed — auto-generated)  
  2. PaySim CSV (6.36 M rows, real financial crime simulation)  
  3. Paper UPI CSV (Sadaf & Manivannan dataset, 647 rows, 20 features)

### Layer 2 — Rust Gateway
- **Files:** `gateway/src/main.rs`, `cache.rs`, `models.rs`
- **Stack:** Actix-Web 4 + DashMap (concurrent lock-free hashmap)
- **Endpoints:** `GET /health`, `POST /v1/tx`, `POST /v1/webhook/update_cache`
- **Privacy boundary:** VPA is SHA-256 hashed in the very first line of the handler — raw PII never enters the cache
- **Latency target:** P99 < 5 ms for `/v1/tx`
- **Rate limiting:** TODO (teammate) — `/v1/tx` rate-limited to 100 req/IP/min; beyond that → HTTP 429
- **Webhook auth:** HMAC-SHA256 signature over request body via `x-varaksha-sig` header

### Layer 3 — Graph Agent
- **File:** `services/graph/graph_agent.py`
- **Model:** BIS Project Aurora-style directed graph (NetworkX)
- **Typologies:** Fan-out, Fan-in, Cycle, Scatter
- **Output:** Detected mule clusters → HMAC-signed POST to `/v1/webhook/update_cache` → Rust DashMap updated with `risk_score ≥ 0.75`
- **Runs:** Async, completely outside the payment hot path

### Layer 4 — Personalised Alert Agent
- **File:** `services/agents/agent03_accessible_alert.py`
- **Bhashini replacement:** `deep-translator` wraps Google Translate free endpoint — no API key, 69+ languages
- **TTS:** gTTS (primary, Google TTS free) + edge-tts (Microsoft Neural TTS fallback) — both free, no API key
- **Personalisation:** Bank app sends `language`, `age_group`, `education` → `UserProfile` → `reading_level` property
  - `simple`: child / basic education / senior non-graduate — short sentences, numbered steps, no jargon
  - `standard`: adult intermediate
  - `detailed`: graduate adult/teen — full legal citations + SHAP signals
- **Law registry:** `LAW_REGISTRY` — IT Act §66D, BNS §318(4), PMLA §3/§4, RBI Master Direction 2025 — all with live `indiacode.nic.in` / `rbi.org.in` URLs
- **Contact portals:** `cybercrime.gov.in` (1930), `cms.rbi.org.in` (14448), NPCI UPI grievance

### Layer 5 — Streamlit Dashboard
- **File:** `services/demo/app.py`
- **Section 1:** Real-time risk cache feed simulation
- **Section 2:** Money-mule network graph (Plotly)
- **Section 3:** Personalised multilingual alert — language picker (69 langs), age group, education level; shows translated report, law links as clickable hrefs, next steps, gTTS audio
- **Section 4:** Global SHAP explainability — beeswarm + waterfall plots from saved PNG artifacts

---

## Hackathon "Bible" Compliance

| Requirement | Implementation | File |
|---|---|---|
| Anomaly Detection | IsolationForest | `train_ensemble.py` |
| Ensemble Methods | RF + XGBoost + LightGBM soft-vote | `train_ensemble.py` |
| SMOTE (imbalanced data) | Train-split only, test untouched | `train_ensemble.py` |
| User-friendly Dashboard | Streamlit + Plotly | `services/demo/app.py` |
| Real-Time Monitoring | Rust DashMap, < 5 ms P99 | `gateway/` |
| Security Explainability | SHAP TreeExplainer + beeswarm PNGs | `train_ensemble.py` |
| Prompt Injection Guard | TF-IDF + LR on JailbreakBench | `prompt_guard.py` |
| Multilingual Accessibility | 69 langs via gTTS + deep-translator | `agent03_accessible_alert.py` |
| Law citations with links | IT Act, BNS, PMLA, RBI on indiacode.nic.in | `agent03_accessible_alert.py` |
| Adversarial testing | Security Battleground (3 arenas) | `scripts/v2_battleground.py` |

---

## Quick Start

### 1. Python dependencies
```powershell
pip install -r requirements.txt
```

### 2. Train all models (Layer 1)
```powershell
# Synthetic data (no CSV needed):
python services/local_engine/train_ensemble.py

# PaySim real data (6.36 M rows):
python services/local_engine/train_ensemble.py --data data/datasets/PS_20174392719_1491204439457_log.csv

# Paper UPI dataset (Sadaf & Manivannan, 647 rows):
python services/local_engine/train_ensemble.py --data "data/datasets/Untitled spreadsheet - upi_transactions.csv"
```

### 3. Train PromptGuard (Layer 0)
```powershell
python services/local_engine/prompt_guard.py
```

### 4. Start the Rust gateway (Layer 2)
```powershell
cd gateway
cargo run --release
# Listens on http://localhost:8082
```

### 5. Run the graph agent (Layer 3)
```powershell
python services/graph/graph_agent.py
```

### 6. Test the alert pipeline (Layer 4)
```powershell
python services/agents/agent03_accessible_alert.py
```

### 7. Launch the dashboard (Layer 5)
```powershell
streamlit run services/demo/app.py
```

### 8. Run the Security Battleground
```powershell
python scripts/v2_battleground.py --host http://localhost:8082
```

---

## Project Structure

```
varaksha/
│
├── gateway/                              ← Layer 2: Rust Actix-Web gateway
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs                       # HTTP server, handlers, rate-limit TODO
│       ├── cache.rs                      # DashMap RiskCache (teammate TODO)
│       └── models.rs                     # TxRequest / TxResponse / Verdict structs
│
├── services/
│   ├── local_engine/
│   │   ├── train_ensemble.py             ← Layer 1: SMOTE + RF + XGB + LightGBM + SHAP
│   │   └── prompt_guard.py              ← Layer 0: prompt injection classifier
│   ├── graph/
│   │   └── graph_agent.py               ← Layer 3: NetworkX mule-ring detection
│   ├── agents/
│   │   └── agent03_accessible_alert.py  ← Layer 4: personalised multilingual alert
│   └── demo/
│       └── app.py                       ← Layer 5: Streamlit dashboard
│
├── scripts/
│   └── v2_battleground.py               ← Adversarial test harness (3 arenas)
│
├── data/
│   ├── models/                          ← .pkl artifacts (gitignored)
│   ├── audio_alerts/                    ← .mp3 outputs (gitignored)
│   ├── explainability/                  ← SHAP PNGs (gitignored)
│   └── datasets/
│       ├── PS_20174392719_…_log.csv     # PaySim (6.36 M rows)
│       ├── Untitled spreadsheet - upi_transactions.csv  # Paper dataset (647 rows)
│       ├── train-…parquet               # JailbreakBench (PromptGuard training)
│       ├── prompt_injections.json       # extra injection samples
│       └── ENHANCED+DETECTION…pdf       # Sadaf & Manivannan reference paper
│
├── requirements.txt
├── README.md
└── DEVLOG.md                            ← full session-by-session development log
```

---

## Key Design Decisions

| Decision | Rationale |
|---|---|
| VPA hashed at gateway entry | Raw PII never stored anywhere downstream |
| SMOTE on train split only | Test set must reflect real class distribution for valid metrics |
| Threshold from PR curve (F2) | Maximises recall — missing fraud is worse than a false alarm |
| deep-translator not Bhashini | Free, no API key, 69+ languages, graceful fallback — Bhashini requires paid access |
| gTTS primary + edge-tts fallback | Both free, no key needed; gTTS native Indian language support |
| Graph agent runs async | DashMap hot path < 5 ms; graph analytics can take seconds — must not block payment |
| PromptGuard inline | Merchant names / device IDs are attacker-controlled — must check before LLM narration |
| Language list dynamic | `_gtts_langs()` queries gTTS at startup via `lru_cache(1)` — never stale, never hardcoded |

---

## Datasets

| Dataset | Rows | Purpose |
|---|---|---|
| PaySim (`PS_20174392719…_log.csv`) | 6,362,620 | Real financial crime simulation; balance-error features |
| Paper UPI CSV (`upi_transactions.csv`) | 647 | Sadaf & Manivannan 2024 features; cross-validation with paper |
| JailbreakBench parquet | 546 | PromptGuard training (injection vs benign) |
| Synthetic (auto-generated) | 50,000 | Fallback when no CSV provided |

---

## Teammate TODO (Rust Cache)

The Python + Streamlit + Graph layers are fully implemented. The Rust gateway compiles and returns HTTP 200 for all requests but always scores 0.0 (ALLOW) because the cache is stubbed. To complete Layer 2:

1. **`cache.rs`** — implement `RiskCache::get()` (expire check + DashMap lookup) and `RiskCache::upsert()` (insert/replace + log)
2. **`main.rs` `update_cache` handler** — verify HMAC-SHA256 on `x-varaksha-sig`, then call `cache.upsert()`
3. **`main.rs` rate limiter** — add per-IP request counter; return HTTP 429 after 100 req/min for `/v1/tx`

See the `TODO` comments in each file — every step is documented with the exact function signatures and latency targets.
