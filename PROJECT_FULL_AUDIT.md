# Varaksha V2 Full Technical Audit

## 1) Executive summary

Varaksha V2 is a fraud-intelligence platform for UPI-like transaction flows. It combines:

- synthetic but behaviorally realistic data generation,
- leakage-aware temporal feature engineering,
- supervised + anomaly model training with ONNX export,
- graph-topology risk enrichment,
- low-latency runtime scoring and caching,
- multilingual alerting,
- a Next.js demo/operations frontend.

The project is built as a multi-runtime system:

- Python for data + ML + graph + alert services,
- Rust (Actix + ONNX Runtime) for hardened low-latency gateway/cache,
- Next.js for user-facing and operator-facing visualization.

Core risk fusion implemented in runtime:

- `fused_risk = (lgbm_weight * lgbm_score) + (anomaly_weight * anomaly_score) + (topology_weight * graph_signal)`
- Current manifest weights: `0.6 / 0.3 / 0.1`.

Current model contract (from `models/feature_manifest.json`):

- `n_features = 24`
- `decision_threshold = 0.46`
- verdict bands:
  - `ALLOW: [0.00, 0.46)`
  - `FLAG:  [0.46, 0.75)`
  - `BLOCK: [0.75, 1.00]`

---

## 2) What this project is (plain-language)

This repository is a full-stack fraud-defense demonstration and engineering baseline. It is not just a model notebook. It includes:

1. A data factory that simulates UPI transaction behavior and injects known fraud physics (mule fan-in, takeover velocity).
2. A strict temporal compiler that builds production-like features without label leakage.
3. A training pipeline that exports deployable ONNX models and explicit serving metadata.
4. A Rust gateway that performs authenticated scoring, caching, policy reload, erasure, and metrics.
5. Supporting graph and alert agents that enrich risk and produce multilingual accessibility outputs.
6. A polished frontend that demonstrates architecture, timeline, live feed, and incident evidence generation.

In short: this is an end-to-end fraud platform prototype, not an isolated ML experiment.

---

## 3) Repository architecture and ownership

Top-level structure:

- `datasets/`
  - Data assets and scripts for generation/compilation workflows.
- `varaksha-v2-core/`
  - Main Python pipeline scripts (`00` through `03`).
- `models/`
  - Model artifacts and serving contracts (`*.onnx`, manifests, metrics).
- `risk-cache/`
  - Rust gateway + cache runtime.
- `services/`
  - Auxiliary services (`graph/`, `agents/`).
- `frontend/`
  - Next.js application (overview, flow, timeline, live, tier3).
- `outputs/`
  - Generated reports/metrics/models dumps.
- `scripts/`
  - Utility and diagnostics scripts.

Primary orchestration path:

1. `00_generate_indian_physics.py`
2. `01_compile_physics.py`
3. `02_forge_the_brain.py`
4. runtime via Python stream gateway and/or Rust gateway
5. frontend visualization and legal/evidence output

---

## 4) Data system and feature logic

### 4.1 Raw generator (`varaksha-v2-core/00_generate_indian_physics.py`)

Purpose:

- produce chronologically consistent UPI-like data with persistent entities,
- include deterministic attack mechanics for model bootstrapping.

Declared guarantees:

- fixed 20-column output schema,
- persistent customers/merchants over 30 days,
- behavior-derived fields from prior state only,
- explicit fraud injections:
  - mule fan-in: `15` distinct senders to one receiver in `<=10 min`,
  - velocity takeover: `20` transactions from one customer in `<=5 min`.

Behavioral state tracked per customer:

- transaction count,
- last transaction time,
- amount running moments (for deviation/z-like dynamics).

### 4.2 Compiler (`varaksha-v2-core/01_compile_physics.py`)

Purpose:

- convert raw stream into leakage-safe train/holdout parquet with canonical feature contract.

Key invariants:

- hash PII columns to `sender_hash` and `receiver_hash`,
- strict chronological sort,
- strict temporal split (80/20),
- left-closed rolling windows (current row does not observe itself),
- canonical 24-feature order.

Canonical feature contract (`N_FEATURES = 24`):

1. amount
2. hour_of_day
3. day_of_week
4. is_weekend
5. device_txn_count_10m
6. device_txn_count_1h
7. device_txn_count_6h
8. device_txn_count_24h
9. device_amount_zscore_24h
10. receiver_unique_senders_10m
11. receiver_txn_count_1h
12. receiver_txn_count_24h
13. receiver_unique_senders_1h
14. amount_zscore_global
15. is_new_device
16. is_new_receiver
17. enc_transaction_type
18. enc_device_type
19. enc_network_type
20. enc_sender_bank
21. enc_receiver_bank
22. is_high_risk_corridor
23. txn_frequency
24. days_since_last_txn

Engineering logic categories:

- velocity windows (10m/1h/6h/24h),
- receiver concentration windows,
- local and global distribution anomaly,
- categorical ordinal maps,
- corridor risk flags.

Outputs:

- `datasets/generated/train_clean.parquet`
- `datasets/generated/holdout_clean.parquet`
- `models/global_stats.json`

---

## 5) Model training, selection, and export

### 5.1 Trainer (`varaksha-v2-core/02_forge_the_brain.py`)

Models trained:

- LightGBM binary classifier (primary supervised model),
- IsolationForest (unsupervised anomaly model).

Exported serving artifacts:

- `models/lgbm_sweeper.onnx`
- `models/isolation_forest.onnx`
- `models/feature_manifest.json`
- `models/training_stats.json`

Selection strategy:

- threshold-aware candidate comparison using decision threshold hyperparameter,
- objective emphasis on `F0.5` (precision-weighted), secondary PR-AUC,
- dynamic class balancing via:
  - `scale_pos_weight = negatives / positives`

Metric computation:

- precision/recall/TP/FP/TN/FN at threshold,
- ROC-AUC and PR-AUC,
- quantiles of holdout score distribution.

`F_beta` implementation for `beta=0.5`:

- `beta^2 = 0.25`
- `F0.5 = (1 + beta^2) * (P * R) / (beta^2 * P + R)`

ONNX details:

- LightGBM exported with `zipmap=False` to produce tensor outputs compatible with Rust extraction path.

### 5.2 Current measured stats (`models/training_stats.json`)

Selection validation snapshot:

- threshold: `0.46`
- precision: `0.9751`
- recall: `0.9714`
- `F0.5`: `0.9743`
- ROC-AUC: `0.9961`
- PR-AUC: `0.9800`

Holdout snapshot:

- ROC-AUC: `0.9970`
- PR-AUC: `0.9813`
- precision at threshold: `0.9856`
- recall at threshold: `0.9741`
- `F0.5` at threshold: `0.9833`

### 5.3 Current serving contract (`models/feature_manifest.json`)

Contract keys of interest:

- `n_features: 24`
- `lgbm_onnx: lgbm_sweeper.onnx`
- `if_onnx: isolation_forest.onnx`
- `decision_threshold: 0.46`
- `score_fusion`:
  - `lgbm_weight: 0.6`
  - `anomaly_weight: 0.3`
  - `topology_weight: 0.1`
- `verdicts`:
  - `ALLOW: [0.0, 0.46]`
  - `FLAG: [0.46, 0.75]`
  - `BLOCK: [0.75, 1.0]`

---

## 6) Runtime scoring architectures

This repository currently contains two serving styles:

1. Python live stream gateway (`varaksha-v2-core/03_live_streaming_gateway.py`),
2. Rust production-grade gateway/cache (`risk-cache/src/main.rs`).

### 6.1 Python live stream gateway (`03_live_streaming_gateway.py`)

Role:

- row-by-row stream simulation and explainable console path,
- mirrors compile feature logic at inference-time using in-memory state,
- applies 3-layer gauntlet:
  - L1 topology signal,
  - L2 IsolationForest anomaly,
  - L3 LightGBM probability.

L1 defaults:

- `FAN_IN_THRESHOLD_10M = 10`
- `VELOCITY_THRESHOLD_10M = 12`

Fusion logic in this script:

- base:
  - `risk = 0.6*lgbm + 0.3*anomaly + 0.1*topology_flag`
- plus escalation rules when topology confirms L3 signal.

Verdict mapping:

- from manifest verdict bands (`ALLOW/FLAG/BLOCK`).

### 6.2 Rust gateway/cache (`risk-cache/src/main.rs`)

Role:

- hardened API service for scoring and risk cache lifecycle,
- authenticated write paths and protected inference paths,
- dynamic policy reload, metrics, and erasure.

Important runtime state:

- ONNX model sessions (`ModelSessions`),
- reloadable policy config (`Arc<RwLock<PolicyConfig>>`),
- feature cache (`DashMap<String, Vec<f32>>`),
- graph delta cache (`RiskCache`),
- rate limiter (`RateLimiter`),
- audit log path (`JSONL`).

Input hygiene and privacy:

- immediate SHA-256 anonymization of `transaction_id` and `raw_device_id`,
- no raw PII persisted in cache keys.

Feature shaping:

- vector resized to manifest `n_features`,
- amount injected at index `0`.

Fusion in Rust (actual execution path):

- `fused_score = (lgbm_weight*lgbm_score) + (anomaly_weight*anomaly_score) + (topology_weight*graph_delta)`
- clamp to `[0,1]`.

Verdict in Rust:

- `ALLOW` if `score < allow_threshold`
- `FLAG` if between allow and block thresholds
- `BLOCK` if `score >= block_threshold`

---

## 7) Rust endpoint contract and auth model

### 7.1 Endpoint catalog

- `GET /health`
  - auth: none
  - output: status + tier

- `GET /metrics`
  - auth: API key (`X-Varaksha-Api-Key`)
  - output: uptime, thresholds, fusion weights, cache stats

- `POST /inference`
  - auth: API key
  - output: hashed txn id, fused risk, component scores, verdict, timing, tier

- `POST /policy/reload`
  - auth: HMAC signature (`X-Varaksha-Signature`, secret `VARAKSHA_UPDATE_SECRET`)
  - behavior: reload `feature_manifest.json` and optional `bank_risk_policy.json`

- `DELETE /erasure/{vpa_hash}`
  - auth: API key
  - behavior: removes entries from feature + graph-delta caches

- `POST /update_cache` (Cloud/OnPrem only)
  - auth: HMAC (`VARAKSHA_UPDATE_SECRET`)
  - behavior: inserts feature vector after length validation

- `POST /graph_update` (Cloud/OnPrem only)
  - auth: HMAC (`VARAKSHA_GRAPH_SECRET`)
  - behavior: upserts graph delta and logs audit event

### 7.2 Tier behavior (`PolicyConfig`)

Tiers:

- `cloud`, `on_prem`, `edge`

Defaults by tier:

- cache TTL seconds:
  - cloud `180`
  - on_prem `300`
  - edge `60`
- rate max per window:
  - cloud `100`
  - on_prem `500`
  - edge `20`

Edge restrictions:

- `update_cache` and `graph_update` disabled,
- IsolationForest may be omitted in edge tier (`if_onnx_path=None`).

### 7.3 Security primitives in Rust

- constant-time API key/HMAC comparison (`XOR` fold),
- per-key sliding window rate limiting with `Retry-After`,
- append-only JSONL audit logging (`graph_update`, `policy_reload`, `erasure`),
- no plaintext PII in logs/caches.

---

## 8) Graph enrichment service

Component:

- `services/graph/graph_agent.py`

Core graph model:

- `networkx.MultiDiGraph` on hashed node identities.

Detected typologies:

- fan-out,
- fan-in,
- short cycle,
- scatter.

Scoring model:

- baseline deltas:
  - fan_out `0.35`
  - fan_in `0.30`
  - cycle `0.50`
  - scatter `0.20`
- severity scaling applied to baseline contributions,
- per-node total clamped to `1.0`.

Gateway integration:

- emits payload with `_timestamp` for Rust contract,
- signs request with HMAC SHA-256 (`X-Varaksha-Signature`).

Operational modes:

- parquet-driven ingestion mode,
- deterministic demo seed mode for judge/demo reproducibility.

---

## 9) Alert agent (accessibility and multilingual)

Component:

- `services/agents/agent03_accessible_alert.py`

Purpose:

- generate deterministic, auditable multilingual fraud alerts,
- synthesize MP3 alerts via edge TTS voices.

Design:

- deterministic template-based narration (not LLM-generated),
- translation via `googletrans` fallback,
- speech synthesis via `edge-tts`,
- supports pre-generation of static MP3 bundles.

Languages currently mapped:

- en, hi, ta, te, bn, mr, gu, kn.

---

## 10) Frontend architecture and logic

Framework:

- Next.js App Router, React 19, Framer Motion, Tailwind CSS.

Build mode:

- static export enabled in `frontend/next.config.ts`:
  - `output: "export"`
  - `trailingSlash: true`
  - `images.unoptimized: true`

### 10.1 Route surface

- `/` overview and mission narrative
- `/flow` architecture walk-through
- `/timeline` milestone narrative
- `/live` sandbox + feed + cache + security arena + legal report
- `/tier3/` edge/on-device simulation page

### 10.2 Live page modules

In `frontend/app/live/page.tsx`:

- Module A: manual sandbox submission with staged UX and risk rendering,
- Module B: event stream transaction feed, fallback generator when stream unavailable,
- incident bus:
  - emits `window` custom event `varaksha:incident` on `FLAG`/`BLOCK` for cross-widget sync.

### 10.3 Legal evidence module

In `frontend/app/live/LegalReport.tsx`:

- listens to `varaksha:incident`,
- dynamically builds report text by verdict and incident details,
- downloadable evidence file naming:
  - `varaksha-evidence-{transactionId}-{verdict}.txt`,
- includes score decomposition fields:
  - LGBM, IF, graph delta.

### 10.4 New simulation components

- `frontend/app/components/DashMapVisualizer.tsx`
  - high-frequency cache visualization simulation (`~5000 TPS`),
  - canvas-based rendering to avoid React re-render bottlenecks,
  - HIT/MISS/EVICT counters and memory ticker log simulation.

- `frontend/app/components/Tier3EdgeSim.tsx`
  - mobile-like local pre-network scoring simulation,
  - heuristic local block logic based on amount, receiver pattern, hour, clipboard hint,
  - architecture panel for on-device quantized ONNX packaging narrative.

### 10.5 Frontend API base resolution

`frontend/app/lib/api-config.ts` resolves backend base URL by priority:

1. `NEXT_PUBLIC_API_URL` if set,
2. runtime hostname detection,
3. localhost mapping fallback,
4. final Railway fallback URL.

---

## 11) Dependency audit by stack

### 11.1 Python (`requirements.txt`)

Data/processing:

- polars, pandas, numpy

ML:

- lightgbm, scikit-learn, imbalanced-learn

Model export/runtime:

- onnxmltools, skl2onnx, onnx, onnxruntime

Graph:

- networkx

Alerting:

- googletrans, edge-tts

Utilities/dev:

- tqdm, click, pytest, black, flake8, mypy

### 11.2 Rust (`risk-cache/Cargo.toml`)

- actix-web (HTTP service)
- dashmap (concurrent in-memory structures)
- ort + ndarray (ONNX Runtime inference)
- serde/serde_json (payloads)
- sha2/hex/hmac (hashing and signatures)
- tokio (async runtime)
- log/env_logger (structured logging)

### 11.3 Frontend (`frontend/package.json`)

Runtime:

- next, react, react-dom
- framer-motion
- lucide-react

Dev/build:

- typescript
- tailwindcss, postcss, autoprefixer
- react/node typings

Engine requirement:

- `node >= 18`

---

## 12) Privacy, compliance, and governance controls present

Implemented controls:

- immediate one-way hashing at ingress (Rust path),
- API key + HMAC protected endpoints,
- constant-time credential/signature comparison,
- rate limiting per hashed key,
- erasure endpoint for hash-based deletion,
- append-only structured audit trails,
- frontend DPDP-oriented disclosure text in layout footer.

Regulatory references are embedded in UI/report narratives, including:

- DPDP Act usage context,
- IT Act and BNS references,
- NPCI/RBI operational framing.

Note: legal references in UI/report text are informational/demo content and should be validated by legal/compliance for production use.

---

## 13) End-to-end control/data flow

### 13.1 Offline build flow

1. Generate synthetic transactions (`00`)
2. Compile leakage-safe features (`01`)
3. Train + export ONNX + manifest (`02`)
4. Persist contract artifacts in `models/`

### 13.2 Online scoring flow (Rust)

1. Receive inference request
2. Validate API key
3. Hash identifiers
4. Enforce per-key rate limit
5. Build normalized feature vector
6. Read graph delta cache
7. Run ONNX models (LGBM + optional IF)
8. Fuse weighted risk
9. Map verdict bands
10. Return JSON response

### 13.3 Enrichment flow (Graph)

1. Build/update graph on hashed nodes
2. Detect topology events
3. Derive per-node delta and reason
4. HMAC-sign and push `/graph_update`
5. Rust cache stores delta for future inference fusion

### 13.4 Alert/evidence flow (Frontend)

1. Live/sandbox emits `varaksha:incident` for risky outcomes
2. Legal report subscribes and updates state
3. User can download verdict-specific evidence text artifact

---

## 14) Known integration gaps and operational caveats

1. API contract split between frontend and Rust service

- frontend live route calls `/v1/tx` and `/v1/stream`.
- Rust service currently exposes `/inference`, `/metrics`, `/graph_update`, etc.
- This implies either:
  - an adapter/sidecar service exists externally, or
  - the frontend is currently wired to a different backend contract.

2. Static export behavior

- frontend is configured with `output: export`.
- `next start` is not the correct production-preview command for this mode.
- static output should be served from `out/` (as already validated locally).

3. Multiple runtime paths

- both Python live gateway and Rust gateway coexist.
- clear environment-based routing and a single source-of-truth API contract are recommended for production hardening.

4. Manifest size and categorical maps

- `feature_manifest.json` includes very large ordinal maps (including some numeric-like fields represented as categorical maps).
- this is not inherently wrong but should be monitored for artifact bloat and maintainability.

---

## 15) Recommended production hardening checklist

1. Finalize one canonical online API contract (or add explicit adapter layer docs).
2. Add OpenAPI/JSON schema for all externally consumed endpoints.
3. Add contract tests between frontend and backend routes.
4. Add CI checks for manifest consistency (`n_features`, feature order, model outputs).
5. Externalize legal/report templates for policy/compliance review workflows.
6. Add structured observability export (metrics sink + log aggregation).
7. Add versioned model registry metadata (artifact hash + manifest hash + training run ID).
8. Add chaos/latency tests for cache misses and graph update bursts.

---

## 16) Local runbook (practical)

### 16.1 Frontend

- `cd frontend`
- `npm install`
- `npm run dev`
- local dev: `http://localhost:3000`

For static export preview:

- `npm run build`
- serve `frontend/out` with a static server

### 16.2 Python core pipeline

- `python varaksha-v2-core/00_generate_indian_physics.py`
- `python varaksha-v2-core/01_compile_physics.py`
- `python varaksha-v2-core/02_forge_the_brain.py`
- optional stream demo:
  - `python varaksha-v2-core/03_live_streaming_gateway.py --csv datasets/demo/real_traffic.csv`

### 16.3 Rust gateway

- `cd risk-cache`
- set required env vars (`VARAKSHA_API_KEY`, model path envs/tier as needed)
- `cargo run`

---

## 17) Final assessment

Varaksha V2 is a high-quality, multi-layer fraud system prototype with strong strengths:

- realistic temporal/graph fraud framing,
- explicit serving contracts and ONNX portability,
- low-latency Rust runtime architecture,
- meaningful privacy/security primitives,
- compelling operator and judge/demo UX.

The main strategic task remaining is contract convergence:

- unify runtime API expectations across frontend, Python stream gateway, and Rust gateway,
- then lock with integration tests and deployment docs.

Once contract convergence is complete, this codebase is well-positioned for production pilot hardening.
