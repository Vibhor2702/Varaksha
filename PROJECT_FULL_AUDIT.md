# Varaksha V2 Full Technical Audit (Deep Dive)

Last updated: 2026-03-31

## 1) Executive summary

Varaksha V2 is an end-to-end fraud defense stack for UPI-like transactions. It ships a full data-to-runtime pipeline:

- synthetic data generation with repeatable fraud mechanics,
- leakage-safe feature compilation (24-feature contract),
- supervised + anomaly model training with ONNX export,
- graph topology risk enrichment,
- hardened Rust scoring gateway with cache and policy reload,
- Python open-banking bridge for streaming and feature injection,
- Next.js live demo and operator dashboards.

The system is built to demonstrate a realistic production flow, not just offline ML metrics.

## 2) System map (end-to-end flow)

1) Data generation and compilation (varaksha-v2-core)
   - Generates raw synthetic transactions and compiles leakage-safe features.
2) Model training (varaksha-v2-core)
   - Trains LightGBM + IsolationForest and exports ONNX and manifest.
3) Runtime scoring (risk-cache)
   - Rust gateway loads ONNX, fuses scores, applies thresholds, and logs audit events.
4) Streaming and integration (services/open_banking)
   - Python FastAPI bridge exposes /v1/tx and /v1/stream for the frontend.
5) Graph enrichment (services/graph)
   - NetworkX agent computes topology deltas and pushes to Rust /graph_update.
6) Frontend demo (frontend)
   - Live feed, graph monitor, model stack view, dataset inject, and reporting.

## 3) Repository map (current structure)

Top-level folders:

- datasets/
  - demo datasets and generated artifacts.
- varaksha-v2-core/
  - Python pipeline scripts for generation, compilation, training, live gateway.
- models/
  - ONNX artifacts, training stats, feature manifest.
- risk-cache/
  - Rust gateway and cache runtime (Actix + DashMap).
- services/
  - graph agent, open-banking bridge, alert agents.
- frontend/
  - Next.js UI (overview, flow, timeline, live, tier3).
- outputs/
  - metrics, reports, model outputs.
- scripts/
  - utility scripts and diagnostics.

## 4) Data system and demo datasets

### 4.1 Demo datasets (frontend served)

These datasets are published for the UI and batch injection:

- frontend/public/datasets/real_traffic.csv
  - 200 rows of realistic but normal traffic.
- frontend/public/datasets/synthetic_attack.csv
  - 138 rows with explicit ATK_* patterns (fan-in and velocity).

Schema (CSV columns):

1. transaction id
2. timestamp
3. transaction type
4. merchant_category
5. amount (INR)
6. transaction_status
7. sender_age_group
8. receiver_age_group
9. sender_state
10. sender_bank
11. receiver_bank
12. device_type
13. network_type
14. fraud_flag
15. hour_of_day
16. day_of_week
17. is_weekend
18. device_surrogate
19. corridor_surrogate

### 4.2 Generated training data

Generated and compiled outputs are in datasets/ and outputs/ and are produced by:

- varaksha-v2-core/00_generate_indian_physics.py
- varaksha-v2-core/01_compile_physics.py

## 5) Feature contract (models/feature_manifest.json)

The scoring contract uses 24 features. The exact ordered list:

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

Manifest also specifies:

- decision_threshold: 0.46
- score_fusion weights:
  - lgbm_weight: 0.6
  - anomaly_weight: 0.3
  - topology_weight: 0.1
- verdict bands:
  - ALLOW: [0.0, 0.46]
  - FLAG:  [0.46, 0.75]
  - BLOCK: [0.75, 1.0]

## 6) Model training and metrics (models/training_stats.json)

Selection threshold: 0.46

Internal validation (selection):

- precision: 0.975062
- recall: 0.971429
- F0.5: 0.974333
- ROC-AUC: 0.996148
- PR-AUC: 0.980005

Holdout performance:

- ROC-AUC: 0.997025
- PR-AUC: 0.981277
- precision at threshold: 0.985605
- recall at threshold: 0.974059
- F0.5 at threshold: 0.983274

Exported artifacts:

- models/lgbm_sweeper.onnx
- models/isolation_forest.onnx
- models/feature_manifest.json
- models/training_stats.json

## 7) Runtime scoring (risk-cache)

### 7.1 Rust gateway overview (risk-cache/src/main.rs)

The Rust gateway is the hardened scoring service. It performs:

- SHA-256 anonymization of raw transaction and device IDs,
- rate limiting per hashed device,
- cache lookup and feature vector normalization,
- graph delta fusion,
- ONNX inference with LightGBM + IsolationForest,
- weighted fusion and verdict mapping,
- JSONL audit logging for updates and graph signals.

### 7.2 Runtime policy (risk-cache/src/config.rs)

Config is loaded from feature_manifest.json and optionally overridden by:

- varaksha-v2-core/bank_risk_policy.json
- environment variables

Tier defaults:

- cache TTL:
  - cloud: 180s
  - on_prem: 300s
  - edge: 60s
- rate limit max requests:
  - cloud: 100
  - on_prem: 500
  - edge: 20

Thresholds:

- allow_threshold, flag_threshold, block_threshold
- defaults from feature_manifest verdict bands
- overridable by bank_risk_policy.json

### 7.3 Rust endpoints

- GET /health
- GET /metrics (API key)
- POST /inference (API key)
- POST /policy/reload (HMAC)
- DELETE /erasure/{vpa_hash} (API key)
- POST /update_cache (HMAC)
- POST /graph_update (HMAC)

## 8) Python bridge and streaming (services/open_banking/feed_bridge.py)

The FastAPI bridge exposes the frontend API surface:

- POST /v1/tx
  - accepts rich 24-feature payload from frontend
  - pushes /update_cache on Rust
  - calls /inference on Rust and returns verdict
- GET /v1/stream
  - SSE live transaction feed (synthetic + live)
- GET /v1/open-banking/stream
  - SSE Setu + Plaid feed
- GET /v1/open-banking/sources
- GET /health

The bridge is also responsible for fallback scoring when Rust is unreachable.

## 9) Graph enrichment (services/graph/graph_agent.py)

Graph agent uses a rolling MultiDiGraph and emits topology deltas to Rust:

Detection thresholds:

- FAN_OUT_MIN_RECEIVERS = 3
- FAN_IN_MIN_SENDERS = 5
- CYCLE_MAX_LENGTH = 5
- SCATTER_RATIO = 2.0

Risk deltas (severity scaled):

- fan_out: 0.35
- fan_in: 0.30
- cycle: 0.50
- scatter: 0.20

Max graph delta clamp: 1.0

## 10) Frontend architecture (frontend/)

Key routes:

- / (overview)
- /flow (architecture walkthrough)
- /timeline (project timeline)
- /live (live console and demos)
- /tier3 (embedded tier simulation)

Live page modules (frontend/app/live/page.tsx):

- Module A: Intelligence Sandbox
- Module B: Live Transaction Feed
- Module C: Rust cache visualizer
- Module F: ML Model Stack
- Module G: Enterprise Graph Network Monitor
- Module H: Open Banking Feed
- Legal report and security arena panels
- Tier scenario architecture (tree view)
- Demo dataset preview and batch inject

## 11) Demo dataset injection (frontend/app/live/page.tsx)

Batch inject flow:

- CSV rows loaded from frontend/public/datasets
- Each row mapped to a /v1/tx payload
- Result appended into live graph
- Batch stats aggregate ALLOW/FLAG/BLOCK counts

The synthetic_attack dataset flags only ATK_* rows, producing a balanced mix.

## 12) Security, privacy, and auditability

- SHA-256 anonymization of raw identifiers at the Rust gateway
- HMAC on write paths (/update_cache, /graph_update)
- API key on /inference and /metrics
- JSONL audit logging for graph updates and policy reloads

## 13) Operational checks (current)

Live connectivity verified:

- Rust gateway /health returns status ok
- /v1/tx returns live verdict + risk score + trace ID

## 14) Known constraints and next steps

- Open-banking streams are demo-grade without real Setu/Plaid credentials
- Edge tier omits IsolationForest by design
- Policy overrides in bank_risk_policy.json should be documented per deployment

Recommended next steps:

1) Version and document bank_risk_policy.json per customer
2) Add signed dataset provenance metadata to demo CSVs
3) Add regression tests for /v1/tx payload mapping

