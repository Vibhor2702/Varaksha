# Varaksha ML Logic (In-Depth)

## 1. System Architecture

Varaksha V2 runs as a sequential build plus live inference architecture.

Offline build path:

1. `varaksha-v2-core/00_generate_indian_physics.py`
2. `varaksha-v2-core/01_compile_physics.py`
3. `varaksha-v2-core/02_forge_the_brain.py`

Live inference/demo path:

1. `varaksha-v2-core/03_live_streaming_gateway.py`
2. ONNX artifacts from `models/`
3. CSV stream from `datasets/demo/`

## 2. Data and Temporal Logic

### 2.1 Generated raw data

`00_generate_indian_physics.py` simulates UPI-like behavior with persistent entities:

- Persistent customers, devices, merchants
- Chronological activity across days
- Physics-based fraud injections, not random labels

Implemented attack physics:

- Fan-in mule pattern: multiple senders converging to one receiver in short windows
- Velocity takeover pattern: high burst frequency from one identity in short windows

### 2.2 Compile and split

`01_compile_physics.py` is leakage-aware by design:

- Strict timestamp sort
- Temporal split: 80% train, 20% holdout
- Feature windows are left-closed (current row excluded from its own history)
- Hashing applied to sender and receiver IDs before feature logic

This gives realistic deployment parity: model sees only past behavior while scoring future events.

## 3. Feature Engineering Strategy

Feature contract is 24 columns with mixed signals.

### 3.1 Behavioral velocity and recurrence

Examples:

- `device_txn_count_10m`, `device_txn_count_1h`, `device_txn_count_6h`, `device_txn_count_24h`
- `receiver_txn_count_1h`, `receiver_txn_count_24h`
- `receiver_unique_senders_10m`, `receiver_unique_senders_1h`

Why:

- UPI fraud often appears as bursty or coordinated graph activity in short windows.
- These features capture transfer velocity and concentration asymmetry.

### 3.2 Statistical anomaly features

Examples:

- `device_amount_zscore_24h`
- `amount_zscore_global`
- `is_new_device`, `is_new_receiver`

Math:

- Z-score form: `z = (x - mu) / sigma`
- Local z-score uses device-local rolling history.
- Global z-score uses corpus-level amount statistics.

Why:

- Fraud often manifests as amount behavior outside user-specific and population-specific norms.

### 3.3 Categorical/context features

Ordinal-encoded context:

- transaction type
- device type
- network type
- sender bank
- receiver bank

Additional corridor flag:

- `is_high_risk_corridor` marks historically higher-risk sender-bank to receiver-bank flows (fit on train only).

Why:

- Bank-to-bank corridors and channel context are strong priors in payment risk systems.

## 4. Models Used and Why

## 4.1 LightGBM binary classifier (primary supervised model)

Artifact:

- `models/lgbm_sweeper.onnx`

Role:

- Main fraud probability estimator.

Why LightGBM:

- Strong tabular performance for mixed numeric/categorical-derived features
- Handles non-linear interactions and threshold effects well
- Fast inference when exported to ONNX

Training logic highlights:

- Class imbalance handled by dynamic `scale_pos_weight = negatives / positives`
- Candidate hyperparameter sets are tried
- Best candidate selected by threshold-aware `F0.5` (precision-emphasized)

F-beta used:

- `F_beta = (1 + beta^2) * (P * R) / (beta^2 * P + R)`
- Here beta = 0.5, so precision is weighted more than recall.

Why precision emphasis:

- In UPI risk controls, excessive false positives create customer friction and payment drop-off.

## 4.2 IsolationForest (unsupervised anomaly model)

Artifact:

- `models/isolation_forest.onnx`

Role:

- Detects unusual behavioral geometry even when supervised labels are sparse or delayed.

Why IsolationForest:

- Useful for novel fraud patterns not fully represented in labels
- Computationally efficient for tabular anomaly scoring

## 4.3 Topology signal in live gateway

`03_live_streaming_gateway.py` computes graph-informed high-confidence signals:

- fan-in pressure
- short-window velocity pressure

This is a rule-based topology layer that complements ML probabilities.

## 5. Score Fusion and Weights

Fusion weights are stored in the model manifest (`models/feature_manifest.json`):

- `lgbm_weight = 0.6`
- `anomaly_weight = 0.3`
- `topology_weight = 0.1`

Operational intuition:

- 0.6 on LightGBM: supervised model is the strongest calibrated signal.
- 0.3 on anomaly: meaningful secondary protection against unknown patterns.
- 0.1 on topology: conservative graph boost to avoid over-triggering from transient graph noise.

This ordering balances stability (supervised model) with adaptability (anomaly + topology).

## 6. Decision Policy

Decision threshold is a first-class control in training and evaluation.

Typical policy shape in manifest:

- ALLOW: low-risk region below decision threshold
- FLAG: middle band for review/challenge
- BLOCK: upper risk band

This is bank-aligned operationally because it supports graduated friction:

- low-friction pass for likely legitimate
- selective friction for uncertain traffic
- hard stop for high-confidence fraud

## 7. UPI-Centric Risk Logic

UPI behavior is strongly graph and time dependent. Design choices target common UPI fraud mechanics:

- Account takeover bursts: caught by 10-minute and 1-hour velocity windows
- Mule collection corridors: caught by unique-sender concentration and fan-in logic
- New endpoint abuse: captured by cold-start flags and corridor priors
- Amount shock attacks: captured via local/global z-scores

This combination intentionally mixes:

- behavioral history
- distributional anomaly
- graph structure
- transactional context

## 8. Why this architecture is practical

- Reproducible: script-driven generation and compile pipeline
- Deployable: ONNX artifacts for runtime portability
- Explainable: feature-level semantics and threshold policy exposed in manifest/stats
- Safe against leakage: chronological split and left-closed windows

## 9. Artifacts in this folder

- `feature_manifest.json`: feature contract, weights, thresholds, ONNX names
- `global_stats.json`: global stats and encoding metadata from compile stage
- `training_stats.json`: holdout metrics and threshold diagnostics from training
- `lgbm_sweeper.onnx`: primary supervised model
- `isolation_forest.onnx`: anomaly model
