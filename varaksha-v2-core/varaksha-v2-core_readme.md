# Varaksha V2 Core Scripts

This folder contains the active end-to-end ML pipeline scripts.

## Pipeline scripts

1. `00_generate_indian_physics.py`
   - Generates UPI-like transactional raw data.
2. `01_compile_physics.py`
   - Compiles features and performs chronological train/holdout split.
3. `02_forge_the_brain.py`
   - Trains models and exports ONNX/manifest artifacts.
4. `03_live_streaming_gateway.py`
   - Runs live scoring over demo CSV streams.

## Data and model paths

- Reads/writes generated data under `datasets/generated/`.
- Reads demo streams from `datasets/demo/`.
- Reads/writes model artifacts under `models/`.

## Typical usage

1. Generate data.
2. Compile features.
3. Train/export models.
4. Run live gateway simulation.

## Why this folder exists

This is the canonical active pipeline; legacy training paths were intentionally removed to reduce ambiguity.
