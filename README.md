# Varaksha V2 Fraud Intelligence Workspace

This repository is organized for fast onboarding and clear ownership of data, models, services, and UI.

## What this project does

Varaksha V2 builds and serves a fraud-risk pipeline that:

- generates UPI-like transaction data,
- compiles leakage-aware temporal features,
- trains supervised and anomaly models,
- serves live risk verdicts as `ALLOW / FLAG / BLOCK`.

## Top-level directory map

- `datasets/`
  - Source-of-truth dataset root.
  - Contains `demo/`, `generated/`, and `scripts/` with their own README files.
- `varaksha-v2-core/`
  - Active pipeline scripts (`00` to `03`).
- `models/`
  - Central model artifacts and ML documentation.
- `risk-cache/`
  - Rust serving/cache service.
- `services/`
  - Auxiliary graph and agent services.
- `frontend/`
  - Next.js UI for live and narrative views.
- `outputs/`
  - Generated run outputs and report dumps.
- `scripts/`
  - Utility diagnostics.

## End-to-end flow

```mermaid
flowchart LR
    A[Generate Data\n00_generate_indian_physics.py] --> B[datasets/generated/upi_raw.csv]
    B --> C[Compile Features\n01_compile_physics.py]
    C --> D[datasets/generated/train_clean.parquet]
    C --> E[datasets/generated/holdout_clean.parquet]
    D --> F[Train Models\n02_forge_the_brain.py]
    E --> F
    F --> G[models/lgbm_sweeper.onnx]
    F --> H[models/isolation_forest.onnx]
    F --> I[models/feature_manifest.json]
    J[datasets/demo/*.csv] --> K[Live Gateway\n03_live_streaming_gateway.py]
    G --> K
    H --> K
    I --> K
    K --> L[ALLOW / FLAG / BLOCK]

    classDef a fill:#e3f2fd,stroke:#1565c0,color:#0d47a1;
    classDef b fill:#e8f5e9,stroke:#2e7d32,color:#1b5e20;
    classDef c fill:#fff3e0,stroke:#ef6c00,color:#e65100;
    classDef d fill:#f3e5f5,stroke:#7b1fa2,color:#4a148c;
    classDef e fill:#fff8e1,stroke:#f9a825,color:#f57f17;

    class A,C,F,K a;
    class B,D,E,G,H,I,J b;
    class L e;
```

For a more detailed diagram and architecture notes, see:

- `models/ML_ARCHITECTURE.md`
- `models/ML_LOGIC.md`

## Quick start

1. Build data:
   - `python datasets/scripts/generate_dataset.py`
   - `python datasets/scripts/compile_dataset.py`
2. Train models:
   - `python varaksha-v2-core/02_forge_the_brain.py`
3. Run live simulation:
   - `python varaksha-v2-core/03_live_streaming_gateway.py --csv datasets/demo/real_traffic.csv`

## Notes

- Old `docs/` content was intentionally removed to reduce stale documentation drift.
- Folder-level README files now act as the primary exploration guide.
