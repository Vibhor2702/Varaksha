# Varaksha ML Architecture Diagram

This diagram reflects the active V2 flow and uses Mermaid syntax for GitHub markdown rendering.

```mermaid
flowchart LR
    A[Data Generator\n00_generate_indian_physics.py]:::gen --> B[Raw Stream\ndatasets/generated/upi_raw.csv]:::data
    B --> C[Feature Compiler\n01_compile_physics.py]:::compile
    C --> D[Train Parquet\ndatasets/generated/train_clean.parquet]:::data
    C --> E[Holdout Parquet\ndatasets/generated/holdout_clean.parquet]:::data
    C --> F[Global Stats\nmodels/global_stats.json]:::artifact

    D --> G[Model Trainer\n02_forge_the_brain.py]:::train
    E --> G
    F --> G

    G --> H[LightGBM ONNX\nmodels/lgbm_sweeper.onnx]:::model
    G --> I[IsolationForest ONNX\nmodels/isolation_forest.onnx]:::model
    G --> J[Feature Manifest\nmodels/feature_manifest.json]:::artifact
    G --> K[Training Stats\nmodels/training_stats.json]:::artifact

    L[Demo Streams\ndatasets/demo/*.csv]:::demo --> M[Live Gateway\n03_live_streaming_gateway.py]:::serve
    H --> M
    I --> M
    J --> M

    M --> N[Verdict\nALLOW / FLAG / BLOCK]:::out

    classDef gen fill:#e3f2fd,stroke:#1565c0,color:#0d47a1,stroke-width:2px;
    classDef compile fill:#ede7f6,stroke:#5e35b1,color:#311b92,stroke-width:2px;
    classDef train fill:#fff3e0,stroke:#ef6c00,color:#e65100,stroke-width:2px;
    classDef serve fill:#e8f5e9,stroke:#2e7d32,color:#1b5e20,stroke-width:2px;
    classDef data fill:#f3e5f5,stroke:#7b1fa2,color:#4a148c;
    classDef model fill:#fbe9e7,stroke:#d84315,color:#bf360c;
    classDef artifact fill:#f1f8e9,stroke:#558b2f,color:#33691e;
    classDef demo fill:#e0f7fa,stroke:#00838f,color:#004d40;
    classDef out fill:#fff8e1,stroke:#f9a825,color:#f57f17,stroke-width:2px;
```

## Reading the diagram

- Left side: data generation and compilation.
- Center: training and artifact export.
- Right side: live inference and final verdict output.

## Key contract

The `feature_manifest.json` file acts as the serving contract between offline training and online inference.
