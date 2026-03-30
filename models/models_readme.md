# Models Folder

This folder is the central home for trained model artifacts and model metadata.

## Contents

- `lgbm_sweeper.onnx`: primary supervised fraud classifier.
- `isolation_forest.onnx`: anomaly detector.
- `feature_manifest.json`: canonical feature contract, thresholds, and fusion settings.
- `global_stats.json`: compiler-side stats and encoded metadata.
- `training_stats.json`: training/evaluation metrics.
- `ML_LOGIC.md`: detailed model rationale and operational logic.
- `ML_ARCHITECTURE.md`: architecture diagram and stage-level flow.

## Purpose

Keep all model-serving dependencies in one place so inference scripts and services can resolve assets consistently.
