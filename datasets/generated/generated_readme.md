# Generated Dataset Folder

This folder stores generated and compiled data artifacts used by the active ML pipeline.

## Purpose

- Hold reproducible outputs from the data generator and compiler.
- Separate build artifacts from demo-only CSV streams.

## Files

- `upi_raw.csv`: generated raw transactional stream.
- `upi_raw_smoke.csv`: smaller generated sample for quick checks.
- `train_clean.parquet`: compiled training feature table.
- `holdout_clean.parquet`: compiled holdout feature table.

## How files are produced

1. `00_generate_indian_physics.py` writes raw CSV outputs.
2. `01_compile_physics.py` hashes IDs, engineers features, and writes temporal split parquets.

## Split policy

- Train: earliest 80% by timestamp
- Holdout: latest 20% by timestamp

This enforces chronological evaluation and reduces leakage risk.
