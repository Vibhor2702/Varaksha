# Dataset Script Wrappers

This folder contains helper entrypoints for building data artifacts without navigating into core script directories.

## Files

- `generate_dataset.py`
  - Wrapper for `varaksha-v2-core/00_generate_indian_physics.py`.
  - Produces raw generated CSV artifacts in `datasets/generated/`.
- `compile_dataset.py`
  - Wrapper for `varaksha-v2-core/01_compile_physics.py`.
  - Produces compiled train/holdout parquet artifacts and refreshes model-side stats.

## Standard workflow

1. `python datasets/scripts/generate_dataset.py`
2. `python datasets/scripts/compile_dataset.py`

## Notes

- These wrappers pass through additional CLI arguments to the underlying scripts.
- Run them from project root for predictable relative-path behavior.
