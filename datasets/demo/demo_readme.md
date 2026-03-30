# Demo Dataset Folder

This folder contains CSV inputs used for demonstration and live gateway simulation.

## Purpose

- Provide realistic replay traffic for product demos.
- Keep demo streams separate from training data.
- Enable deterministic local smoke tests.

## Files

- `real_traffic.csv`: mostly normal transactional behavior.
- `synthetic_attack.csv`: higher-risk stream with attack-like patterns.
- `_tmp_gateway_smoke.csv`: compact smoke-run file for quick validation.

## Usage

Example:

- `python varaksha-v2-core/03_live_streaming_gateway.py --csv datasets/demo/real_traffic.csv`
- `python varaksha-v2-core/03_live_streaming_gateway.py --csv datasets/demo/synthetic_attack.csv`

## Notes

These files are inference-time demo inputs, not training labels or production truth data.
