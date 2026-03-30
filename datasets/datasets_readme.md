# Datasets Directory Guide

This folder is the single source of truth for all dataset assets used by the active Varaksha V2 workflow.

## Structure

- `demo/`
	- Sample CSV streams used for demos and live simulation runs.
- `generated/`
	- Script-generated raw CSV plus compiled train/holdout parquet files.
- `scripts/`
	- Wrapper scripts that run the data generator and compiler.

## Purpose

Keep data responsibilities clear:

- demo traffic stays separate from training artifacts
- generated artifacts are reproducible from scripts
- no hidden or duplicated legacy dataset paths

## Main generated artifacts

- `generated/upi_raw.csv`
	- Physics-generated UPI-like transaction stream.
- `generated/train_clean.parquet`
	- Feature table used for model fitting.
- `generated/holdout_clean.parquet`
	- Feature table used for final evaluation.

## Split policy

The compiler uses strict chronological split logic:

- Train: first 80% by timestamp
- Holdout: final 20% by timestamp

This is intentionally leakage-resistant and matches real deployment conditions.

## Inspiration for feature/column design

- UPI fraud datasets (2024-era public references)
- PaySim-style mobile money fraud patterns

These references informed feature selection, while the actual data remains generated and reproducible via project scripts.
