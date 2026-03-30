# Outputs

This folder is reserved for run-time outputs and export artifacts produced by experiments or training workflows.

## Subfolders

- `metrics/`: numeric results and experiment metrics.
- `models/`: optional exported model files from non-primary runs.
- `reports/`: generated run reports.

## Purpose

Separate disposable/generated run outputs from the canonical model assets in `models/`.

## Usage guidance

- Use this folder for temporary or experiment outputs.
- Keep serving-critical artifacts in top-level `models/`.
