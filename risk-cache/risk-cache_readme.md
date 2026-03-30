# Risk Cache Service

This folder contains the Rust service used for low-latency risk serving and cache operations.

## Purpose

- Host HTTP endpoints for inference and cache updates.
- Fuse model score and graph delta signals.
- Return verdict labels aligned to `ALLOW / FLAG / BLOCK`.

## Key files

- `Cargo.toml`: Rust dependencies and crate config.
- `src/main.rs`: service startup, routing, inference, verdict mapping.
- `src/cache.rs`: risk-delta cache behavior.
- `src/cleaner.rs`: periodic cleanup for expiring entries.

## Typical workflow

1. Build service with Cargo.
2. Point model path env var to ONNX artifact.
3. Run service and hit endpoints from frontend/tools.
