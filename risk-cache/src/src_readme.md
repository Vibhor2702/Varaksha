# Risk Cache Source

Rust source modules for gateway and cache runtime.

## Files

- `main.rs`: HTTP endpoints and inference flow.
- `cache.rs`: in-memory risk delta cache operations.
- `entry.rs`: cache entry structure.
- `cleaner.rs`: background expiration cleanup.
- `metrics.rs`: cache/gateway metrics helpers.
- `lib.rs`: module exports.

## Endpoint intent

- health checks
- cache updates
- inference requests
- graph score updates
