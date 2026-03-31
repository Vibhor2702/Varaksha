#!/usr/bin/env bash
# Development startup script for Varaksha risk-cache.
# Sets all required env vars and launches the compiled binary.
#
# Usage:  bash start_dev.sh
# Stop:   Ctrl+C

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

export RUST_LOG=info
export VARAKSHA_MODELS_DIR="${SCRIPT_DIR}/../models"
export VARAKSHA_TIER=on_prem

if [[ -z "${ORT_DYLIB_PATH:-}" ]]; then
	if [[ -f "${SCRIPT_DIR}/../.venv/lib/site-packages/onnxruntime/capi/libonnxruntime.so" ]]; then
		export ORT_DYLIB_PATH="${SCRIPT_DIR}/../.venv/lib/site-packages/onnxruntime/capi/libonnxruntime.so"
	elif [[ -f "${SCRIPT_DIR}/../.venv/lib/site-packages/onnxruntime/capi/libonnxruntime.dylib" ]]; then
		export ORT_DYLIB_PATH="${SCRIPT_DIR}/../.venv/lib/site-packages/onnxruntime/capi/libonnxruntime.dylib"
	fi
fi

generate_secret() {
	if command -v python3 >/dev/null 2>&1; then
		python3 -c "import secrets; print(secrets.token_hex(16))"
	elif command -v python >/dev/null 2>&1; then
		python -c "import secrets; print(secrets.token_hex(16))"
	else
		printf "%s%s%s" "$(date +%s 2>/dev/null || echo 0)" "$$" "$RANDOM"
	fi
}

if [[ -z "${VARAKSHA_API_KEY:-}" ]]; then
	export VARAKSHA_API_KEY="dev-api-key-$(generate_secret)"
	echo "[start_dev] VARAKSHA_API_KEY not set; generated ephemeral value."
fi
if [[ -z "${VARAKSHA_GRAPH_SECRET:-}" ]]; then
	export VARAKSHA_GRAPH_SECRET="dev-graph-secret-$(generate_secret)"
	echo "[start_dev] VARAKSHA_GRAPH_SECRET not set; generated ephemeral value."
fi
if [[ -z "${VARAKSHA_UPDATE_SECRET:-}" ]]; then
	export VARAKSHA_UPDATE_SECRET="dev-update-secret-$(generate_secret)"
	echo "[start_dev] VARAKSHA_UPDATE_SECRET not set; generated ephemeral value."
fi

echo "[start_dev] Tier:          ${VARAKSHA_TIER}"
echo "[start_dev] Models dir:    ${VARAKSHA_MODELS_DIR}"
if [[ -n "${ORT_DYLIB_PATH:-}" ]]; then
	echo "[start_dev] ORT DYLIB:     ${ORT_DYLIB_PATH}"
else
	echo "[start_dev] ORT DYLIB:     not set - using system loader/runtime defaults"
fi

exec "${SCRIPT_DIR}/target/debug/risk-cache.exe"
