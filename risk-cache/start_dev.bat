@echo off
REM Development startup for Varaksha risk-cache.
REM Run from the risk-cache\ directory: start_dev.bat

set RUST_LOG=info
set VARAKSHA_MODELS_DIR=..\models
set VARAKSHA_TIER=on_prem

if not defined ORT_DYLIB_PATH (
	if exist "..\.venv\Lib\site-packages\onnxruntime\capi\onnxruntime.dll" (
		set ORT_DYLIB_PATH=..\.venv\Lib\site-packages\onnxruntime\capi\onnxruntime.dll
	)
)

REM Generate ephemeral dev credentials when not supplied by environment.
if not defined VARAKSHA_API_KEY (
	for /f %%i in ('powershell -NoProfile -Command "[guid]::NewGuid().ToString('N')"') do set VARAKSHA_API_KEY=dev-api-key-%%i
	echo [start_dev] VARAKSHA_API_KEY not set; generated ephemeral value.
)
if not defined VARAKSHA_GRAPH_SECRET (
	for /f %%i in ('powershell -NoProfile -Command "[guid]::NewGuid().ToString('N')"') do set VARAKSHA_GRAPH_SECRET=dev-graph-secret-%%i
	echo [start_dev] VARAKSHA_GRAPH_SECRET not set; generated ephemeral value.
)
if not defined VARAKSHA_UPDATE_SECRET (
	for /f %%i in ('powershell -NoProfile -Command "[guid]::NewGuid().ToString('N')"') do set VARAKSHA_UPDATE_SECRET=dev-update-secret-%%i
	echo [start_dev] VARAKSHA_UPDATE_SECRET not set; generated ephemeral value.
)

echo [start_dev] Tier:       %VARAKSHA_TIER%
echo [start_dev] Models dir: %VARAKSHA_MODELS_DIR%
if defined ORT_DYLIB_PATH (
	echo [start_dev] ORT DLL:    %ORT_DYLIB_PATH%
) else (
	echo [start_dev] ORT DLL:    not set - using system loader/runtime defaults
)
echo [start_dev] Starting...

target\debug\risk-cache.exe
