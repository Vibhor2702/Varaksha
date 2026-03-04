# Varaksha — UPI Fraud Detection System

> Production-deployable, cryptographically-verified AI fraud detection pipeline for the Indian UPI payment network.

```
Rust Gateway (Ed25519 + HMAC-SHA256 + Laplace DP)
    → Agent 01: IsolationForest Profiler + Fraud Heuristics
    → Agent 02: NetworkX Graph Analyst [SGX simulation]
    → Agent 03: Weighted Decision + GPT-4o-mini Narrative
    → Court-ready signed verdict
```

---

## Repository layout

```
gateway/rust-core/          Rust Actix-Web gateway + crypto
  gateway/src/
    main.rs                 POST /v1/tx endpoint
    privacy.rs              HMAC pseudonymisation + Laplace DP noise
    gate.rs                 Ed25519 sign / verify
    rate_limit.rs           DashMap sliding window + IP quarantine
    models.rs               Shared types
  varaksha-bench/           Adversarial benchmark CLI (bench-mode only)

services/
  agents/
    agent01_profiler.py     IsolationForest + heuristic rule engine
    agent02_graph.py        NetworkX fan-out / circular / hub detection
    agent03_decision.py     Weighted score + GPT-4o-mini narrative
    pipeline.py             LangGraph StateGraph orchestrator
  demo/
    app.py                  Streamlit demo dashboard

scripts/
  train_profiler.py         IsolationForest training on PaySim + BankSim
  build_injection_index.py  FAISS injection index builder
  adversarial_scan.py       FAISS + KL injection scanner
  legal_report.py           reportlab PDF generator

security/
  gate-m/                   GATE-M capability-token kernel (Linux/Windows)

security_battleground/      AI Security Evaluation Framework
  arenas/                   fraud_arena, injection_arena, gate_m_arena
  attacks/                  JSON attack definitions (fraud, injection, GATE-M)
  runner.py                 Main entry point
  report/                   Per-run JSON scorecard

data/
  datasets/                 Download instructions (no real data committed)
  models/                   Generated model artifacts (not committed)

docs/
  architecture/
  devlogs/
  pitch/

config/                     .env.example and service config templates
tests/                      Integration test suite
```

---

## Quick start

### Prerequisites

| Tool | Version | Install |
|---|---|---|
| Rust | stable 1.77+ | https://rustup.rs → download rustup-init.exe (x64), option 1 |
| Python | 3.12 | https://python.org |
| Kaggle CLI | any | `pip install kaggle` |
| maturin | 1.5+ | `pip install maturin` |

### 1 — Build the Rust gateway

```powershell
cd gateway/rust-core
cargo build --release
# Binary: gateway/rust-core/target/release/varaksha-gateway.exe
```

Build the Python extension (makes `import varaksha_gateway` work in agents):

```powershell
cd gateway/rust-core
maturin develop
```

### 2 — Install Python dependencies

```powershell
pip install -r services/agents/requirements.txt
```

### 3 — Download datasets

See [data/datasets/README.md](data/datasets/README.md) for full instructions.

```powershell
# PaySim (CC0, ~470 MB)
kaggle datasets download -d ealaxi/paysim1 -p data/datasets/paysim/
# BankSim (~27 MB)
kaggle datasets download -d ntnu-testimon/banksim1 -p data/datasets/banksim/
```

### 4 — Train models

```powershell
python scripts/train_profiler.py
python scripts/build_injection_index.py --input data/datasets/prompt_injections.json
```

### 5 — Configure environment

```powershell
copy config/.env.example .env
# Set OPENAI_API_KEY for GPT-4o-mini narratives
# Leave blank for fully offline template narratives
```

### 6 — Start all services

Open 5 terminals from the repo root:

```powershell
# Terminal 1 — Rust gateway (port 8080)
$env:VARAKSHA_IP_SALT="your-random-salt"
.\gateway\rust-core\target\release\varaksha-gateway.exe

# Terminal 2 — Agent 01 (profiler, port 8001)
uvicorn services.agents.agent01_profiler:app --port 8001

# Terminal 3 — Agent 02 (graph analyst, port 8002)
uvicorn services.agents.agent02_graph:app --port 8002

# Terminal 4 — Agent 03 (decision + narrative, port 8003)
uvicorn services.agents.agent03_decision:app --port 8003

# Terminal 5 — Pipeline + Streamlit demo
uvicorn services.agents.pipeline:app --port 8000
streamlit run services/demo/app.py
```

### 7 — Send a test transaction

```powershell
$body = @{
    sender_upi_id   = "alice@okicici"
    receiver_upi_id = "landlord@okhdfc"
    amount_inr      = 1500.0
    merchant_category = "rent"
    is_first_transfer = $false
} | ConvertTo-Json

Invoke-RestMethod -Method POST -Uri "http://localhost:8080/v1/tx" `
    -ContentType "application/json" -Body $body
```

---

## AI Security Battleground

Built-in adversarial evaluation framework — tests Varaksha against simulated fraud, prompt injection, and GATE-M capability attacks.

```powershell
# Run all three arenas (requires services running)
python security_battleground/runner.py

# Individual arenas
python security_battleground/runner.py --arena fraud       # live gateway required
python security_battleground/runner.py --arena injection   # fully offline
python security_battleground/runner.py --arena gate_m      # fully offline
```

**Results (March 2026 — all services running, March 2026):**

| Arena | Pass | Key metric |
|---|---|---|
| Fraud detection | 10/10 | 8/8 attacks caught, 0 false positives |
| Injection blocking | 8/8 | 6/6 injections blocked (100%) |
| GATE-M enforcement | 6/6 | 3/3 unsafe actions prevented (100%) |
| **Overall** | **24/24** | **100%** |

Results written to `security_battleground/report/battleground_report.json` after each run.

---

## Architecture

```
[Client]
   │  POST /v1/tx (raw UPI JSON)
   ▼
[Rust Gateway :8080]
   • Rate limit: DashMap sliding window (100 req/s, 5-strike quarantine)
   • Privacy: HMAC-SHA256 pseudonymize UPI IDs (15-min key rotation)
   • DP noise: Laplace ε=1.0 on amount
   • GPS: haversine km only — raw coordinates dropped
   • Sign: Ed25519 SanitizedTx
   │
[Gate A — Ed25519 verify]
   ▼
[Agent 01 :8001 — IsolationForest Profiler]
   • Trained on PaySim (CC0) + BankSim
   • Features: log(amount), velocity, GPS delta, category, network
   • Heuristic rule engine: safe-merchant shield, large-GPS first-transfer,
     first-transfer unverified recipient, fan-out signal
   • Outputs: anomaly_score, velocity_score, z_score, heuristic_labels
   │
   ▼
[Agent 02 :8002 — Graph Analyst]  ← [SGX simulation on this hardware]
   • NetworkX DiGraph of pseudonymized edges (TTL 24h)
   • Detects: fan-out (≥4 receivers/hr), circular flow (A→B→C→A), hub centrality
   │
   ▼
[Agent 03 :8003 — Decision]
   • Score = 0.35×anomaly + 0.35×graph + 0.15×velocity + 0.15×hub
   • Law mapping: BNS §318(4), §111, IT Act §66C/66D, PMLA §3 (IndiaCode)
   • GPT-4o-mini zero-PII narrative (falls back to template offline)
   ▼
[FinalVerdict] → client  (risk_score, verdict, narrative)
```

---

## Security design

| Property | Implementation |
|---|---|
| Zero PII to AI | HMAC-SHA256 pseudonymous IDs; Laplace DP noise on amount |
| Message integrity | Ed25519 sign/verify at every agent boundary |
| Rate-limit / DDoS | DashMap sliding window + 10-min IP quarantine |
| Memo injection | FAISS cosine + hardcoded regex (7 patterns) |
| File-system safety | GATE-M capability-token kernel — scope + forbidden enforcement |
| Court-ready output | Signed verdict with BNS/IT Act citations on every BLOCK |

---

## GATE-M

See [security/gate-m/README.md](security/gate-m/README.md) for full documentation.

GATE-M is a mistake-prevention kernel that sits between an AI agent and the filesystem. Every tool call (read / write / exec) is checked against a capability token before execution.

**Enforcement layers:**

| Layer | What it checks | Hard stop? |
|---|---|---|
| L1 Scope | Touched files ∈ write_scope; forbidden patterns (.env, ../../*) | Sometimes |
| L2 Category | Declared edit type matches actual diff shape | No |
| L3 AST | subprocess, socket, os.environ, exec, eval added | Yes |
| L4 Invariant | SHA-256 of protected files; test suite passes | Yes |
| L5 LLM Verifier | Intent alignment for large diffs (>20 lines) | No |

---

## SGX note

Agent 02's graph analysis is labeled **[SGX simulation]** throughout.
The logic is production-ready; only the memory isolation is absent on this
14th-gen Intel machine (no SGX hardware available).
In a Gramine-SGX deployment the NetworkX graph and all pseudonymized edges
are invisible to the host OS.

---

## Datasets

| Dataset | License | Size | Used for |
|---|---|---|---|
| PaySim | CC0 | ~470 MB | IsolationForest training |
| BankSim | Free (Kaggle) | ~27 MB | Additional training diversity |
| deepset/prompt-injections | Apache 2.0 | Small | FAISS injection index |
| JailbreakBench | MIT | Small | FAISS index augmentation |

No dataset files are committed. See [data/datasets/README.md](data/datasets/README.md).

---

## Law references (verified against IndiaCode)

| Section | Offence | Max sentence |
|---|---|---|
| BNS §318(4) | Cheating (financial fraud) | 7 yrs + fine |
| BNS §61 + §111 | Organised crime / money mule circuit | Life + min ₹5L fine |
| IT Act §66C/66D | Identity theft / phishing | 3 yrs + ₹1L fine |
| PMLA §3 | Money laundering | 7 yrs + ₹5L fine |


---

## Quick Start

### Prerequisites

| Tool | Version | Install |
|------|---------|---------|
| Rust | stable (1.77+) | https://rustup.rs → **Download rustup-init.exe (x64)** → option 1 |
| Python | 3.12 | python.org |
| Kaggle CLI | any | `pip install kaggle` |
| maturin | 1.5+ | `pip install maturin` |

### 1. Install Rust (if not done)
Visit **https://rustup.rs**, download **rustup-init.exe (x64)**, run it, choose option 1.
After install, close and reopen your terminal.

### 2. Build the Rust gateway

```powershell
cd varaksha-core
cargo build --release
# Gateway binary: varaksha-core/target/release/varaksha-gateway.exe
```

Build the Python extension (makes `import varaksha_gateway` work in agents):
```powershell
cd varaksha-core
pip install maturin
maturin develop
```

### 3. Install Python dependencies

```powershell
pip install -r agents/requirements.txt
```

### 4. Download datasets

See [datasets/README.md](datasets/README.md) for full instructions.
Short version:
```powershell
# PaySim (CC0, ~470 MB)
kaggle datasets download -d ealaxi/paysim1 -p datasets/paysim/
# BankSim (~27 MB)
kaggle datasets download -d ntnu-testimon/banksim1 -p datasets/banksim/
# Adversarial strings
python -c "from datasets import load_dataset; ds = load_dataset('deepset/prompt-injections'); ..."
```

### 5. Train models

```powershell
python agents/train_profiler.py
python agents/build_injection_index.py --input datasets/all_adversarial.json --build-corpus
```

### 6. Configure environment

```powershell
copy .env.example .env
# Edit .env — add OPENAI_API_KEY if you want GPT-4o-mini narratives
# (leave blank for fully-offline template narratives)
```

### 7. Start the system

Open 5 terminals:

```powershell
# Terminal 1 — Rust gateway
$env:VARAKSHA_IP_SALT="your-random-salt"; .\varaksha-core\target\release\varaksha-gateway.exe
# Copy the gate key fingerprint printed to stdout → paste into .env

# Terminal 2 — Agent 01
uvicorn agents.agent01_profiler:app --port 8001

# Terminal 3 — Agent 02
uvicorn agents.agent02_graph:app --port 8002

# Terminal 4 — Agent 03
uvicorn agents.agent03_decision:app --port 8003

# Terminal 5 — Pipeline + demo
uvicorn agents.pipeline:app --port 8000
streamlit run demo/app.py
```

Open http://localhost:8501 in your browser.

---

## Running the adversarial benchmark

```powershell
# Build bench binary (with bench-mode — NEVER use in production)
cargo build --manifest-path varaksha-core/Cargo.toml --features bench-mode
# Run 200-payload attack suite
.\varaksha-core\target\debug\varaksha-bench.exe --target http://localhost:8080 --report bench-report.pdf
# Expects ≥95% block rate to exit 0
```

---

## Architecture

```
[Client]
   │  POST /v1/tx (raw UPI JSON)
   ▼
[Rust Gateway :8080]
   • Rate limit: DashMap sliding window (100 req/s, 5-strike quarantine)
   • Privacy: HMAC-SHA256 pseudonymize UPI IDs (15-min key rotation)
   • DP noise: Laplace ε=1.0 on amount
   • GPS: haversine km only, raw coordinates dropped
   • Sign: Ed25519 SanitizedTx
   │
[Gate A — Ed25519 verify]
   ▼
[Agent 01 :8001 — IsolationForest Profiler]
   • Trained on PaySim (CC0) + BankSim
   • Features: log(amount), velocity, GPS delta, category, network
   • Outputs: anomaly_score, velocity_score, z_score
   │
[Gate B — Ed25519 verify]
   ▼
[Agent 02 :8002 — Graph Analyst]  ← [SGX simulation on this hardware]
   • NetworkX DiGraph of pseudonymized edges
   • Detects: fan-out (≥4 receivers/hr), circular flow (A→B→C→A), hub centrality
   │
[Gate C — Ed25519 verify]
   ▼
[Agent 03 :8003 — Decision]
   • Score = 0.35×anomaly + 0.35×graph + 0.15×velocity + 0.15×hub
   • Law mapping: BNS §318(4), §111, IT Act §66C/66D, PMLA §3 (IndiaCode)
   • GPT-4o-mini zero-PII narrative (falls back to template offline)
   ▼
[FinalVerdict + signed PDF] → client + reports/
```

---

## Security design

| Property | Implementation |
|---|---|
| Zero PII to AI | HMAC-SHA256 pseudonymous IDs; Laplace DP noise on amount |
| Message integrity | Ed25519 sign/verify at every agent boundary |
| Rate-limit / DDoS | DashMap sliding window + 10-min IP quarantine |
| Adversarial robustness | FAISS cosine + KL-divergence memo scanner; IBM ART bench suite |
| court-ready output | Signed PDF with BNS/IT Act citations on every BLOCK |

---

## Key directories

```
varaksha-core/       Rust workspace
  gateway/           Actix-Web gateway + crypto (privacy, gate, rate_limit)
  varaksha-bench/    CLI adversarial benchmark (bench-mode only)
agents/              Python LangGraph agents
  agent01_profiler.py
  agent02_graph.py
  agent03_decision.py
  pipeline.py        LangGraph StateGraph orchestrator
  adversarial_scan.py FAISS + KL injection scanner
  legal_report.py    reportlab PDF generator
  train_profiler.py  IsolationForest training script
  build_injection_index.py FAISS index builder
  requirements.txt
datasets/            Download instructions (no actual data committed)
models/              Generated model files (not committed)
demo/                Streamlit demo harness
reports/             Generated PDF reports (not committed)
GATE-M-master/       Partner repo — OS-level kernel wrapper (Linux, fanotify)
```

---

## SGX note

Agent 02's graph analysis is labeled **[SGX simulation]** throughout.
The logic is production-ready; only the memory isolation is absent on this
14th-gen Intel machine (no SGX hardware).
In a Gramine-SGX deployment, the NetworkX graph and all pseudonymized edges
are invisible to the host OS.

---

## Datasets

| Dataset | License | Size | Used for |
|---|---|---|---|
| PaySim | CC0 | ~470 MB | IsolationForest training |
| BankSim | Free (Kaggle) | ~27 MB | Additional training diversity |
| deepset/prompt-injections | Apache 2.0 | Small | FAISS injection index |
| JailbreakBench | MIT | Small | FAISS injection index (augment) |

No datasets are committed to this repository.

---

## Law references (verified against IndiaCode)

| Section | Offence | Max Sentence |
|---|---|---|
| BNS §318(4) | Cheating (financial fraud) | 7 yrs + fine |
| BNS §61 + §111 | Organised crime (money mule) | Life + min ₹5L fine |
| IT Act §66C/66D | Identity theft / phishing | 3 yrs + ₹1L fine |
| PMLA §3 | Money laundering | 7 yrs + ₹5L fine |
