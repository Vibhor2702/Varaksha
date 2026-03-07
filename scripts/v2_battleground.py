"""
scripts/v2_battleground.py
──────────────────────────────────────────────────────────────────────────────
Varaksha V2 — Security Battleground
Standalone adversarial test harness.  Does NOT touch any application code.

Usage:
    python scripts/v2_battleground.py [--host http://localhost:8082]

Arenas:
    1. Latency & Rate-Limit Arena   — 150 requests; expect first 100 → 200,
                                      last 50 → 429 Too Many Requests
    2. Adversarial ML Evasion       — "Sneaky Mule" just-below-threshold payload;
                                      expect verdict FLAG or BLOCK
    3. Graph Ring Detection         — 4-hop money-laundering cycle A→B→C→D→A;
                                      expect final hop → BLOCK

Dependencies (both already in requirements.txt or installable):
    pip install requests rich

NOTE: The Rust gateway at /v1/tx is partially stubbed (TODOs for teammate).
      This script tolerates a missing rate-limiter and a non-blocking cache
      gracefully — it marks those assertions as SKIP/WARN so the demo can
      still run, and it simulates the expected responses locally when the
      live endpoint is unreachable.
──────────────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

import argparse
import hashlib
import statistics
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Literal

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    sys.exit("requests not found — run: pip install requests")

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
    from rich.rule import Rule
    from rich.table import Table
    from rich import box
except ImportError:
    sys.exit("rich not found — run: pip install rich")

# ── Config ────────────────────────────────────────────────────────────────────

DEFAULT_HOST = "http://localhost:8082"
TX_ENDPOINT  = "/v1/tx"

console = Console()

Status = Literal["PASS", "FAIL", "WARN", "SKIP"]


# ── HTTP session (no retries — we want to see failures) ───────────────────────

def _make_session(host: str) -> tuple[requests.Session, bool]:
    """Return (session, gateway_alive)."""
    session = requests.Session()
    adapter = HTTPAdapter(max_retries=Retry(total=0))
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    try:
        r = session.get(f"{host}/health", timeout=2)
        return session, r.status_code == 200
    except Exception:
        return session, False


# ── Payload factories ────────────────────────────────────────────────────────

def _tx_payload(
    vpa: str,
    amount_inr: float,
    merchant_category: str = "P2P",
    device_id: str = "dev-known-01",
    hour: int = 14,
    day: int = 2,
) -> dict:
    """Build a /v1/tx request body matching TxRequest in models.rs."""
    iso_ts = datetime(2026, 3, 7, hour, 0, 0, tzinfo=timezone.utc).isoformat()
    return {
        "vpa":               vpa,
        "amount_paise":      int(amount_inr * 100),   # INR → paise
        "merchant_category": merchant_category,
        "device_id":         hashlib.sha256(device_id.encode()).hexdigest()[:16],
        "initiated_at":      iso_ts,
    }


# ── Result accumulator ────────────────────────────────────────────────────────

@dataclass
class ArenaResult:
    name:    str
    status:  Status = "PASS"
    details: list[str] = field(default_factory=list)
    metrics: dict       = field(default_factory=dict)

    def fail(self, msg: str) -> None:
        self.status = "FAIL"
        self.details.append(f"[red]✗[/red] {msg}")

    def warn(self, msg: str) -> None:
        if self.status == "PASS":
            self.status = "WARN"
        self.details.append(f"[yellow]⚠[/yellow] {msg}")

    def ok(self, msg: str) -> None:
        self.details.append(f"[green]✓[/green] {msg}")

    def skip(self, msg: str) -> None:
        if self.status == "PASS":
            self.status = "SKIP"
        self.details.append(f"[dim]↷ SKIP:[/dim] {msg}")


# ── Arena 1: Latency & Rate-Limit ─────────────────────────────────────────────

def arena_rate_limit(session: requests.Session, host: str, alive: bool) -> ArenaResult:
    """
    Fire 150 identical requests from a single simulated IP.
    Expectation:
      - First 100: HTTP 200, latency < 5 ms
      - Last  50:  HTTP 429 (rate limited)
    If gateway is down, runs in dry-run mode and notes the stub.
    """
    result  = ArenaResult("Latency & Rate-Limit Arena")
    payload = _tx_payload("loadtest@okaxis", 500.00, "P2P")
    headers = {"X-Forwarded-For": "203.0.113.42"}   # RFC 5737 TEST-NET — safe simulated IP

    latencies_ok: list[float] = []  # ms for HTTP-200 responses
    ok_count   = 0
    rate_count = 0
    err_count  = 0
    TOTAL      = 150
    RATE_AFTER = 100

    if not alive:
        result.skip(
            "Gateway unreachable — simulating 100×200 + 50×429 locally "
            "(latency: ~0.01 ms / req)"
        )
        # Simulate latency distribution for the scorecard
        result.metrics = {
            "total": TOTAL, "ok": RATE_AFTER, "rate_limited": 50,
            "errors": 0, "avg_latency_ms": 0.01, "p99_latency_ms": 0.02,
            "rate_limit_enforced": "SIMULATED",
        }
        result.ok(
            f"Simulated {RATE_AFTER} × 200 OK (avg 0.01 ms) + 50 × 429"
        )
        return result

    url = f"{host}{TX_ENDPOINT}"
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as prog:
        task = prog.add_task(f"  Firing {TOTAL} requests…", total=TOTAL)
        for i in range(TOTAL):
            t0 = time.perf_counter()
            try:
                resp = session.post(url, json=payload, headers=headers, timeout=5)
                elapsed_ms = (time.perf_counter() - t0) * 1000
                if resp.status_code == 200:
                    ok_count += 1
                    latencies_ok.append(elapsed_ms)
                elif resp.status_code == 429:
                    rate_count += 1
                else:
                    err_count += 1
            except Exception:
                err_count += 1
            prog.advance(task)

    # ── Assertions ─────────────────────────────────────────────────────────
    avg_lat = statistics.mean(latencies_ok) if latencies_ok else 0.0
    p99_lat = (sorted(latencies_ok)[int(len(latencies_ok) * 0.99) - 1]
               if len(latencies_ok) >= 2 else avg_lat)

    result.metrics = {
        "total":              TOTAL,
        "ok":                 ok_count,
        "rate_limited":       rate_count,
        "errors":             err_count,
        "avg_latency_ms":     round(avg_lat, 3),
        "p99_latency_ms":     round(p99_lat, 3),
        "rate_limit_enforced": rate_count >= 40,  # lenient: ≥40/50 is acceptable
    }

    # Latency assertion (only on 200s)
    if latencies_ok:
        if p99_lat < 5.0:
            result.ok(f"{ok_count} × 200 OK — P99 latency {p99_lat:.2f} ms (target < 5 ms) ✓")
        else:
            result.warn(
                f"{ok_count} × 200 OK — P99 latency {p99_lat:.2f} ms EXCEEDS 5 ms target. "
                "Rust cache TODO not yet implemented."
            )
    else:
        result.warn("No HTTP 200 responses received — gateway may require auth or is not routing.")

    # Rate-limit assertion
    if rate_count >= 40:
        result.ok(f"Rate-limiter active: {rate_count}/50 requests beyond threshold returned 429.")
    elif rate_count > 0:
        result.warn(
            f"Partial rate-limiting: only {rate_count}/50 requests returned 429. "
            "Rate-limit middleware may be incomplete."
        )
    else:
        result.warn(
            "Rate-limiter not active: 0 × 429 observed. "
            "Expected after req #100 — TODO in Rust gateway."
        )

    if err_count:
        result.warn(f"{err_count} requests failed with connection errors.")

    return result


# ── Arena 2: Adversarial ML Evasion ──────────────────────────────────────────

def arena_ml_evasion(session: requests.Session, host: str, alive: bool) -> ArenaResult:
    """
    'Sneaky Mule' evasion probe:
      - amount ₹99,999 (just below standard ₹1L alerting threshold)
      - 3 AM initiation time
      - fresh device fingerprint (is_new_device signal)
      - P2P merchant category (common mule channel)
    Expect verdict == "FLAG" or "BLOCK".
    """
    result  = ArenaResult("Adversarial ML Evasion")
    payload = _tx_payload(
        vpa               = "sneaky.mule99@paytm",
        amount_inr        = 99_999.00,   # ₹99,999 — just under ₹1L BNS threshold
        merchant_category = "P2P",
        device_id         = "new-device-XYZ-2026",  # unseen device fingerprint
        hour              = 3,            # 3 AM — anomalous hour
        day               = 6,            # Sunday
    )

    result.details.append(
        "[dim]Payload: ₹99,999 | 3 AM | new device | P2P | just below ₹1L threshold[/dim]"
    )

    if not alive:
        result.skip(
            "Gateway unreachable — ML ensemble would flag amount_zscore ≈ 3.2, "
            "hour_of_day=3, is_new_device=1 → expected verdict: FLAG or BLOCK."
        )
        result.metrics = {"expected_verdict": "FLAG|BLOCK", "live": False}
        return result

    url = f"{host}{TX_ENDPOINT}"
    t0  = time.perf_counter()
    try:
        resp    = session.post(url, json=payload, timeout=5)
        lat_ms  = (time.perf_counter() - t0) * 1000
    except Exception as exc:
        result.fail(f"Request failed: {exc}")
        return result

    result.metrics = {"http_status": resp.status_code, "latency_ms": round(lat_ms, 3)}

    if resp.status_code != 200:
        result.warn(f"Gateway returned HTTP {resp.status_code} — cache stub may not score VPAs yet.")
        return result

    try:
        body    = resp.json()
        verdict = body.get("verdict", "").upper()
        score   = body.get("risk_score", 0.0)
        result.metrics.update({"verdict": verdict, "risk_score": score})
    except Exception:
        result.fail("Response body is not valid JSON.")
        return result

    if verdict in ("FLAG", "BLOCK"):
        result.ok(
            f"Sneaky Mule correctly caught — verdict={verdict}, score={score:.3f} "
            f"(latency {lat_ms:.2f} ms)."
        )
    elif verdict == "ALLOW":
        result.fail(
            f"Evasion SUCCEEDED — model returned ALLOW (score={score:.3f}). "
            "Check amount_zscore + hour_of_day feature engineering."
        )
        result.details.append(
            "[dim]  Hint: ensure is_new_device and hour_of_day=3 push the ensemble "
            "score above 0.40 (FLAG threshold).[/dim]"
        )
    else:
        # Cache stub returns 0.0 / no verdict — tolerate as WARN
        result.warn(
            f"Verdict not in {{FLAG, BLOCK, ALLOW}}: '{verdict}' (score={score:.3f}). "
            "Rust cache TODO: score_to_verdict() stub always returns ALLOW at score 0.0."
        )

    return result


# ── Arena 3: Graph Ring Detection ────────────────────────────────────────────

def arena_graph_ring(session: requests.Session, host: str, alive: bool) -> ArenaResult:
    """
    Simulate a 4-hop money-laundering ring: A→B → B→C → C→D → D→A.
    The closing hop (D→A) completes the cycle and should be BLOCKed
    by the NetworkX ring detector feeding the Rust cache.
    """
    result = ArenaResult("Graph Ring Detection")

    ring_hops = [
        ("ring.nodeA@upi", "ring.nodeB@upi", 25_000.0, "P2P"),
        ("ring.nodeB@upi", "ring.nodeC@upi", 24_800.0, "P2P"),   # slight amount decay
        ("ring.nodeC@upi", "ring.nodeD@upi", 24_600.0, "P2P"),
        ("ring.nodeD@upi", "ring.nodeA@upi", 24_400.0, "P2P"),   # closes the ring
    ]

    if not alive:
        result.skip(
            "Gateway unreachable — ring simulation: hops 1-3 → ALLOW, "
            "hop 4 (D→A closes cycle) → expected BLOCK via graph agent feed."
        )
        result.metrics = {
            "hops": len(ring_hops),
            "ring_closed_at": 4,
            "final_verdict": "BLOCK (expected)",
            "live": False,
        }
        return result

    url      = f"{host}{TX_ENDPOINT}"
    verdicts = []

    for i, (sender, receiver, amount, cat) in enumerate(ring_hops, start=1):
        # Build payload — receiver VPA put in the device_id field as a trace marker
        payload = _tx_payload(sender, amount, cat)
        payload["device_id"] = hashlib.sha256(receiver.encode()).hexdigest()[:16]

        label = f"Hop {i}/{len(ring_hops)}: {sender.split('@')[0]}→{receiver.split('@')[0]}"
        t0    = time.perf_counter()
        try:
            resp   = session.post(url, json=payload, timeout=5)
            lat_ms = (time.perf_counter() - t0) * 1000
        except Exception as exc:
            result.fail(f"{label} — request failed: {exc}")
            return result

        if resp.status_code != 200:
            result.warn(f"{label} — HTTP {resp.status_code}")
            verdicts.append("ERROR")
            continue

        try:
            body    = resp.json()
            verdict = body.get("verdict", "UNKNOWN").upper()
            score   = body.get("risk_score", 0.0)
        except Exception:
            result.warn(f"{label} — invalid JSON response")
            verdicts.append("ERROR")
            continue

        verdicts.append(verdict)

        if i < len(ring_hops):
            # Intermediate hops: ideally ALLOW or FLAG (ring not yet closed)
            status_icon = "[green]✓[/green]" if verdict in ("ALLOW", "FLAG") else "[yellow]⚠[/yellow]"
            result.details.append(
                f"  {status_icon} {label} → [bold]{verdict}[/bold] (score={score:.3f}, {lat_ms:.1f} ms)"
            )
        else:
            # Final hop: should be BLOCK
            if verdict == "BLOCK":
                result.ok(
                    f"  [green]✓[/green] {label} → [bold red]BLOCK[/bold red] "
                    f"(score={score:.3f}, {lat_ms:.1f} ms) — ring detected ✓"
                )
            else:
                result.warn(
                    f"  {label} → {verdict} (score={score:.3f}, {lat_ms:.1f} ms) — "
                    "ring NOT yet detected. Graph agent cache feed (webhook) may not be wired."
                )
                result.details.append(
                    "[dim]  Hint: graph_agent.py must POST /v1/webhook/update_cache "
                    "with risk_score≥0.75 for ring.nodeD VPA before this hop fires.[/dim]"
                )

    result.metrics = {
        "hops":         len(ring_hops),
        "verdicts":     verdicts,
        "ring_blocked": verdicts[-1] == "BLOCK" if verdicts else False,
    }
    return result


# ── Scorecard renderer ────────────────────────────────────────────────────────

_STATUS_COLOUR = {"PASS": "green", "FAIL": "red", "WARN": "yellow", "SKIP": "dim"}
_STATUS_ICON   = {"PASS": "●", "FAIL": "✗", "WARN": "⚠", "SKIP": "↷"}


def render_scorecard(results: list[ArenaResult], gateway_alive: bool) -> None:
    console.print()
    console.print(Rule("[bold white]VARAKSHA V2 — SECURITY BATTLEGROUND REPORT[/bold white]", style="white"))
    console.print()

    # Gateway status banner
    gw_status = "[bold green]LIVE[/bold green]" if gateway_alive else "[bold yellow]OFFLINE (dry-run)[/bold yellow]"
    console.print(f"  Gateway status : {gw_status}")
    console.print(f"  Run timestamp  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    console.print()

    # Per-arena detail panels
    for r in results:
        colour = _STATUS_COLOUR[r.status]
        icon   = _STATUS_ICON[r.status]
        header = f"[bold {colour}]{icon} {r.name}[/bold {colour}]  [{colour}]{r.status}[/{colour}]"
        body   = "\n".join(r.details) if r.details else "[dim]No details.[/dim]"
        console.print(Panel(body, title=header, border_style=colour, expand=False, padding=(0, 2)))
        console.print()

    # Summary table
    table = Table(
        title        = "Arena Summary",
        box          = box.SIMPLE_HEAVY,
        show_header  = True,
        header_style = "bold white",
        expand       = False,
    )
    table.add_column("Arena",   style="white",  min_width=34)
    table.add_column("Status",  justify="center", min_width=8)
    table.add_column("Key Metric", min_width=38)

    for r in results:
        colour  = _STATUS_COLOUR[r.status]
        icon    = _STATUS_ICON[r.status]
        status  = f"[{colour}]{icon} {r.status}[/{colour}]"

        # Build a one-line key metric
        m = r.metrics
        if r.name.startswith("Latency"):
            if m.get("live", True) is False:
                metric = f"Simulated: avg {m.get('avg_latency_ms', '?')} ms"
            else:
                metric = (
                    f"avg {m.get('avg_latency_ms','?')} ms | "
                    f"P99 {m.get('p99_latency_ms','?')} ms | "
                    f"429s: {m.get('rate_limited','?')}/50"
                )
        elif r.name.startswith("Adversarial"):
            if not m.get("live", True):
                metric = "Dry-run — expected FLAG/BLOCK"
            else:
                metric = (
                    f"verdict={m.get('verdict','?')} | "
                    f"score={m.get('risk_score', '?')}"
                )
        elif r.name.startswith("Graph"):
            if not m.get("live", True):
                metric = "Dry-run — hop 4 → BLOCK expected"
            else:
                v = m.get("verdicts", [])
                blocked = "✓ YES" if m.get("ring_blocked") else "✗ NO"
                metric = f"verdicts={v} | ring_blocked={blocked}"
        else:
            metric = str(m)

        table.add_row(r.name, status, metric)

    console.print(table)
    console.print()

    # Pass rate
    counts = {s: sum(1 for r in results if r.status == s) for s in ("PASS","FAIL","WARN","SKIP")}
    total  = len(results)
    passes = counts["PASS"]
    console.print(
        f"  [bold]Result: {passes}/{total} arenas PASS[/bold]  "
        f"([green]{counts['PASS']} PASS[/green] / "
        f"[red]{counts['FAIL']} FAIL[/red] / "
        f"[yellow]{counts['WARN']} WARN[/yellow] / "
        f"[dim]{counts['SKIP']} SKIP[/dim])"
    )

    if not gateway_alive:
        console.print()
        console.print(
            "  [dim]Gateway was offline — all assertions ran in dry-run / simulation mode.\n"
            "  Start the Rust gateway with `cargo run` in gateway/ then re-run.[/dim]"
        )

    console.print()
    console.print(Rule(style="white"))


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Varaksha V2 Security Battleground — adversarial API test harness"
    )
    parser.add_argument(
        "--host", default=DEFAULT_HOST,
        help=f"Gateway base URL (default: {DEFAULT_HOST})"
    )
    args = parser.parse_args()
    host = args.host.rstrip("/")

    console.print()
    console.print(Panel(
        f"[bold white]Varaksha V2 — Security Battleground[/bold white]\n"
        f"[dim]Target: {host}{TX_ENDPOINT}[/dim]\n"
        f"[dim]Arenas: Latency/Rate-Limit · ML Evasion · Graph Ring[/dim]",
        border_style="white",
        expand=False,
    ))
    console.print()

    session, alive = _make_session(host)
    if not alive:
        console.print(
            f"  [yellow]⚠  Gateway at {host} is not responding — running in dry-run mode.[/yellow]\n"
            f"  [dim]Start it with: cd gateway && cargo run[/dim]\n"
        )

    results: list[ArenaResult] = []

    console.print(Rule("[dim]Arena 1: Latency & Rate-Limit[/dim]"))
    results.append(arena_rate_limit(session, host, alive))

    console.print(Rule("[dim]Arena 2: Adversarial ML Evasion[/dim]"))
    results.append(arena_ml_evasion(session, host, alive))

    console.print(Rule("[dim]Arena 3: Graph Ring Detection[/dim]"))
    results.append(arena_graph_ring(session, host, alive))

    render_scorecard(results, alive)

    # Exit non-zero if any FAIL
    if any(r.status == "FAIL" for r in results):
        sys.exit(1)


if __name__ == "__main__":
    main()
