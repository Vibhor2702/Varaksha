// varaksha-bench/src/main.rs
// CLI harness for adversarial robustness testing of the Varaksha Gateway.
//
// Usage:
//   varaksha-bench --target http://localhost:8080 --report ./report.pdf
//
// What it does:
//   1. Runs the adversarial attack suite (attack_suite.rs) — 200 payloads
//      across 5 MITRE ATLAS attack classes.
//   2. Collects ALLOW/BLOCK verdicts from the live gateway.
//   3. Generates a signed JSON summary + a human-readable PDF report.
//
// NOTE: This binary must only target a gateway compiled WITH `bench-mode`.
// production deployments have no /test/art-harness route.

use anyhow::Result;
use clap::Parser;
use tracing::info;
use tracing_subscriber::EnvFilter;

mod attack_suite;
mod report;

use attack_suite::{run_all_attacks, AttackClass};
use report::{generate_pdf_report, generate_signed_json, AttackFinding};

// ─── CLI args ─────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "varaksha-bench",
    version,
    about = "Adversarial robustness benchmark for the Varaksha Gateway",
    long_about = r#"
Runs 200 adversarial payloads (5 MITRE ATLAS classes × 40 samples each) against
a running Varaksha Gateway instance compiled with --features bench-mode.

DO NOT run against a production gateway.  The target URL must serve
POST /test/art-harness.

Output:
  --report <path>.pdf   Human-readable PDF with per-attack findings
  --json   <path>.json  Machine-readable signed JSON (for CI/CD gates)
"#
)]
struct Args {
    /// Gateway base URL, e.g. http://localhost:8080
    #[arg(short, long, default_value = "http://localhost:8080")]
    target: String,

    /// Path to write the PDF report (default: ./varaksha-bench-report.pdf)
    #[arg(short, long, default_value = "./varaksha-bench-report.pdf")]
    report: String,

    /// Path to write the signed JSON summary (default: ./varaksha-bench-report.json)
    #[arg(short, long, default_value = "./varaksha-bench-report.json")]
    json: String,

    /// Only run attacks of this class (optional; blank = all 5 classes)
    #[arg(short, long)]
    class: Option<String>,

    /// Pretty-print JSON output to stdout
    #[arg(long)]
    verbose: bool,
}

// ─── main ─────────────────────────────────────────────────────────────────────

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();

    info!(target = %args.target, "Starting Varaksha adversarial benchmark");

    // Optionally filter to a single attack class
    let class_filter: Option<AttackClass> = args
        .class
        .as_deref()
        .map(|s| s.parse().expect("unknown attack class"));

    // Run the full (or filtered) attack suite against the live gateway
    let findings: Vec<AttackFinding> = run_all_attacks(&args.target, class_filter)?;

    let total = findings.len();
    let blocked = findings.iter().filter(|f| f.blocked).count();
    let block_rate = blocked as f64 / total as f64 * 100.0;

    info!(
        total    = total,
        blocked  = blocked,
        block_rate = format!("{block_rate:.1}%"),
        "Attack suite complete"
    );

    // Signed JSON summary
    let json_path = std::path::Path::new(&args.json);
    let signed = generate_signed_json(&findings)?;
    std::fs::write(json_path, &signed)?;
    info!(path = %json_path.display(), "Signed JSON written");

    // PDF report
    let pdf_path = std::path::Path::new(&args.report);
    generate_pdf_report(&findings, pdf_path)?;
    info!(path = %pdf_path.display(), "PDF report written");

    if args.verbose {
        println!("{}", serde_json::to_string_pretty(&findings)?);
    }

    // Non-zero exit if block rate falls below 95%
    if block_rate < 95.0 {
        eprintln!(
            "FAIL: block rate {block_rate:.1}% is below 95% threshold."
        );
        std::process::exit(1);
    }

    println!(
        "PASS: {blocked}/{total} attacks blocked ({block_rate:.1}%)."
    );
    Ok(())
}
