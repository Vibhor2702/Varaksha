// varaksha-bench/src/report.rs
// PDF + signed JSON report generator for the adversarial benchmark run.

use anyhow::{Context, Result};
use chrono::Utc;
use ed25519_dalek::{Signer, SigningKey};
use printpdf::{Mm, PdfDocument};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::io::BufWriter;
use std::path::Path;

use crate::attack_suite::AttackClass;

// ─── Finding record ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackFinding {
    pub attack_class:   AttackClass,
    pub sample_id:      usize,
    pub description:    String,
    pub mitre_atlas_id: String,
    pub mitre_atlas_name: String,
    pub owasp_ml_ref:   String,
    pub severity:       String,
    pub blocked:        bool,
    pub raw_verdict:    String,
    pub latency_ms:     u64,
}

// ─── Summary ─────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct BenchSummary {
    pub run_id:            String,
    pub generated_at:      String,
    pub total_attacks:     usize,
    pub total_blocked:     usize,
    pub block_rate_pct:    f64,
    pub per_class_summary: Vec<ClassSummary>,
    pub findings:          Vec<AttackFinding>,
    pub report_signature:  String,  // Ed25519 over canonical JSON of the rest
    pub signing_key_fp:    String,  // 16-byte fingerprint of the one-time report key
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ClassSummary {
    pub attack_class: AttackClass,
    pub total:        usize,
    pub blocked:      usize,
    pub block_rate_pct: f64,
}

// ─── Signed JSON generation ───────────────────────────────────────────────────

/// Build a `BenchSummary` and sign it with a freshly-generated one-time Ed25519 key.
/// The verifying key fingerprint is included in the JSON so downstream tooling can
/// at least confirm the report hasn't been tampered since generation.
pub fn generate_signed_json(findings: &[AttackFinding]) -> Result<String> {
    let total = findings.len();
    let blocked = findings.iter().filter(|f| f.blocked).count();
    let block_rate = blocked as f64 / total as f64 * 100.0;

    let per_class = [
        AttackClass::DataPoisoning,
        AttackClass::ModelEvasion,
        AttackClass::PromptInjection,
        AttackClass::MembershipInference,
        AttackClass::ModelInversion,
    ]
    .iter()
    .map(|&class| {
        let class_findings: Vec<_> = findings.iter().filter(|f| f.attack_class == class).collect();
        let ct = class_findings.len();
        let cb = class_findings.iter().filter(|f| f.blocked).count();
        ClassSummary {
            attack_class: class,
            total: ct,
            blocked: cb,
            block_rate_pct: if ct > 0 { cb as f64 / ct as f64 * 100.0 } else { 0.0 },
        }
    })
    .collect();

    // One-time signing key for this report
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let fp = hex::encode(&verifying_key.as_bytes()[..16]);

    // Build summary without signature first
    let mut summary = BenchSummary {
        run_id:            uuid::Uuid::new_v4().to_string(),
        generated_at:      Utc::now().to_rfc3339(),
        total_attacks:     total,
        total_blocked:     blocked,
        block_rate_pct:    block_rate,
        per_class_summary: per_class,
        findings:          findings.to_vec(),
        report_signature:  String::new(),
        signing_key_fp:    fp,
    };

    // Canonical JSON of the unsigned body
    let body_json = serde_json::to_vec(&summary).context("serialize summary")?;
    let sig: ed25519_dalek::Signature = signing_key.sign(&body_json);
    summary.report_signature = hex::encode(sig.to_bytes());

    serde_json::to_string_pretty(&summary).context("serialize signed summary")
}

// ─── PDF generation ───────────────────────────────────────────────────────────

/// Produce a printpdf-based PDF report at `output_path`.
pub fn generate_pdf_report(findings: &[AttackFinding], output_path: &Path) -> Result<()> {
    let (doc, page1, layer1) = PdfDocument::new(
        "Varaksha Adversarial Benchmark Report",
        Mm(210.0), // A4
        Mm(297.0),
        "Layer 1",
    );

    let current_layer = doc.get_page(page1).get_layer(layer1);

    // Use built-in font
    let font = doc.add_builtin_font(printpdf::BuiltinFont::HelveticaBold)
        .context("load builtin font")?;
    let font_regular = doc.add_builtin_font(printpdf::BuiltinFont::Helvetica)
        .context("load regular font")?;

    let total        = findings.len();
    let blocked      = findings.iter().filter(|f| f.blocked).count();
    let block_rate   = blocked as f64 / total as f64 * 100.0;

    // Title
    current_layer.use_text(
        "Varaksha Gateway — Adversarial Robustness Report",
        18.0,
        Mm(15.0),
        Mm(280.0),
        &font,
    );

    current_layer.use_text(
        &format!("Generated: {}   Run ID: auto", Utc::now().format("%Y-%m-%d %H:%M UTC")),
        9.0,
        Mm(15.0),
        Mm(272.0),
        &font_regular,
    );

    // Summary box
    current_layer.use_text("Summary", 13.0, Mm(15.0), Mm(262.0), &font);
    current_layer.use_text(
        &format!("Total attacks: {total}    Blocked: {blocked}    Block rate: {block_rate:.1}%"),
        10.0,
        Mm(15.0),
        Mm(255.0),
        &font_regular,
    );

    let threshold_line = if block_rate >= 95.0 {
        "PASS — block rate exceeds 95% threshold"
    } else {
        "FAIL — block rate is below 95% threshold"
    };
    current_layer.use_text(threshold_line, 11.0, Mm(15.0), Mm(248.0), &font);

    // Per-class table header
    let mut y = Mm(235.0);
    current_layer.use_text("Attack Class", 9.0, Mm(15.0), y, &font);
    current_layer.use_text("MITRE ATLAS", 9.0, Mm(70.0), y, &font);
    current_layer.use_text("Total", 9.0, Mm(130.0), y, &font);
    current_layer.use_text("Blocked", 9.0, Mm(150.0), y, &font);
    current_layer.use_text("Rate", 9.0, Mm(175.0), y, &font);

    y -= Mm(6.0);

    for class in [
        AttackClass::DataPoisoning,
        AttackClass::ModelEvasion,
        AttackClass::PromptInjection,
        AttackClass::MembershipInference,
        AttackClass::ModelInversion,
    ] {
        let class_f: Vec<_> = findings.iter().filter(|f| f.attack_class == class).collect();
        let ct = class_f.len();
        let cb = class_f.iter().filter(|f| f.blocked).count();
        let cr = if ct > 0 { cb as f64 / ct as f64 * 100.0 } else { 0.0 };
        let atlas_id = class_f.first().map(|f| f.mitre_atlas_id.as_str()).unwrap_or("-");

        current_layer.use_text(&format!("{class}"), 9.0, Mm(15.0), y, &font_regular);
        current_layer.use_text(atlas_id, 9.0, Mm(70.0), y, &font_regular);
        current_layer.use_text(&ct.to_string(), 9.0, Mm(130.0), y, &font_regular);
        current_layer.use_text(&cb.to_string(), 9.0, Mm(150.0), y, &font_regular);
        current_layer.use_text(&format!("{cr:.0}%"), 9.0, Mm(175.0), y, &font_regular);

        y -= Mm(6.0);
    }

    // Note about SGX and bench-mode
    y -= Mm(6.0);
    current_layer.use_text(
        "Note: SGX usage in Agent 02 is simulation mode only on this hardware. \
         bench-mode feature must not be compiled into production gateway.",
        7.5,
        Mm(15.0),
        y,
        &font_regular,
    );

    // Write PDF to disk
    let file = std::fs::File::create(output_path)
        .with_context(|| format!("create PDF file: {}", output_path.display()))?;
    let mut writer = BufWriter::new(file);
    doc.save(&mut writer).context("save PDF")?;

    Ok(())
}
