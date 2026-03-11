"use client";

import { motion, useInView } from "framer-motion";
import { useRef } from "react";

// ── Color tokens ──────────────────────────────────────────────────────────────
const ML_C  = "#2563EB";   // blue  — ML Expert  (mirrors saffron)
const SEC_C = "#EC4899";   // pink  — Security Expert

type Owner = "ml" | "sec" | "both";

function cColor(o: Owner) {
  return o === "sec" ? SEC_C : ML_C;
}
function cGrad(o: Owner): string | undefined {
  return o === "both"
    ? `linear-gradient(135deg, ${SEC_C} 0%, ${ML_C} 100%)`
    : undefined;
}
function cLabel(o: Owner) {
  return o === "sec" ? "Security Expert" : o === "ml" ? "ML Expert" : "Joint Effort";
}

// ── Data ──────────────────────────────────────────────────────────────────────
interface TEvent {
  date:      string;
  phase:     string;
  title:     string;
  body:      string;
  tags:      string[];
  owner:     Owner;
  artifact?: string;
}

const EVENTS: TEvent[] = [
  {
    date:     "Feb 28",
    phase:    "Phase 0",
    title:    "Concept & Architecture Defined",
    body:     "Full V1 audit: PyO3 Rust-Python bridge, GATE-M kernel monitor, SLSA supply-chain verification — all passing tests, but 12-step setup killed demo legibility. Decision: branch test, rebuild as five focused layers with plain JSON interfaces. V1 preserved on main for reference.",
    tags:     ["V1 Audit", "5-Layer Design", "Architecture Decision", "test branch"],
    owner:    "both",
    artifact: "docs/devlogs/DEVLOG.md",
  },
  {
    date:     "Mar 1",
    phase:    "Phase 1",
    title:    "Layer 1 — ML Engine First Cut",
    body:     "train_ensemble.py scaffolded: VotingClassifier (RF + XGBoost, soft vote), 8 derived features (velocity, round-amount flag, out-degree, hour-of-day sinusoid), SMOTE applied before split. Loaders for PaySim 50K stratified sample + UPI synthetic CSV. IsolationForest contamination=0.02.",
    tags:     ["RandomForest", "XGBoost", "SMOTE", "IsolationForest", "8 features", "PaySim"],
    owner:    "ml",
    artifact: "services/local_engine/train_ensemble.py",
  },
  {
    date:     "Mar 1",
    phase:    "Phase 2",
    title:    "Layer 2 — Rust Gateway Built",
    body:     "Actix-Web 4 server on :8082. Privacy chokepoint: SHA-256 VPA hashing — raw UPI IDs seen once, never written downstream. DashMap for lock-free concurrent risk cache across Actix worker threads. Three endpoints wired: GET /health, POST /v1/tx, POST /v1/webhook/update_cache. score_to_verdict() threshold logic complete.",
    tags:     ["Actix-Web 4", "DashMap", "SHA-256", "Rust", "<5ms P99", "VPA hash"],
    owner:    "sec",
    artifact: "gateway/src/main.rs · cache.rs · models.rs",
  },
  {
    date:     "Mar 2",
    phase:    "Phase 3",
    title:    "Layer 3 — Graph Mule Detection",
    body:     "NetworkX graph agent running fully async — never blocks /v1/tx response. Four BIS Project Hertha typologies: fan-out (+0.35), fan-in (+0.30), directed cycle (+0.50), scatter (+0.20). Max aggregation (not sum) to prevent false-flagging on high-volume legitimate merchants. HMAC-SHA256-signed webhook pushes scores to Rust cache.",
    tags:     ["NetworkX", "Fan-out", "Fan-in", "Cycle", "HMAC-SHA256", "Async Webhook"],
    owner:    "sec",
    artifact: "services/graph/graph_agent.py",
  },
  {
    date:     "Mar 2",
    phase:    "Phase 4",
    title:    "Layer 4 — Multilingual Alert Agent",
    body:     "Last-mile communication for flagged transactions: deterministic Hindi narration templates (no LLM dependency, auditable output), googletrans for 22 Indian scheduled languages, edge-tts for free Microsoft neural TTS with no API key. Graceful degradation to plain-text on base Python. BLOCK verdicts cite IT Act 2000 §66C and BNSS §318.",
    tags:     ["edge-tts", "Hindi", "googletrans", "IT Act §66C", "BNSS §318", "22 languages"],
    owner:    "sec",
    artifact: "services/agents/agent03_accessible_alert.py",
  },
  {
    date:     "Mar 3",
    phase:    "Phase 5",
    title:    "Layer 5 — Streamlit Demo Dashboard",
    body:     "Single-file live dashboard: auto-refreshing ALLOW/FLAG/BLOCK risk feed with coloured verdict badges, Plotly Scattergl force-directed transaction network, Hindi alert panel for latest flagged transaction, audit log of last 50 scored transactions. Zero real PII — all VPA strings synthetic from seeded RNG.",
    tags:     ["Streamlit", "Plotly", "Risk Feed", "Audit Log", "Synthetic PII"],
    owner:    "both",
    artifact: "services/demo/app.py",
  },
  {
    date:     "Mar 5–7",
    phase:    "Phase 6",
    title:    "ML Pipeline Overhaul — RF-Only + 7 Datasets",
    body:     "XGBoost dropped: RF+XGB simultaneously = ~450 MB, blowing the 512 MB free-tier budget. RF-300 alone achieves ROC-AUC 0.9869 — marginal gain from adding XGB < 0.005. Feature count expanded 8→16: added balance_drain_ratio, account_age_days, previous_failed_attempts, transfer_cashout_flag. Seven loaders merged 75,358 rows. ONNX output: varaksha_rf_model.onnx.",
    tags:     ["RF-300", "XGB dropped", "16 features", "75K rows", "ONNX", "94.4% acc", "ROC-AUC 0.9869"],
    owner:    "ml",
    artifact: "varaksha_rf_model.onnx · isolation_forest.onnx · scaler.onnx",
  },
  {
    date:     "Mar 9–10",
    phase:    "Phase 7",
    title:    "Next.js 15 Frontend — Three Pages",
    body:     "Static export (output: \"export\") for Cloudflare Pages edge delivery — zero SSR, zero cold starts. Three routes: / (landing with metric cards + architecture diagram), /flow (animated 5-layer architectural walkthrough with interactive step navigation), /live (synthetic real-time transaction feed with Security Arena and Cache Visualizer panels). First deployment live.",
    tags:     ["Next.js 15", "Cloudflare Pages", "Static Export", "framer-motion", "3 Routes"],
    owner:    "both",
    artifact: "frontend/ → varaksha.pages.dev",
  },
  {
    date:     "Mar 11",
    phase:    "Phase 8 — Part I",
    title:    "Dataset Audit — 3 Missing Loaders Found",
    body:     "Review of data/datasets/ found 10 CSV files but train_ensemble.py had loaders for only 7. Three silently ignored: supervised_dataset.csv (API behavior anomaly, 1,699 rows), remaining_behavior_ext.csv (bot/attack/outlier behaviors, 34,423 rows), ton-iot.csv (IoT network intrusion, 19 rows). File timestamps on disk models confirmed they predated the Phase 6 loaders — never truly trained on full set.",
    tags:     ["Data Audit", "supervised_dataset", "remaining_behavior_ext", "ton-iot", "stale timestamps"],
    owner:    "ml",
    artifact: "train_ensemble.py — 3 new loaders added",
  },
  {
    date:     "Mar 11",
    phase:    "Phase 8 — Part II",
    title:    "Retrain on 111,499 Rows",
    body:     "Three loaders wired into load_and_merge_all(). SMOTE rebalancing: 51,735 legit / 51,735 fraud. Result: RF Accuracy 96.52% (+2.1pp), ROC-AUC 0.9952, Fraud Precision 0.9745, Recall 0.9419, F1 0.9579. Stale ghost artifacts removed: lightgbm.pkl, xgboost.pkl/onnx, voting_ensemble.pkl/onnx.",
    tags:     ["111K rows", "96.52%", "ROC-AUC 0.9952", "SMOTE 50/50", "Ghost cleanup"],
    owner:    "ml",
    artifact: "data/models/ — 5 stale files removed",
  },
  {
    date:     "Mar 11",
    phase:    "Phase 9",
    title:    "UI Polish — Textures & Colour System",
    body:     "Dot-grid body texture (22 px pitch, ink@5% opacity) layered with denim radial glow (top-left) and teal radial glow (bottom-right). .surface-card diagonal gradient utility applied to metric and step-detail cards. New flag (#D97706 amber) Tailwind token split from saffron (blue) — FLAG verdict colour now amber across all live-page components. Dark <main> on live page receives matching inline texture.",
    tags:     ["dot-grid", "surface-card", "flag #D97706", "saffron split", "amber FLAG", "texture"],
    owner:    "both",
    artifact: "globals.css · tailwind.config.ts · live/page.tsx",
  },
  {
    date:     "Mar 11",
    phase:    "Deployment",
    title:    "Repo Transfer & Final Deploy",
    body:     "Repository transferred from Vibhor2702/Varaksha to Varaksha-G/Varaksha org. Remote updated locally, all commits pushed. Cloudflare Pages project recreated under new identity. Metric card updated: 96.52% · 111K rows · 7 real datasets. README and DEVLOG updated for Phases 8–9. Timeline page shipped.",
    tags:     ["Varaksha-G/Varaksha", "Cloudflare Pages", "Docs Updated", "Final Deploy"],
    owner:    "both",
    artifact: "varaksha.pages.dev",
  },
];

// ── Spine node ────────────────────────────────────────────────────────────────
function SpineNode({ owner }: { owner: Owner }) {
  const color = owner === "sec" ? SEC_C : ML_C;
  const grad  = owner === "both";

  return (
    <div className="relative w-5 h-5 flex items-center justify-center shrink-0">
      <motion.span
        className="absolute inset-0 rounded-full"
        style={{ border: `1.5px solid ${grad ? SEC_C : color}` }}
        animate={{ scale: [1, 1.85, 1], opacity: [0.45, 0, 0.45] }}
        transition={{ duration: 2.8, repeat: Infinity, ease: "easeOut" }}
      />
      <div
        className="w-3 h-3 rounded-full shadow-sm"
        style={
          grad
            ? { background: `linear-gradient(135deg, ${SEC_C}, ${ML_C})` }
            : { backgroundColor: color }
        }
      />
    </div>
  );
}

// ── Connector arm (spine ↔ card) ─────────────────────────────────────────────
function Arm({ owner, side }: { owner: Owner; side: "left" | "right" }) {
  const color = owner === "sec" ? SEC_C : ML_C;
  const grad  = owner === "both";
  return (
    <div
      className="hidden lg:block h-px w-10 shrink-0"
      style={
        grad
          ? { backgroundImage: `linear-gradient(${side === "right" ? "to right" : "to left"}, ${SEC_C}, ${ML_C})` }
          : { backgroundColor: color, opacity: 0.35 }
      }
    />
  );
}

// ── Event card ────────────────────────────────────────────────────────────────
function EventCard({ ev, side }: { ev: TEvent; side: "left" | "right" | "center" }) {
  const ref    = useRef<HTMLDivElement>(null);
  const inView = useInView(ref, { once: true, margin: "-80px 0px 0px 0px" });

  const color = ev.owner === "sec" ? SEC_C : ML_C;
  const grad  = cGrad(ev.owner);

  const dx = side === "left" ? -24 : side === "right" ? 24 : 0;

  const cardInner = (
    <div className="bg-white/62 p-4 lg:p-5">
      {/* Owner + date row */}
      <div className="flex items-start justify-between gap-3 mb-2">
        <span
          className="font-barlow text-[0.5rem] tracking-[0.28em] uppercase font-semibold"
          style={
            grad
              ? { backgroundImage: grad, WebkitBackgroundClip: "text", color: "transparent" }
              : { color }
          }
        >
          {cLabel(ev.owner)}
        </span>
        <span className="font-courier text-[0.52rem] text-ink/25 tracking-wider whitespace-nowrap">
          {ev.date}
        </span>
      </div>

      {/* Phase kicker */}
      <p className="font-barlow text-[0.47rem] tracking-[0.24em] uppercase text-ink/28 mb-0.5">
        {ev.phase}
      </p>

      {/* Title */}
      <h3 className="font-playfair font-bold text-ink text-[1rem] lg:text-[1.08rem] leading-tight mb-2">
        {ev.title}
      </h3>

      {/* Body */}
      <p className="font-barlow text-[0.72rem] text-ink/48 leading-relaxed mb-3">
        {ev.body}
      </p>

      {/* Tags */}
      <div className="flex flex-wrap gap-1 mb-3">
        {ev.tags.map((t, i) => (
          <span
            key={i}
            className="font-courier text-[0.47rem] tracking-wider uppercase px-1.5 py-0.5"
            style={{
              color:           grad ? "#6b7280" : color,
              backgroundColor: grad ? "rgba(0,0,0,0.03)" : `${color}0d`,
              border:          `1px solid ${grad ? "rgba(0,0,0,0.09)" : color + "2e"}`,
            }}
          >
            {t}
          </span>
        ))}
      </div>

      {/* Artifact */}
      {ev.artifact && (
        <p className="font-courier text-[0.5rem] text-ink/22 tracking-wider border-t border-ink/[0.06] pt-2">
          ↳ {ev.artifact}
        </p>
      )}
    </div>
  );

  return (
    <motion.div
      ref={ref}
      initial={{ opacity: 0, x: dx, y: 10 }}
      animate={inView ? { opacity: 1, x: 0, y: 0 } : {}}
      transition={{ duration: 0.52, ease: [0.22, 1, 0.36, 1] }}
      className="overflow-hidden"
    >
      {grad ? (
        /* Gradient border wrapper for joint events */
        <div
          className="p-[1.5px]"
          style={{ backgroundImage: grad }}
        >
          {cardInner}
        </div>
      ) : (
        <div
          className="border"
          style={{ borderColor: `${color}28` }}
        >
          {/* Coloured top bar */}
          <div className="h-[3px]" style={{ backgroundColor: color }} />
          {cardInner}
        </div>
      )}
    </motion.div>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────
export default function TimelinePage() {
  return (
    <main className="min-h-screen bg-cream text-ink pb-32">

      {/* ── Sub-header ─────────────────────────────────────────────────── */}
      <header className="border-b border-ink/10 px-6 lg:px-12 py-2.5">
        <div className="max-w-7xl mx-auto flex items-center gap-3">
          <a
            href="/"
            className="font-barlow text-[0.6rem] tracking-[0.24em] uppercase text-ink/32 hover:text-saffron transition-colors"
          >
            &larr;&thinsp;Varaksha
          </a>
          <span className="text-ink/15 select-none">|</span>
          <span className="font-barlow text-[0.6rem] tracking-[0.24em] uppercase text-ink/32">
            Build Timeline
          </span>
        </div>
      </header>

      {/* ── Hero ───────────────────────────────────────────────────────── */}
      <section className="px-6 lg:px-12 pt-14 pb-10 max-w-7xl mx-auto">
        <motion.p
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          className="font-barlow text-[0.68rem] tracking-[0.36em] uppercase mb-4"
          style={{ backgroundImage: `linear-gradient(90deg, ${SEC_C}, ${ML_C})`, WebkitBackgroundClip: "text", color: "transparent", display: "inline-block" }}
        >
          Feb 28 &ndash; Mar 11, 2026
        </motion.p>

        <motion.h1
          initial={{ opacity: 0, y: 18 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.07, duration: 0.5, ease: "easeOut" }}
          className="font-playfair font-bold text-ink leading-[0.92] mb-4"
          style={{ fontSize: "clamp(2.4rem, 5.5vw, 4.2rem)" }}
        >
          How We Built Varaksha
          <br className="hidden md:block" />
          in 11 Days
        </motion.h1>

        <motion.p
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.18, duration: 0.5 }}
          className="font-barlow text-[0.8rem] text-ink/45 max-w-xl leading-relaxed mb-8"
        >
          A two-person sprint reconstructed phase by phase. Security architecture in pink,
          machine learning in blue, joint efforts in gradient.
        </motion.p>

        {/* Legend */}
        <motion.div
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.26 }}
          className="flex flex-wrap items-center gap-6"
        >
          {(["sec", "ml", "both"] as Owner[]).map((o) => {
            const color = o === "sec" ? SEC_C : ML_C;
            const grad  = cGrad(o);
            return (
              <div key={o} className="flex items-center gap-2">
                <div
                  className="w-3 h-3 rounded-full shrink-0"
                  style={grad ? { backgroundImage: grad } : { backgroundColor: color }}
                />
                <span className="font-barlow text-[0.62rem] tracking-[0.2em] uppercase text-ink/55">
                  {cLabel(o)}
                </span>
              </div>
            );
          })}
        </motion.div>
      </section>

      {/* ── Timeline ───────────────────────────────────────────────────── */}
      <section className="px-4 lg:px-12 max-w-5xl mx-auto">
        <div className="relative">

          {/* Background spine — desktop only */}
          <div
            className="absolute top-2 bottom-2 w-px bg-ink/10 hidden lg:block"
            style={{ left: "50%" }}
          />

          {/* ── Mobile: single column with left spine ── */}
          <div className="lg:hidden space-y-6">
            {EVENTS.map((ev, i) => (
              <div key={i} className="relative pl-8">
                {/* Mobile left-spine segment */}
                <div
                  className="absolute left-0 top-0 bottom-0 w-px"
                  style={{
                    backgroundImage: cGrad(ev.owner) ?? `linear-gradient(to bottom, ${
                      i > 0 ? cColor(EVENTS[i - 1].owner) : "transparent"
                    }, ${cColor(ev.owner)})`,
                    opacity: 0.4,
                  }}
                />
                {/* Mobile spine node */}
                <div className="absolute left-[-8px] top-5">
                  <SpineNode owner={ev.owner} />
                </div>
                <EventCard ev={ev} side="center" />
              </div>
            ))}
          </div>

          {/* ── Desktop: two-column alternating ── */}
          <div className="hidden lg:block">
            {EVENTS.map((ev, i) => {
              const isBoth = ev.owner === "both";

              return (
                <motion.div
                  key={i}
                  className="relative mb-10"
                  initial={{ opacity: 0 }}
                  whileInView={{ opacity: 1 }}
                  viewport={{ once: true, margin: "-60px" }}
                  transition={{ duration: 0.3 }}
                >
                  {/* Colored spine segment — from prev event node down to this node */}
                  {i > 0 && (
                    <div
                      className="absolute w-px"
                      style={{
                        left: "50%",
                        top: -40,
                        height: 40,
                        backgroundImage: cGrad(ev.owner) ?? `linear-gradient(to bottom, ${cColor(EVENTS[i - 1].owner)}40, ${cColor(ev.owner)}40)`,
                      }}
                    />
                  )}

                  {/* Spine node — centered */}
                  <div
                    className="absolute z-10 flex items-center justify-center"
                    style={{ left: "calc(50% - 10px)", top: isBoth ? 20 : 20 }}
                  >
                    <SpineNode owner={ev.owner} />
                  </div>

                  {isBoth ? (
                    /* ── Joint event: centered card ── */
                    <div className="flex items-start justify-center pt-2">
                      <div className="w-[min(480px,42%)]">
                        <EventCard ev={ev} side="center" />
                      </div>
                    </div>
                  ) : ev.owner === "sec" ? (
                    /* ── Security event: left side ── */
                    <div className="flex items-start pt-2">
                      <div className="flex-1 flex justify-end">
                        <div className="w-[92%]">
                          <EventCard ev={ev} side="left" />
                        </div>
                      </div>
                      <Arm owner={ev.owner} side="left" />
                      {/* Node placeholder */}
                      <div className="w-5 shrink-0" />
                      <Arm owner={ev.owner} side="right" />
                      <div className="flex-1" />
                    </div>
                  ) : (
                    /* ── ML event: right side ── */
                    <div className="flex items-start pt-2">
                      <div className="flex-1" />
                      <Arm owner={ev.owner} side="left" />
                      {/* Node placeholder */}
                      <div className="w-5 shrink-0" />
                      <Arm owner={ev.owner} side="right" />
                      <div className="flex-1 flex justify-start">
                        <div className="w-[92%]">
                          <EventCard ev={ev} side="right" />
                        </div>
                      </div>
                    </div>
                  )}
                </motion.div>
              );
            })}
          </div>

        </div>
      </section>

      {/* ── Footer stamp ─────────────────────────────────────────────── */}
      <div className="mt-20 flex flex-col items-center gap-3 px-6">
        <div
          className="w-px h-12"
          style={{ backgroundImage: `linear-gradient(to bottom, ${SEC_C}, ${ML_C})` }}
        />
        <div
          className="px-5 py-2 font-courier text-[0.6rem] tracking-[0.3em] uppercase"
          style={{
            border: "1px solid",
            borderImageSlice: 1,
            borderImageSource: `linear-gradient(135deg, ${SEC_C}, ${ML_C})`,
            backgroundImage: `linear-gradient(135deg, ${SEC_C}08, ${ML_C}08)`,
            color: "transparent",
            backgroundClip: "text",
            WebkitBackgroundClip: "text",
            WebkitTextFillColor: "transparent",
          }}
        >
          Varaksha · 11 days · 2 people · shipped
        </div>
      </div>

    </main>
  );
}
