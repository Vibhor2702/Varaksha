"use client";

import { useRef } from "react";
import {
  motion,
  useScroll,
  useTransform,
  useInView,
} from "framer-motion";
import {
  Lightbulb,
  ShieldCheck,
  BrainCircuit,
  GitBranch,
  MessageCircle,
  BarChart2,
  RefreshCw,
  Globe,
  SearchCode,
  Zap,
  Rocket,
  type LucideIcon,
} from "lucide-react";

// ── Palette ───────────────────────────────────────────────────────────────────
const PINK = "#EC4899";
const BLUE = "#2563EB";

type Owner = "sec" | "ml" | "both";

const LABEL: Record<Owner, string> = {
  sec:  "Security",
  ml:   "ML",
  both: "Together",
};

function ownerColor(o: Owner) {
  return o === "sec" ? PINK : BLUE;
}

// ── Milestone data ────────────────────────────────────────────────────────────
interface Milestone {
  date:  string;
  title: string;
  quote: string;
  body:  string;
  tags:  string[];
  owner: Owner;
  Icon:  LucideIcon;
}

const MILESTONES: Milestone[] = [
  {
    date:  "Feb 28",
    title: "The Reboot",
    quote: "V1 passed every test. It was also impossible to demo.",
    body:  "We audited V1 together — PyO3 bindings, a kernel monitor, six agents, twelve setup steps. All of it worked. None of it was showable in thirty seconds. We made the call: branch test, five focused layers, plain JSON between them. V1 stays on main as proof of depth. V2 is for the room.",
    tags:  ["Architecture", "Decision Day", "V1 Audit"],
    owner: "both",
    Icon:  Lightbulb,
  },
  {
    date:  "Mar 1",
    title: "A Privacy Chokepoint in Rust",
    quote: "Raw UPI IDs are toxic data. They should not survive past the front door.",
    body:  "Built the Actix-Web gateway as the single process that ever sees raw VPAs. SHA-256 on entry — everything downstream works with hashes. DashMap for the lock-free concurrent risk cache. Three endpoints wired, score_to_verdict() thresholds set, every TODO comment has exact implementation steps for whoever fills in the cache methods.",
    tags:  ["Rust", "SHA-256", "DashMap", "Actix-Web 4"],
    owner: "sec",
    Icon:  ShieldCheck,
  },
  {
    date:  "Mar 1",
    title: "Teaching the Model",
    quote: "Start with something that trains. We can sharpen it later.",
    body:  "First cut: RandomForest and XGBoost in a soft-vote ensemble, eight engineered features — transaction velocity, round-amount flag, out-degree, hour sinusoid. SMOTE before the split, always. PaySim 50K stratified. It trained. Numbers looked reasonable. Moved on.",
    tags:  ["RF + XGBoost", "SMOTE", "8 features", "PaySim"],
    owner: "ml",
    Icon:  BrainCircuit,
  },
  {
    date:  "Mar 2",
    title: "Following the Money Graph",
    quote: "Fan-out is the tell. Every mule ring looks the same once you see the shape.",
    body:  "Wired the NetworkX agent completely off the payment path — heavy graph traversal must never block a /v1/tx response. Four BIS typologies detected: fan-out, fan-in, directed cycles, scatter. Switched score aggregation from sum to max after sum false-flagged legitimate high-volume merchants. HMAC-signed webhook pushes result to the Rust cache.",
    tags:  ["NetworkX", "Fan-out", "Cycles", "Async", "HMAC-SHA256"],
    owner: "sec",
    Icon:  GitBranch,
  },
  {
    date:  "Mar 2-3",
    title: "Alerts That Actually Reach People",
    quote: "If the alert goes out in English, 44% of India cannot act on it.",
    body:  "Alert agent built with zero hard dependencies — deterministic Hindi templates, no LLM, no API key required. Edge-tts for free neural TTS. Googletrans covers all 22 scheduled Indian languages. BLOCK verdicts cite IT Act 2000 and BNSS by design — the legal framing matters. Falls back gracefully to plain text on base Python.",
    tags:  ["Hindi TTS", "22 languages", "IT Act", "edge-tts"],
    owner: "sec",
    Icon:  MessageCircle,
  },
  {
    date:  "Mar 3",
    title: "First Time it Felt Real",
    quote: "Watching fake transactions scroll by with real verdict colours — that is when it clicked.",
    body:  "Streamlit dashboard as local proof-of-life: auto-refreshing ALLOW / FLAG / BLOCK feed, Plotly Scattergl transaction network, Hindi alert panel, audit log of the last 50. One command. Zero real PII — every VPA synthetic from a seeded RNG. Rough, but alive.",
    tags:  ["Streamlit", "Plotly", "Live Feed", "Zero PII"],
    owner: "both",
    Icon:  BarChart2,
  },
  {
    date:  "Mar 5-7",
    title: "The Big Model Refactor",
    quote: "RF and XGBoost together hit 450 MB at inference. We only had 512. XGBoost had to go.",
    body:  "Dropped XGBoost from the serving stack — RF-300 alone reaches ROC-AUC 0.9869, the marginal gain from the ensemble was under 0.005 on this dataset family. Expanded features from 8 to 16. Seven dataset loaders merged 75,358 real rows. Output: varaksha_rf_model.onnx. The model finally felt like it was trained on something.",
    tags:  ["RF-300 only", "16 features", "75K rows", "ONNX", "0.9869 AUC"],
    owner: "ml",
    Icon:  RefreshCw,
  },
  {
    date:  "Mar 9-10",
    title: "Shipped to the Web",
    quote: "Static export to Cloudflare Pages. Zero cold starts. No excuses for a slow demo.",
    body:  "Next.js 15 with output export — no Node server, no spin-up time, global edge delivery. Three routes: landing metrics, animated 5-layer walkthrough, real-time transaction feed with Security Arena and Cache Visualizer. First deploy live the night before the final sprint.",
    tags:  ["Next.js 15", "Cloudflare Pages", "framer-motion", "3 routes"],
    owner: "both",
    Icon:  Globe,
  },
  {
    date:  "Mar 11 AM",
    title: "Three Datasets Were Sitting Right There",
    quote: "The file timestamps do not lie. Those models were never trained on the full set.",
    body:  "Audited data/datasets/ — 10 CSV files, but only 7 had loaders. supervised_dataset.csv (1,699 rows), remaining_behavior_ext.csv (34,423 rows), ton-iot.csv — all ignored. Timestamps on the ONNX files confirmed they predated the Phase 6 additions. Three new loaders written, wired in, merged.",
    tags:  ["Data Audit", "34K rows found", "3 missing loaders", "stale timestamps"],
    owner: "ml",
    Icon:  SearchCode,
  },
  {
    date:  "Mar 11 PM",
    title: "96.52%",
    quote: "I ran the eval three times. The number kept coming back.",
    body:  "Retrained on 111,499 merged rows. SMOTE to 50/50. RF Accuracy 96.52% — up 2.1 points. ROC-AUC 0.9952. Fraud F1 0.9579. Cleaned out the ghost artifacts after: lightgbm, xgboost, voting_ensemble — none of them were ever loaded at inference. Just noise.",
    tags:  ["111K rows", "96.52%", "ROC-AUC 0.9952", "Ghost cleanup"],
    owner: "ml",
    Icon:  Zap,
  },
  {
    date:  "Mar 11",
    title: "Polish, Transfer, Ship",
    quote: "The gap between done and shipped is the finishing touches. They always matter.",
    body:  "Dot-grid body texture, surface-card gradient utility, nav shadow. Amber (#D97706) split from the blue accent for FLAG verdicts — the colour finally reads as a warning. Repo transferred to the Varaksha-G org. Cloudflare project recreated. Docs updated. Timeline page added. That was it.",
    tags:  ["Texture", "Amber FLAG", "Varaksha-G org", "Cloudflare"],
    owner: "both",
    Icon:  Rocket,
  },
];

// ── Chip (owner label) ────────────────────────────────────────────────────────
function Chip({ owner }: { owner: Owner }) {
  if (owner === "both") {
    return (
      <div className="flex items-center gap-1.5">
        <span className="inline-block w-2 h-2 rounded-full" style={{ backgroundColor: PINK }} />
        <span
          className="font-barlow text-[0.5rem] tracking-[0.22em] uppercase"
          style={{
            backgroundImage: `linear-gradient(90deg, ${PINK}, ${BLUE})`,
            WebkitBackgroundClip: "text",
            color: "transparent",
          }}
        >
          Together
        </span>
        <span className="inline-block w-2 h-2 rounded-full" style={{ backgroundColor: BLUE }} />
      </div>
    );
  }
  const color = ownerColor(owner);
  return (
    <div className="flex items-center gap-1.5">
      <span className="inline-block w-2 h-2 rounded-full" style={{ backgroundColor: color }} />
      <span className="font-barlow text-[0.5rem] tracking-[0.22em] uppercase" style={{ color }}>
        {LABEL[owner]}
      </span>
    </div>
  );
}

// ── Spine node ────────────────────────────────────────────────────────────────
function SpineNode({ ms }: { ms: Milestone }) {
  const color = ms.owner === "both" ? PINK : ownerColor(ms.owner);
  return (
    <div className="relative flex items-center justify-center w-10 h-10 shrink-0">
      <motion.span
        className="absolute inset-0 rounded-full"
        style={{ border: `1px solid ${color}`, opacity: 0.3 }}
        animate={{ scale: [1, 1.75, 1], opacity: [0.3, 0, 0.3] }}
        transition={{ duration: 3, repeat: Infinity, ease: "easeOut" }}
      />
      <div
        className="relative z-10 w-8 h-8 rounded-full flex items-center justify-center"
        style={{ backgroundColor: `${color}12`, border: `1px solid ${color}30` }}
      >
        <ms.Icon size={14} style={{ color }} />
      </div>
    </div>
  );
}

// ── Milestone card ────────────────────────────────────────────────────────────
function Card({ ms, side }: { ms: Milestone; side: "left" | "right" | "center" }) {
  const ref    = useRef<HTMLDivElement>(null);
  const inView = useInView(ref, { once: true, margin: "-80px 0px 0px 0px" });
  const color  = ms.owner === "sec" ? PINK : BLUE;
  const isBoth = ms.owner === "both";
  const initX  = side === "left" ? -28 : side === "right" ? 28 : 0;

  return (
    <motion.div
      ref={ref}
      initial={{ opacity: 0, x: initX, y: 10 }}
      animate={inView ? { opacity: 1, x: 0, y: 0 } : {}}
      transition={{ duration: 0.6, ease: [0.22, 1, 0.36, 1] }}
      className="group"
    >
      <div
        className="h-[2px] mb-0 rounded-full"
        style={
          isBoth
            ? { backgroundImage: `linear-gradient(90deg, ${PINK}, ${BLUE})` }
            : { backgroundColor: color, opacity: 0.65 }
        }
      />
      <div className="bg-white/55 backdrop-blur-sm px-5 py-5 lg:px-6 lg:py-6 transition-shadow duration-300 group-hover:shadow-[0_4px_24px_rgba(15,30,46,0.07)]">
        <div className="flex items-start justify-between gap-4 mb-3">
          <Chip owner={ms.owner} />
          <span className="font-courier text-[0.48rem] tracking-[0.18em] text-ink/25 whitespace-nowrap pt-px">
            {ms.date}
          </span>
        </div>
        <h3
          className="font-playfair font-bold text-ink leading-tight mb-3"
          style={{ fontSize: "clamp(1.05rem, 2vw, 1.25rem)" }}
        >
          {ms.title}
        </h3>
        <p
          className="font-playfair italic leading-snug mb-3"
          style={{ fontSize: "0.8rem", color: isBoth ? PINK : color, opacity: 0.85 }}
        >
          &ldquo;{ms.quote}&rdquo;
        </p>
        <p className="font-barlow text-[0.71rem] text-ink/48 leading-relaxed mb-4">
          {ms.body}
        </p>
        <div className="flex flex-wrap gap-1.5">
          {ms.tags.map((t, i) => (
            <span
              key={i}
              className="font-courier text-[0.45rem] tracking-widest uppercase px-2 py-0.5 rounded-full"
              style={{
                color:           isBoth ? "#6b7280" : color,
                backgroundColor: isBoth ? "rgba(0,0,0,0.03)" : `${color}0c`,
                border:          `1px solid ${isBoth ? "rgba(0,0,0,0.07)" : `${color}1f`}`,
              }}
            >
              {t}
            </span>
          ))}
        </div>
      </div>
    </motion.div>
  );
}

// ── Thin connector (spine node to card) ──────────────────────────────────────
function Connector({ ms }: { ms: Milestone }) {
  const color = ms.owner === "sec" ? PINK : BLUE;
  return (
    <div
      className="hidden lg:block self-center h-px shrink-0 w-8"
      style={{ backgroundColor: color, opacity: 0.18 }}
    />
  );
}

// ── Page ──────────────────────────────────────────────────────────────────────
export default function TimelinePage() {
  const containerRef = useRef<HTMLDivElement>(null);
  const { scrollYProgress } = useScroll({
    target:  containerRef,
    offset:  ["start 15%", "end 85%"],
  });
  const lineScaleY = useTransform(scrollYProgress, [0, 1], [0, 1]);

  return (
    <main className="min-h-screen bg-cream text-ink pb-32">

      {/* breadcrumb */}
      <header className="border-b border-ink/10 px-6 lg:px-12 py-2.5">
        <div className="max-w-7xl mx-auto flex items-center gap-3">
          <a
            href="/"
            className="font-barlow text-[0.58rem] tracking-[0.24em] uppercase text-ink/30 hover:text-saffron transition-colors"
          >
            &larr;&thinsp;Varaksha
          </a>
          <span className="text-ink/15 select-none">|</span>
          <span className="font-barlow text-[0.58rem] tracking-[0.24em] uppercase text-ink/30">
            Build Timeline
          </span>
        </div>
      </header>

      {/* Hero */}
      <section className="px-6 lg:px-12 pt-14 pb-12 max-w-5xl mx-auto">
        <motion.p
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.5 }}
          className="font-barlow text-[0.65rem] tracking-[0.36em] uppercase mb-5"
          style={{
            backgroundImage: `linear-gradient(90deg, ${PINK}, ${BLUE})`,
            WebkitBackgroundClip: "text",
            color: "transparent",
            display: "inline-block",
          }}
        >
          Feb 28 &ndash; Mar 11, 2026 &middot; 11 days
        </motion.p>

        <motion.h1
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.08, duration: 0.6, ease: "easeOut" }}
          className="font-playfair font-bold text-ink leading-[0.9] mb-5"
          style={{ fontSize: "clamp(2.4rem, 5.5vw, 4.2rem)" }}
        >
          How We Built<br />Varaksha in a Sprint
        </motion.h1>

        <motion.p
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.2 }}
          className="font-barlow text-[0.78rem] text-ink/42 leading-relaxed max-w-md mb-9"
        >
          A sprint diary from two people working on different halves of the same problem.
          Security architecture in pink. Machine learning in blue.
          Shared decisions in gradient.
        </motion.p>

        {/* Legend */}
        <motion.div
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
          className="flex flex-wrap items-center gap-6"
        >
          {[
            { label: "Security Expert", color: PINK },
            { label: "ML Expert",       color: BLUE },
          ].map(({ label, color }) => (
            <div key={label} className="flex items-center gap-2.5">
              <div className="w-7 h-[2px] rounded-full" style={{ backgroundColor: color }} />
              <span className="font-barlow text-[0.6rem] tracking-[0.2em] uppercase text-ink/42">
                {label}
              </span>
            </div>
          ))}
          <div className="flex items-center gap-2.5">
            <div
              className="w-7 h-[2px] rounded-full"
              style={{ backgroundImage: `linear-gradient(90deg, ${PINK}, ${BLUE})` }}
            />
            <span className="font-barlow text-[0.6rem] tracking-[0.2em] uppercase text-ink/42">
              Together
            </span>
          </div>
        </motion.div>
      </section>

      {/* Timeline */}
      <section ref={containerRef} className="px-4 lg:px-12 max-w-5xl mx-auto relative">

        {/* Animated spine — desktop */}
        <div
          className="absolute top-0 bottom-0 hidden lg:block overflow-hidden"
          style={{ left: "50%", width: 1, transform: "translateX(-0.5px)" }}
        >
          <div className="absolute inset-0 bg-ink/8" />
          <motion.div
            className="absolute inset-x-0 top-0 origin-top"
            style={{
              scaleY: lineScaleY,
              backgroundImage: `linear-gradient(to bottom, ${PINK}, #9333ea 45%, ${BLUE})`,
              height: "100%",
            }}
          />
        </div>

        {/* Left spine — mobile */}
        <div
          className="absolute top-0 bottom-0 lg:hidden"
          style={{ left: 18, width: 1, backgroundColor: "rgba(15,30,46,0.08)" }}
        />

        <div className="space-y-0">
          {MILESTONES.map((ms, i) => {
            const isBoth = ms.owner === "both";
            const isSec  = ms.owner === "sec";
            return (
              <div key={i} className="relative">

                {/* Mobile layout */}
                <div className="lg:hidden flex items-start gap-4 pl-10 pb-10">
                  <div className="absolute left-[3px] top-0">
                    <SpineNode ms={ms} />
                  </div>
                  <Card ms={ms} side="center" />
                </div>

                {/* Desktop alternating */}
                {isBoth ? (
                  <div className="hidden lg:flex items-center justify-center py-8">
                    <div className="w-[min(460px,46%)] flex flex-col items-center gap-2">
                      <SpineNode ms={ms} />
                      <Card ms={ms} side="center" />
                    </div>
                  </div>
                ) : isSec ? (
                  <div className="hidden lg:flex items-center py-8">
                    <div className="flex-1 flex justify-end pr-1">
                      <div className="w-[92%]"><Card ms={ms} side="left" /></div>
                    </div>
                    <Connector ms={ms} />
                    <SpineNode ms={ms} />
                    <Connector ms={ms} />
                    <div className="flex-1" />
                  </div>
                ) : (
                  <div className="hidden lg:flex items-center py-8">
                    <div className="flex-1" />
                    <Connector ms={ms} />
                    <SpineNode ms={ms} />
                    <Connector ms={ms} />
                    <div className="flex-1 flex justify-start pl-1">
                      <div className="w-[92%]"><Card ms={ms} side="right" /></div>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </section>

      {/* Footer */}
      <motion.div
        initial={{ opacity: 0, y: 16 }}
        whileInView={{ opacity: 1, y: 0 }}
        viewport={{ once: true }}
        transition={{ duration: 0.55 }}
        className="mt-16 flex flex-col items-center gap-4 px-6"
      >
        <div
          className="w-px h-16"
          style={{ backgroundImage: `linear-gradient(to bottom, ${BLUE}, ${PINK})` }}
        />
        <p
          className="font-playfair italic text-[0.9rem] text-center"
          style={{
            backgroundImage: `linear-gradient(90deg, ${PINK}, ${BLUE})`,
            WebkitBackgroundClip: "text",
            color: "transparent",
          }}
        >
          11 days &middot; 2 people &middot; shipped.
        </p>
      </motion.div>

    </main>
  );
}
