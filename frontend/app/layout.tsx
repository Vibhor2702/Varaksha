import type { Metadata } from "next";
import { Playfair_Display, Barlow, Courier_Prime } from "next/font/google";
import Link from "next/link";
import "./globals.css";

// ── Font Definitions ──────────────────────────────────────────────────────────
// Each font is assigned a CSS custom property (variable) that Tailwind picks
// up via fontFamily in tailwind.config.ts.

const playfairDisplay = Playfair_Display({
  subsets: ["latin"],
  weight: ["400", "700", "900"],
  style: ["normal", "italic"],
  variable: "--font-playfair",
  display: "swap",
});

const barlow = Barlow({
  subsets: ["latin"],
  weight: ["400", "500", "600", "700"],
  style: ["normal"],
  variable: "--font-barlow",
  display: "swap",
});

const courierPrime = Courier_Prime({
  subsets: ["latin"],
  weight: ["400", "700"],
  style: ["normal"],
  variable: "--font-courier",
  display: "swap",
});

// ── Metadata ──────────────────────────────────────────────────────────────────
export const metadata: Metadata = {
  title: "Varaksha — UPI Fraud Defense Network",
  description:
    "Privacy-preserving collaborative UPI fraud intelligence. " +
    "Rust gateway delivers ALLOW / FLAG / BLOCK verdicts in <10ms, " +
    "decoupled from the heavy ML ensemble and graph traversal off the critical path.",
};

// ── Root Layout ───────────────────────────────────────────────────────────────
export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html
      lang="en"
      className={`
        ${playfairDisplay.variable}
        ${barlow.variable}
        ${courierPrime.variable}
      `}
    >
      {/*
       * font-barlow  → body copy
       * bg-cream     → #F0F4F8 cold off-white base
       * text-ink     → #0F1E2E deep navy
       * antialiased  → subpixel rendering
       */}
      <body className="bg-cream text-ink font-barlow antialiased">
        {/* ── Site-wide navigation ── */}
        <nav className="sticky top-0 z-50 border-b border-white/40 bg-white/25 backdrop-blur-xl shadow-[0_2px_32px_rgba(15,30,46,0.10),inset_0_1px_0_rgba(255,255,255,0.6)]">
          <div className="max-w-7xl mx-auto px-6 lg:px-12 flex items-center justify-between h-11">
            <Link
              href="/"
              className="font-playfair font-bold text-[1.05rem] text-ink tracking-tight hover:text-saffron transition-colors"
            >
              Varaksha<span className="text-saffron">.</span>
            </Link>
            <div className="flex items-center gap-1">
              {(
                [
                  { href: "/",        label: "Overview"     },
                  { href: "/flow",    label: "How It Works" },
                  { href: "/timeline",label: "Timeline"     },
                ] as const
              ).map(({ href, label }) => (
                <Link
                  key={href}
                  href={href}
                  className="group relative font-barlow text-[0.65rem] tracking-[0.22em] uppercase text-ink/50 hover:text-ink px-3 py-1.5 rounded-sm cursor-pointer transition-all duration-200 hover:bg-ink/[0.06] active:scale-95"
                >
                  {label}
                  {/* animated underline */}
                  <span className="absolute bottom-0.5 left-3 right-3 h-px bg-ink/30 scale-x-0 group-hover:scale-x-100 transition-transform duration-200 origin-left" />
                </Link>
              ))}

              {/* Live Demo — blinking green */}
              <Link
                href="/live"
                className="ml-3 flex items-center gap-2 font-barlow text-[0.65rem] tracking-[0.22em] uppercase bg-ink text-cream px-3 py-1.5 rounded-sm cursor-pointer hover:bg-ink/80 active:scale-95 transition-all duration-200 shadow-[0_2px_12px_rgba(15,30,46,0.25)] hover:shadow-[0_4px_20px_rgba(15,30,46,0.35)]"
              >
                {/* pulse dot */}
                <span className="relative flex h-2 w-2 shrink-0">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-80" />
                  <span className="relative inline-flex rounded-full h-2 w-2 bg-green-400" />
                </span>
                Live Demo
              </Link>
            </div>
          </div>
        </nav>
        {children}
      </body>
    </html>
  );
}
