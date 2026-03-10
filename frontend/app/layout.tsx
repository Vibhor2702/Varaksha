import type { Metadata } from "next";
import { Playfair_Display, Barlow, Courier_Prime } from "next/font/google";
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
  title: "Varaksha V2 — UPI Fraud Defense Network",
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
       * bg-cream     → #F7F2E8 parchment base
       * text-ink     → #1C1610 near-black
       * antialiased  → subpixel rendering
       */}
      <body className="bg-cream text-ink font-barlow antialiased">
        {children}
      </body>
    </html>
  );
}
