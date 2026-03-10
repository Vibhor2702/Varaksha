import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./components/**/*.{js,ts,jsx,tsx,mdx}",
    "./app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      // ── Brand Colors ──────────────────────────────────────
      // Cream (#F7F2E8): page background
      // Ink  (#1C1610): primary text & dark surfaces
      // Saffron (#D4500A): accent / primary action
      // Allow (#2D7A3E): verdict green
      // Block (#C0392B): verdict red
      colors: {
        cream: "#F7F2E8",
        ink: "#1C1610",
        saffron: "#D4500A",
        allow: "#2D7A3E",
        block: "#C0392B",
      },

      // ── Brand Typefaces ───────────────────────────────────
      // Injected as CSS custom properties by next/font in layout.tsx
      fontFamily: {
        playfair: ["var(--font-playfair)", "Georgia", "serif"],
        barlow: ["var(--font-barlow)", "system-ui", "sans-serif"],
        courier: ["var(--font-courier)", "Courier New", "monospace"],
      },
    },
  },
  plugins: [],
};

export default config;
