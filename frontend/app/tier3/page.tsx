"use client";

import { Tier3EdgeSim } from "../components/Tier3EdgeSim";

export default function Tier3Page() {
  return (
    <main className="min-h-screen bg-ink text-cream">
      <div className="max-w-7xl mx-auto px-6 lg:px-12 py-10 space-y-6">
        <div>
          <p className="font-barlow text-[0.62rem] tracking-[0.3em] uppercase text-saffron mb-2">
            Tier 3 · On-Device Shield
          </p>
          <h1 className="font-playfair font-bold text-[2rem] lg:text-[2.8rem] leading-tight">
            Edge Security Simulation
          </h1>
          <p className="font-barlow text-cream/60 text-[0.86rem] mt-2 max-w-3xl">
            This module represents pre-network fraud evaluation inside the mobile app runtime.
          </p>
        </div>
        <Tier3EdgeSim />
      </div>
    </main>
  );
}
