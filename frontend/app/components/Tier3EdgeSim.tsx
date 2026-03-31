"use client";

import { useMemo, useState } from "react";

type Stage = "idle" | "verifying" | "allow" | "block";

function isLocallyBlocked(amount: number, vpa: string, hour: number, clipboardHint: string): boolean {
  const v = vpa.toLowerCase();
  const riskyReceiver = v.includes("cash") || v.includes("agent") || v.includes("crypto") || v.includes("wallet");
  const oddHour = hour <= 5 || hour >= 23;
  const suspiciousClipboard = clipboardHint.length >= 10;
  return amount >= 50000 || (riskyReceiver && amount >= 15000) || (oddHour && amount >= 12000) || suspiciousClipboard;
}

export function Tier3EdgeSim() {
  const [receiver, setReceiver] = useState("cash.agent.77@paytm");
  const [amount, setAmount] = useState("29999");
  const [stage, setStage] = useState<Stage>("idle");
  const [resultMsg, setResultMsg] = useState("");

  const localHour = useMemo(() => new Date().getHours(), []);

  const onPay = async () => {
    if (stage === "verifying") return;
    setStage("verifying");
    setResultMsg("Verifying Locally...");

    let clip = "";
    try {
      clip = await navigator.clipboard.readText();
    } catch {
      clip = "";
    }

    const amt = Number(amount) || 0;
    const blocked = isLocallyBlocked(amt, receiver, localHour, clip);

    window.setTimeout(() => {
      if (blocked) {
        setStage("block");
        setResultMsg("Locally Blocked: Threat Signature Detected");
      } else {
        setStage("allow");
        setResultMsg("Local Check Passed: Safe to proceed");
      }
    }, 920);
  };

  return (
    <section className="border border-cream/[0.08] bg-ink text-cream overflow-hidden">
      <div className="px-5 py-3 border-b border-cream/[0.08] flex items-center justify-between">
        <span className="font-barlow text-[0.58rem] tracking-[0.28em] uppercase text-cream/45">
          Tier 3 Edge Simulation
        </span>
        <span className="font-courier text-[0.54rem] text-cream/28">On-device pre-network defense</span>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-[380px_1fr] gap-6 p-5">
        <div className="mx-auto w-full max-w-[360px]">
          <div className="relative aspect-[9/16] rounded-[2rem] border-[7px] border-cream/20 bg-[#0a1626] shadow-[0_10px_40px_rgba(0,0,0,0.5)] overflow-hidden">
            <div className="absolute top-0 left-1/2 -translate-x-1/2 w-32 h-5 rounded-b-xl bg-black/45" />
            <div className="px-4 pt-7 pb-4 h-full flex flex-col">
              <p className="font-barlow text-[0.52rem] tracking-[0.26em] uppercase text-cream/30 mb-3">UPI Payment</p>

              <label className="font-barlow text-[0.55rem] text-cream/45 mb-1">Receiver VPA</label>
              <input
                value={receiver}
                onChange={(e) => setReceiver(e.target.value)}
                className="font-courier text-[0.72rem] bg-cream/[0.06] border border-cream/[0.16] px-2.5 py-2 mb-3"
              />

              <label className="font-barlow text-[0.55rem] text-cream/45 mb-1">Amount (INR)</label>
              <input
                value={amount}
                onChange={(e) => setAmount(e.target.value)}
                className="font-courier text-[0.9rem] bg-cream/[0.06] border border-cream/[0.16] px-2.5 py-2 mb-4"
              />

              <button
                onClick={onPay}
                disabled={stage === "verifying"}
                className="mt-auto bg-saffron hover:bg-saffron/85 disabled:opacity-60 text-cream font-barlow text-[0.72rem] tracking-[0.18em] uppercase py-3"
              >
                Pay
              </button>
            </div>

            {stage !== "idle" && (
              <div className="absolute inset-0 bg-black/58 backdrop-blur-[1px] flex items-center justify-center p-4 text-center">
                <div
                  className={`border px-4 py-5 ${
                    stage === "block"
                      ? "border-block/40 bg-block/10"
                      : stage === "allow"
                      ? "border-allow/40 bg-allow/10"
                      : "border-saffron/40 bg-saffron/10"
                  }`}
                >
                  <p className="font-courier text-[0.95rem] mb-1">
                    {stage === "block" ? "X" : stage === "allow" ? "OK" : "..."}
                  </p>
                  <p className="font-barlow text-[0.72rem] leading-relaxed">{resultMsg}</p>
                </div>
              </div>
            )}
          </div>
        </div>

        <div className="border border-cream/[0.08] bg-black/20 p-4">
          <p className="font-barlow text-[0.56rem] tracking-[0.28em] uppercase text-cream/35 mb-3">
            How It Is Packed (Tier 3)
          </p>

          <div className="font-courier text-[0.66rem] text-cream/65 leading-[1.6] space-y-2">
            <p>&gt; Model Packaging: Quantized ONNX-exported Random Forest</p>
            <p>&gt; Bundle Size: &lt; 5MB compressed model artifact</p>
            <p>&gt; Deployment: Packed inside iOS/Android app bundle via ONNX Runtime Mobile (native C++)</p>
            <p>&gt; Advantage: Zero-latency, offline-capable anomaly detection without server round-trip</p>
          </div>

          <div className="mt-4 border-t border-cream/[0.08] pt-3">
            <p className="font-barlow text-[0.7rem] text-cream/60 mb-1">Local checks in simulation:</p>
            <ul className="font-barlow text-[0.66rem] text-cream/45 leading-[1.6]">
              <li>Device velocity heuristic</li>
              <li>Unusual time-of-day trigger</li>
              <li>Clipboard anomaly hint</li>
              <li>Receiver-risk signature check</li>
            </ul>
          </div>
        </div>
      </div>
    </section>
  );
}
