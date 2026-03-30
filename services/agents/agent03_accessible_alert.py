#!/usr/bin/env python3
"""
Varaksha L4 — Multilingual Accessible Alert Agent
services/agents/agent03_accessible_alert.py

Generates human-readable fraud alerts in 8 Indian languages with
neural text-to-speech audio via Microsoft edge-tts.

Design principles:
  - Deterministic template narration — no LLM, fully auditable.
  - Translation via googletrans (no API key required).
  - Audio synthesis via edge-tts Neural voices (offline-capable after first use).
  - Pre-generated MP3s served as static assets — zero inference latency.

Supported languages and Neural voices:
  en  English   en-IN-NeerjaNeural
  hi  Hindi     hi-IN-SwaraNeural
  ta  Tamil     ta-IN-PallaviNeural
  te  Telugu    te-IN-ShrutiNeural
  bn  Bengali   bn-IN-TanishaaNeural
  mr  Marathi   mr-IN-AarohiNeural
  gu  Gujarati  gu-IN-DhwaniNeural
  kn  Kannada   kn-IN-SapnaNeural

CLI usage:
  # Generate alert for a single verdict
  python -m services.agents.agent03_accessible_alert \\
    --verdict '{"verdict":"BLOCK","amount":5000,"merchant":"XYZ Store","reason":"fan_in mule ring detected"}' \\
    --output-dir services/agents/static/alerts/

  # Pre-generate representative static assets (16 MP3s: BLOCK+FLAG × 8 languages)
  python -m services.agents.agent03_accessible_alert \\
    --pregenerate --output-dir services/agents/static/alerts/
"""

from __future__ import annotations

import argparse
import asyncio
import json
import re
import time
from pathlib import Path
from typing import Any, Dict, Optional

# ---------------------------------------------------------------------------
# Language / voice registry
# ---------------------------------------------------------------------------

LANGUAGES: Dict[str, Dict[str, str]] = {
    "en": {"name": "English",  "voice": "en-IN-NeerjaNeural",  "googletrans_code": "en"},
    "hi": {"name": "Hindi",    "voice": "hi-IN-SwaraNeural",   "googletrans_code": "hi"},
    "ta": {"name": "Tamil",    "voice": "ta-IN-PallaviNeural", "googletrans_code": "ta"},
    "te": {"name": "Telugu",   "voice": "te-IN-ShrutiNeural",  "googletrans_code": "te"},
    "bn": {"name": "Bengali",  "voice": "bn-IN-TanishaaNeural","googletrans_code": "bn"},
    "mr": {"name": "Marathi",  "voice": "mr-IN-AarohiNeural",  "googletrans_code": "mr"},
    "gu": {"name": "Gujarati", "voice": "gu-IN-DhwaniNeural",  "googletrans_code": "gu"},
    "kn": {"name": "Kannada",  "voice": "kn-IN-SapnaNeural",   "googletrans_code": "kn"},
}

# ---------------------------------------------------------------------------
# Narration templates
# ---------------------------------------------------------------------------

BLOCK_TEMPLATE = (
    "Warning: Varaksha Alert. Transaction of {amount} rupees to {merchant} "
    "has been BLOCKED. Reason: {reason}. "
    "This may constitute an offence under the Information Technology Act 2000 "
    "section 66D, and Bharatiya Nyaya Sanhita section 318 subsection 4. "
    "Please contact your bank's fraud desk immediately."
)

FLAG_TEMPLATE = (
    "Notice: Varaksha Alert. Transaction of {amount} rupees to {merchant} "
    "has been flagged for review. Reason: {reason}. "
    "Your bank will verify this transaction before proceeding. "
    "No action is required from you at this time."
)

# Representative verdicts used for pre-generating static assets.
_STATIC_VERDICTS = [
    {
        "verdict": "BLOCK",
        "amount": 10000,
        "merchant": "Unknown Merchant",
        "reason": "fan-in mule ring detected",
        "risk_score": 0.92,
        "typology": "fan_in",
    },
    {
        "verdict": "FLAG",
        "amount": 5000,
        "merchant": "New Payee",
        "reason": "unusual transaction pattern",
        "risk_score": 0.55,
        "typology": "scatter",
    },
]

# ---------------------------------------------------------------------------
# Agent
# ---------------------------------------------------------------------------

class AccessibleAlertAgent:
    """
    Generates multilingual fraud alerts in text and audio form.

    Translation is attempted via googletrans. If translation fails for any
    language, the English text is used as a safe fallback (ensuring audio
    is always generated even if the translation service is unavailable).
    """

    def __init__(self, translation_timeout: float = 5.0) -> None:
        self.translation_timeout = translation_timeout
        self._translator: Optional[Any] = None

    def _get_translator(self) -> Any:
        if self._translator is None:
            try:
                from googletrans import Translator
                self._translator = Translator()
            except ImportError:
                raise ImportError(
                    "googletrans is required: pip install googletrans==4.0.0-rc1"
                )
        return self._translator

    # ------------------------------------------------------------------
    # Text building
    # ------------------------------------------------------------------

    def build_text(self, verdict: Dict[str, Any]) -> str:
        """
        Fill the narration template from a verdict dict.
        Template is selected by verdict["verdict"] ("BLOCK" or "FLAG").
        Missing fields fall back to safe defaults — never raises.
        """
        v = verdict.get("verdict", "FLAG").upper()
        amount = verdict.get("amount", 0)
        merchant = verdict.get("merchant", "Unknown Merchant")
        reason = verdict.get("reason", "suspicious activity detected")

        template = BLOCK_TEMPLATE if v == "BLOCK" else FLAG_TEMPLATE
        return template.format(amount=amount, merchant=merchant, reason=reason)

    # ------------------------------------------------------------------
    # Translation
    # ------------------------------------------------------------------

    async def translate(self, text: str, lang_code: str) -> str:
        """
        Translate text to the target language using googletrans.
        Returns original English text if translation fails.
        """
        if lang_code == "en":
            return text

        target = LANGUAGES[lang_code]["googletrans_code"]
        try:
            translator = self._get_translator()
            loop = asyncio.get_event_loop()
            result = await asyncio.wait_for(
                loop.run_in_executor(None, lambda: translator.translate(text, dest=target)),
                timeout=self.translation_timeout,
            )
            translated = result.text if result and result.text else text
            return translated
        except Exception:
            # Safe fallback: English text is always intelligible.
            return text

    # ------------------------------------------------------------------
    # Audio synthesis
    # ------------------------------------------------------------------

    async def synthesize(self, text: str, voice: str, out_path: Path) -> None:
        """
        Synthesize text to MP3 at out_path using edge-tts Neural voice.
        Requires: pip install edge-tts>=6.1.9
        """
        try:
            import edge_tts
        except ImportError:
            raise ImportError("edge-tts is required: pip install edge-tts>=6.1.9")

        out_path.parent.mkdir(parents=True, exist_ok=True)
        communicate = edge_tts.Communicate(text, voice)
        await communicate.save(str(out_path))

    # ------------------------------------------------------------------
    # Generate alert in all 8 languages
    # ------------------------------------------------------------------

    async def generate_alert(
        self,
        verdict: Dict[str, Any],
        output_dir: Path,
        filename_prefix: str = "",
    ) -> Dict[str, Path]:
        """
        Translate + synthesize the verdict alert in all 8 languages.

        Returns a dict mapping lang code → Path of the generated MP3.
        """
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        english_text = self.build_text(verdict)

        prefix = filename_prefix or _safe_filename_prefix(verdict)
        results: Dict[str, Path] = {}

        async def _process_lang(lang_code: str) -> None:
            voice = LANGUAGES[lang_code]["voice"]
            translated = await self.translate(english_text, lang_code)
            out_path = output_dir / f"{prefix}_{lang_code}.mp3"
            await self.synthesize(translated, voice, out_path)
            results[lang_code] = out_path

        await asyncio.gather(*(_process_lang(lc) for lc in LANGUAGES))
        return results

    # ------------------------------------------------------------------
    # Pre-generate static assets
    # ------------------------------------------------------------------

    async def pregenerate_static(self, output_dir: Path) -> None:
        """
        Pre-generate representative MP3s for static serving.
        Produces 2 verdicts × 8 languages = 16 MP3 files.
        """
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        print(f"[alert_agent] Pre-generating static assets → {output_dir}")
        total = 0
        for verdict in _STATIC_VERDICTS:
            v_type = verdict["verdict"].lower()
            prefix = f"static_{v_type}"
            print(f"  Generating {verdict['verdict']} alerts ...")
            paths = await self.generate_alert(verdict, output_dir, prefix)
            for lang_code, path in sorted(paths.items()):
                lang_name = LANGUAGES[lang_code]["name"]
                print(f"    [{lang_code}] {lang_name:10s} → {path.name}")
            total += len(paths)

        print(f"[alert_agent] Done — {total} MP3 files written to {output_dir}")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _safe_filename_prefix(verdict: Dict[str, Any]) -> str:
    """Build a filesystem-safe filename prefix from verdict fields."""
    v = verdict.get("verdict", "alert").lower()
    ts = int(time.time())
    return f"varaksha_{v}_{ts}"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Varaksha Multilingual Alert Agent")
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--verdict",
        type=str,
        help="JSON string of a single verdict to generate alerts for.",
    )
    group.add_argument(
        "--pregenerate",
        action="store_true",
        help="Pre-generate representative static MP3 assets.",
    )
    p.add_argument(
        "--output-dir",
        type=Path,
        default=Path("services/agents/static/alerts"),
        help="Directory to write MP3 files.",
    )
    p.add_argument(
        "--lang",
        type=str,
        default=None,
        help="Generate only a single language (e.g. hi). Omit for all 8.",
    )
    return p.parse_args()


async def _main() -> None:
    args = _parse_args()
    agent = AccessibleAlertAgent()

    if args.pregenerate:
        await agent.pregenerate_static(args.output_dir)
        return

    # Single verdict mode.
    try:
        verdict = json.loads(args.verdict)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid verdict JSON: {e}") from e

    # Optionally restrict to one language.
    if args.lang:
        if args.lang not in LANGUAGES:
            raise ValueError(f"Unknown language code '{args.lang}'. Choose from: {list(LANGUAGES)}")
        text = agent.build_text(verdict)
        translated = await agent.translate(text, args.lang)
        voice = LANGUAGES[args.lang]["voice"]
        prefix = _safe_filename_prefix(verdict)
        out_path = Path(args.output_dir) / f"{prefix}_{args.lang}.mp3"
        await agent.synthesize(translated, voice, out_path)
        print(f"[alert_agent] Generated: {out_path}")
        return

    paths = await agent.generate_alert(verdict, args.output_dir)
    print(f"[alert_agent] Generated {len(paths)} MP3 files:")
    for lang_code, path in sorted(paths.items()):
        print(f"  [{lang_code}] {LANGUAGES[lang_code]['name']:10s} → {path}")


if __name__ == "__main__":
    asyncio.run(_main())
