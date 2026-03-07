"""
services/agents/agent03_accessible_alert.py
â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
Layer 4: Personalised AI Alert & Accessible Report Generator
Varaksha V2

For a blocked/flagged transaction this agent:
  1. Builds law citations with real India Code / RBI / cybercrime portal URLs.
  2. Generates a plain-English warning via mock LLM (swap body for real API).
  3. Translates to user's preferred language via deep-translator (free Google
     Translate wrapper â€” no API key, replaces Bhashini NMT dependency).
  4. Adapts vocabulary, sentence complexity, and tone for the user's age group
     and education level (data supplied by the bank app).
  5. Generates MP3 audio via gTTS (free Google TTS â€” supports ~10 Indian
     languages natively).
  6. Returns a structured AlertResult for the Streamlit dashboard.

Bhashini replacement rationale:
  - deep-translator wraps Google Translate's public endpoint (same engine as
    translate.google.com), zero cost, zero API key, supports all 22 scheduled
    Indian languages.
  - gTTS (Google TTS) supports: hi, bn, gu, kn, ml, mr, ta, te, pa, ur + en.
  - If network is unavailable, both fall back gracefully (English text + no audio).

Personalisation inputs (sent by bank app as part of AlertRequest):
  - language      : IETF tag e.g. "hi", "ta", "te", "bn", "gu", "ml", "mr"
  - age_group     : "child" | "teen" | "adult" | "senior"
  - education     : "basic" | "intermediate" | "graduate"

Indian laws cited (with live government URLs):
  - BNS Â§318(4)  : Cheating    â†’ indiacode.nic.in
  - IT Act Â§66D  : Cyber fraud â†’ indiacode.nic.in
  - PMLA Â§3/Â§4   : Money laundering
  - RBI Master Direction on fraud (2025)
  - Cybercrime portal: cybercrime.gov.in  |  Helpline: 1930
  - Banking Ombudsman: cms.rbi.org.in
"""

from __future__ import annotations

import asyncio
import functools
import hashlib
import logging
import pathlib
import re
import sys
from dataclasses import dataclass, field

# â”€â”€ SHAP explain_transaction (graceful fallback if models not yet trained) â”€â”€â”€â”€
_EXPLAIN_AVAILABLE = False
try:
    _REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
    if str(_REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(_REPO_ROOT))
    from services.local_engine.train_ensemble import explain_transaction as _explain_tx
    _EXPLAIN_AVAILABLE = True
except Exception:
    pass

# â”€â”€ PromptGuard (Layer 0 â€” inline injection guard) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
_GUARD_AVAILABLE = False
try:
    from services.local_engine.prompt_guard import is_injection as _is_injection
    _GUARD_AVAILABLE = True
except Exception:
    pass

log = logging.getLogger("varaksha.agent03")

AUDIO_DIR = pathlib.Path(__file__).resolve().parents[2] / "data" / "audio_alerts"
AUDIO_DIR.mkdir(parents=True, exist_ok=True)


def _check_injection(text: str, field_name: str) -> None:
    if not _GUARD_AVAILABLE:
        return
    if _is_injection(text):
        log.warning("PromptGuard blocked injection in field '%s': %.60sâ€¦", field_name, text)
        raise ValueError(
            f"Potential prompt injection detected in field '{field_name}'. "
            "Transaction alert aborted for security."
        )


# â”€â”€ Law registry with real government URLs â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# All URLs are stable Indian government / official portals.
# India Code is the official digital repository of all Central Acts.

LAW_REGISTRY: dict[str, dict] = {
    "IT_66D": {
        "citation": "IT Act Â§66D â€” Cheating by personation using computer resource",
        "summary":  "Using a computer or phone to impersonate someone else to steal money is a criminal offence.",
        "simple":   "Someone used a computer trick to pretend to be you and steal your money. That is illegal.",
        "url":      "https://www.indiacode.nic.in/handle/123456789/13765",
        "penalty":  "Up to 3 years imprisonment and fine up to â‚¹1,00,000.",
    },
    "BNS_318_4": {
        "citation": "BNS Â§318(4) â€” Cheating where value exceeds â‚¹1,00,000",
        "summary":  "Cheating someone of more than â‚¹1 lakh is punishable with up to 7 years in prison.",
        "simple":   "The stolen amount is very large. The law gives heavy punishment for this.",
        "url":      "https://www.indiacode.nic.in/handle/123456789/20062",
        "penalty":  "Up to 7 years imprisonment and fine.",
    },
    "PMLA_3": {
        "citation": "PMLA Â§3 â€” Money-laundering offence",
        "summary":  "Moving stolen money through multiple accounts to hide its origin is money laundering.",
        "simple":   "The stolen money was moved through many accounts to hide it. That is a serious crime.",
        "url":      "https://www.indiacode.nic.in/handle/123456789/1441",
        "penalty":  "Rigorous imprisonment 3â€“7 years, extendable to 10 years in some cases.",
    },
    "PMLA_4": {
        "citation": "PMLA Â§4 â€” Punishment for money-laundering",
        "summary":  "Punishment for the money-laundering offence under PMLA Â§3.",
        "simple":   "This adds extra punishment on top of the cheating charge.",
        "url":      "https://www.indiacode.nic.in/handle/123456789/1441",
        "penalty":  "Rigorous imprisonment 3â€“7 years and property attachment.",
    },
    "RBI_FRAUD": {
        "citation": "RBI Master Direction â€” Fraud Risk Management in Banks (2025)",
        "summary":  "Banks must report fraud within 7 days and cannot hold you liable if you report within 3 days.",
        "simple":   "If you report the fraud quickly, the bank must refund your money.",
        "url":      "https://www.rbi.org.in/Scripts/BS_ViewMasDirections.aspx?id=12586",
        "penalty":  "Bank is liable to refund if customer reports within 3 working days.",
    },
}

CONTACT_LINKS = {
    "cybercrime_portal": {
        "name":    "National Cyber Crime Reporting Portal",
        "url":     "https://cybercrime.gov.in",
        "helpline": "1930",
    },
    "banking_ombudsman": {
        "name":    "RBI Banking Ombudsman (online complaint)",
        "url":     "https://cms.rbi.org.in",
        "helpline": "14448",
    },
    "npci_grievance": {
        "name":    "NPCI UPI Grievance Portal",
        "url":     "https://www.npci.org.in/what-we-do/upi/grievance-redressal",
        "helpline": None,
    },
}


# â”€â”€ User profile â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

@dataclass
class UserProfile:
    """
    Sent by the bank app with every alert request.
    Drives vocabulary level, tone, and language of the generated report.
    """
    language:  str = "hi"        # IETF language tag: "hi","ta","te","bn","gu","ml","mr","kn","pa","en"
    age_group: str = "adult"     # "child" | "teen" | "adult" | "senior"
    education: str = "intermediate"  # "basic" | "intermediate" | "graduate"

    @property
    def reading_level(self) -> str:
        """Merge age + education into a single reading complexity level."""
        if self.age_group in ("child",) or self.education == "basic":
            return "simple"
        if self.age_group == "senior" and self.education != "graduate":
            return "simple"
        if self.education == "graduate" and self.age_group in ("adult", "teen"):
            return "detailed"
        return "standard"


# â”€â”€ Data models â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

@dataclass
class FlaggedTransaction:
    transaction_id:    str
    vpa_hash:          str          # SHA-256 hex â€” never the raw VPA
    amount_inr:        float
    merchant_category: str
    risk_score:        float        # 0.0 â€“ 1.0
    graph_flags:       list[str] = field(default_factory=list)


@dataclass
class AlertResult:
    transaction_id:     str
    english_warning:    str
    translated_warning: str          # in user's language (may equal english_warning if lang="en")
    laws_cited:         list[str]
    law_links:          list[dict]   # [{"citation": â€¦, "url": â€¦, "penalty": â€¦}, â€¦]
    contact_links:      list[dict]   # [{"name": â€¦, "url": â€¦, "helpline": â€¦}, â€¦]
    next_steps:         list[str]    # plain-language action items for the user
    audio_path:         pathlib.Path | None
    risk_level:         str          # "HIGH" | "CRITICAL"
    language:           str
    reading_level:      str
    shap_contributions: list[dict] = field(default_factory=list)


# â”€â”€ Law citation builder â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def _build_law_citations(tx: FlaggedTransaction) -> tuple[list[str], list[dict]]:
    """Return (citation strings, full law dicts with URLs) for a flagged transaction."""
    keys = ["IT_66D", "RBI_FRAUD"]
    if tx.amount_inr >= 100_000:
        keys.append("BNS_318_4")
    if "CYCLE" in tx.graph_flags or "FAN_IN" in tx.graph_flags:
        keys.append("PMLA_3")
    if tx.risk_score >= 0.90:
        keys.append("PMLA_4")

    citations = [LAW_REGISTRY[k]["citation"] for k in keys]
    law_dicts = [
        {"key": k, "citation": LAW_REGISTRY[k]["citation"],
         "url": LAW_REGISTRY[k]["url"], "penalty": LAW_REGISTRY[k]["penalty"],
         "summary": LAW_REGISTRY[k]["summary"], "simple": LAW_REGISTRY[k]["simple"]}
        for k in keys
    ]
    return citations, law_dicts


# â”€â”€ Personalised report builder â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

def _build_english_report(
    tx: FlaggedTransaction,
    laws: list[str],
    law_dicts: list[dict],
    shap_contributions: list[dict],
    profile: UserProfile,
) -> tuple[str, list[str]]:
    """
    Generate a personalised English report + next-steps list.
    Vocabulary and tone are adapted to the user's reading_level.
    Returns (report_text, next_steps_list).
    """
    level      = profile.reading_level
    amount_str = f"â‚¹{tx.amount_inr:,.0f}"
    score_pct  = f"{tx.risk_score:.0%}"

    # Law descriptions: use simple explanations for basic/senior, full citations otherwise
    if level == "simple":
        law_lines = "\n".join(f"  â€¢ {d['simple']}" for d in law_dicts)
    else:
        law_lines = "\n".join(
            f"  â€¢ {d['citation']} â€” {d['summary']}" for d in law_dicts
        )

    # SHAP signals (omit for basic readers â€” too technical)
    shap_block = ""
    if shap_contributions and level in ("standard", "detailed"):
        signals = [f"{c['feature'].replace('_',' ')} ({c['direction']}{c['pct']:.0f}%)"
                   for c in shap_contributions[:3]]
        shap_block = f"\nAI risk signals: {', '.join(signals)}."

    # Next steps â€” always plain language
    next_steps = [
        f"Call your bank helpline RIGHT NOW and tell them to block your account.",
        f"File a complaint at cybercrime.gov.in or call 1930 (free, 24Ã—7).",
        f"File a complaint with the RBI Banking Ombudsman at cms.rbi.org.in if your bank does not help within 3 days.",
        f"Keep a screenshot of this alert as proof.",
    ]

    if level == "simple":
        report = (
            f"âš ï¸  YOUR MONEY IS IN DANGER\n\n"
            f"We stopped a payment of {amount_str} from your account.\n"
            f"Our computer system found this payment very suspicious ({score_pct} danger).\n\n"
            f"What the law says:\n{law_lines}\n\n"
            f"WHAT YOU MUST DO NOW:\n"
            + "\n".join(f"  {i+1}. {s}" for i, s in enumerate(next_steps))
        )
    elif level == "detailed":
        net_flags = (", ".join(tx.graph_flags) or "none")
        report = (
            f"FRAUD ALERT â€” Transaction {tx.transaction_id} BLOCKED\n\n"
            f"A payment of {amount_str} to merchant category '{tx.merchant_category}' "
            f"has been flagged with a composite risk score of {score_pct}. "
            f"Network graph analysis identified: [{net_flags}].{shap_block}\n\n"
            f"Applicable statutes and regulatory directions:\n{law_lines}\n\n"
            f"Recommended actions:\n"
            + "\n".join(f"  {i+1}. {s}" for i, s in enumerate(next_steps))
        )
    else:  # standard
        report = (
            f"âš ï¸  FRAUD ALERT â€” Transaction Blocked\n\n"
            f"A payment of {amount_str} has been stopped because it looks suspicious "
            f"(risk score: {score_pct}).{shap_block}\n\n"
            f"Laws that apply:\n{law_lines}\n\n"
            f"What you should do next:\n"
            + "\n".join(f"  {i+1}. {s}" for i, s in enumerate(next_steps))
        )

    return report, next_steps


# â”€â”€ Translation (Bhashini replacement) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Uses deep-translator â†’ Google Translate free public endpoint.
# No API key required. Falls back to English on any error.
# Supports all 22 scheduled Indian languages + English.

_GTRANSLATE_AVAILABLE = False
try:
    from deep_translator import GoogleTranslator as _GTrans  # type: ignore
    _GTRANSLATE_AVAILABLE = True
except ImportError:
    pass

@functools.lru_cache(maxsize=1)
def _gtts_langs() -> set[str]:
    """
    Return the set of language codes supported by gTTS.
    Queried once at runtime — covers all languages Google TTS supports,
    not a hardcoded list. Falls back to a minimal safe set if unavailable.
    """
    try:
        from gtts.lang import tts_langs  # type: ignore
        return set(tts_langs().keys())
    except Exception:
        return {"hi", "en"}  # minimal fallback; gTTS install issue


@functools.lru_cache(maxsize=1)
def get_supported_languages() -> dict[str, str]:
    """
    Return {"Language Name (code)": "code"} for every language that both
    deep-translator and gTTS support — built dynamically at runtime.
    Suitable for populating a UI language picker without hardcoding.
    """
    try:
        from gtts.lang import tts_langs  # type: ignore
        langs = tts_langs()  # {code: name}, e.g. {"hi": "Hindi", "ta": "Tamil"}
    except Exception:
        langs = {"hi": "Hindi", "en": "English"}
    return {f"{name} ({code})": code for code, name in sorted(langs.items(), key=lambda x: x[1])}


def _translate(text: str, target_lang: str) -> str:
    """
    Translate text to target_lang using deep-translator (Google Translate free tier).
    Falls back to original English text if translation fails or lang is "en".
    """
    if target_lang == "en" or not target_lang:
        return text
    if not _GTRANSLATE_AVAILABLE:
        log.warning("deep-translator not installed; returning English text")
        return text
    try:
        # Chunk text if > 4500 chars (Google Translate limit per request)
        if len(text) <= 4500:
            return _GTrans(source="en", target=target_lang).translate(text)
        # Split on double-newlines to preserve paragraph structure
        parts = text.split("\n\n")
        translated_parts = [
            _GTrans(source="en", target=target_lang).translate(p) if p.strip() else p
            for p in parts
        ]
        return "\n\n".join(translated_parts)
    except Exception as exc:
        log.warning("Translation to '%s' failed (%s); returning English", target_lang, exc)
        return text


# â”€â”€ gTTS audio generation (Bhashini TTS replacement) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# gTTS wraps Google TTS â€” free, no API key, supports ~10 Indian languages.
# Falls back to edge-tts for languages gTTS can't handle.

async def _generate_audio(
    text: str,
    transaction_id: str,
    language: str = "hi",
) -> pathlib.Path | None:
    """
    Generate an MP3 audio alert.
    Primary: gTTS (free Google TTS, supports most Indian languages).
    Fallback: edge-tts Neural TTS (Microsoft, also free, broader voice range).
    """
    safe_id  = hashlib.md5(transaction_id.encode()).hexdigest()[:10]
    out_path = AUDIO_DIR / f"alert_{safe_id}_{language}.mp3"

    # Keep only the first 500 chars for audio â€” long text causes gTTS timeouts
    audio_text = text[:500].strip()
    audio_lang = language if language in _gtts_langs() else "hi"

    # 1. Try gTTS first
    try:
        from gtts import gTTS  # type: ignore
        import io
        tts = gTTS(text=audio_text, lang=audio_lang, slow=False)
        with io.BytesIO() as buf:
            tts.write_to_fp(buf)
            buf.seek(0)
            out_path.write_bytes(buf.read())
        log.info("gTTS audio saved â†’ %s", out_path)
        return out_path
    except Exception as gtts_err:
        log.warning("gTTS failed (%s); trying edge-tts â€¦", gtts_err)

    # 2. Fallback: edge-tts (Microsoft Neural TTS, also free)
    _EDGE_VOICE = {
        "hi": "hi-IN-SwaraNeural", "ta": "ta-IN-PallaviNeural",
        "te": "te-IN-ShrutiNeural", "bn": "bn-IN-TanishaaNeural",
        "gu": "gu-IN-DhwaniNeural", "kn": "kn-IN-SapnaNeural",
        "ml": "ml-IN-SobhanaNeural", "mr": "mr-IN-AarohiNeural",
        "en": "en-IN-NeerjaNeural",
    }
    voice = _EDGE_VOICE.get(language, "en-IN-NeerjaNeural")
    try:
        import edge_tts  # type: ignore
        communicate = edge_tts.Communicate(text=audio_text, voice=voice)
        await communicate.save(str(out_path))
        log.info("edge-tts audio saved â†’ %s", out_path)
        return out_path
    except Exception as edge_err:
        log.warning("edge-tts also failed (%s); no audio generated", edge_err)
        return None


# â”€â”€ Main alert function â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

async def generate_alert(
    tx: FlaggedTransaction,
    profile: UserProfile | None = None,
) -> AlertResult:
    """
    Full pipeline: PromptGuard â†’ law citation â†’ SHAP â†’ personalised report â†’
    translation â†’ audio.

    profile: UserProfile with language / age_group / education from bank app.
             Defaults to Hindi / adult / intermediate if not provided.
    """
    if profile is None:
        profile = UserProfile()

    log.info(
        "Generating alert for %s (score=%.2f | lang=%s | age=%s | edu=%s)",
        tx.transaction_id, tx.risk_score,
        profile.language, profile.age_group, profile.education,
    )

    # Layer 0: PromptGuard â€” check user-controlled fields before report generation
    for _fname, _val in [("merchant_category", tx.merchant_category),
                          ("transaction_id", tx.transaction_id)]:
        _check_injection(str(_val), _fname)
    for _flag in tx.graph_flags:
        _check_injection(str(_flag), "graph_flags")

    # Build law citations
    law_citations, law_dicts = _build_law_citations(tx)

    # SHAP contributions
    shap_contributions: list[dict] = []
    if _EXPLAIN_AVAILABLE:
        try:
            tx_dict = {
                "merchant_category":     tx.merchant_category,
                "transaction_type":      "DEBIT",
                "device_type":           "ANDROID",
                "amount":                tx.amount_inr,
                "hour_of_day":           3,
                "day_of_week":           6,
                "transactions_last_1h":  10,
                "transactions_last_24h": 25,
                "amount_zscore":         max(3.0, (tx.amount_inr - 3000) / 5000),
                "gps_delta_km":          500.0 if "CYCLE" in tx.graph_flags else 5.0,
                "is_new_device":         1,
                "is_new_merchant":       1,
            }
            shap_contributions = _explain_tx(tx_dict)
        except Exception as exc:
            log.warning("SHAP explain unavailable: %s", exc)

    # Build personalised English report
    english_report, next_steps = _build_english_report(
        tx, law_citations, law_dicts, shap_contributions, profile
    )

    # Translate to user's language
    translated_report = _translate(english_report, profile.language)

    # Generate audio from the translated report
    audio_path = await _generate_audio(
        translated_report, tx.transaction_id, profile.language
    )

    # Collect contact links
    contact_links = list(CONTACT_LINKS.values())

    risk_level = "CRITICAL" if tx.risk_score >= 0.85 else "HIGH"

    return AlertResult(
        transaction_id     = tx.transaction_id,
        english_warning    = english_report,
        translated_warning = translated_report,
        laws_cited         = law_citations,
        law_links          = law_dicts,
        contact_links      = contact_links,
        next_steps         = next_steps,
        audio_path         = audio_path,
        risk_level         = risk_level,
        language           = profile.language,
        reading_level      = profile.reading_level,
        shap_contributions = shap_contributions,
    )


# â”€â”€ CLI demo â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

    demo_tx = FlaggedTransaction(
        transaction_id    = "TXN-DEMO-20260307-001",
        vpa_hash          = hashlib.sha256(b"victim@okaxis").hexdigest(),
        amount_inr        = 175_000.00,
        merchant_category = "P2P",
        risk_score        = 0.92,
        graph_flags       = ["FAN_OUT", "CYCLE"],
    )

    # Test three reading levels
    for age, edu, lang in [("senior", "basic", "hi"), ("adult", "graduate", "en"), ("adult", "intermediate", "ta")]:
        p = UserProfile(language=lang, age_group=age, education=edu)
        result = asyncio.run(generate_alert(demo_tx, profile=p))
        print(f"\n{'â•'*60}")
        print(f"  PROFILE: age={age} | edu={edu} | lang={lang} | level={result.reading_level}")
        print("â•"*60)
        print(result.english_warning[:500])
        if result.translated_warning != result.english_warning:
            print(f"\n[{lang.upper()} TRANSLATION]")
            print(result.translated_warning[:300])
        print(f"\nLAW LINKS:")
        for lw in result.law_links:
            print(f"  â€¢ {lw['citation']}")
            print(f"    {lw['url']}")
        print(f"\nNEXT STEPS:")
        for i, s in enumerate(result.next_steps, 1):
            print(f"  {i}. {s}")
        print(f"\nAUDIO: {result.audio_path}")

