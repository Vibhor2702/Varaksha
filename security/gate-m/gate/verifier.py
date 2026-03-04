"""LLM verifier — only invoked when diff line count > 20.

Primary: Groq (llama-3.3-70b-versatile)
Fallback: Gemini 2.0 flash
Timeout: 10s. On timeout → fail open (approve) + log warning.
"""

from __future__ import annotations

import json
import logging
from typing import Optional

import httpx

from .models import CapabilityToken, ToolCall

logger = logging.getLogger(__name__)

_GROQ_ENDPOINT = "https://api.groq.com/openai/v1/chat/completions"
_GEMINI_ENDPOINT = (
    "https://generativelanguage.googleapis.com/v1beta/models/"
    "gemini-2.0-flash:generateContent"
)

_SYSTEM_PROMPT = (
    "You are a code change verifier. You check if a proposed code change "
    "is aligned with a declared intent. Be strict but fair. Respond only in JSON."
)


def count_diff_lines(diff: str) -> int:
    """Count added + removed lines in a unified diff."""
    count = 0
    for line in diff.splitlines():
        if (line.startswith("+") and not line.startswith("+++")) or (
            line.startswith("-") and not line.startswith("---")
        ):
            count += 1
    return count


def _build_user_prompt(tool_call: ToolCall, token: CapabilityToken) -> str:
    intent = tool_call.intent
    diff_snippet = (tool_call.proposed_diff or "")[:3000]
    return (
        f"Goal: {token.natural_language_goal}\n"
        f"Declared intent: {intent.intent if intent else 'N/A'}\n"
        f"Edit category: {intent.edit_category if intent else 'N/A'}\n"
        f"Expected postcondition: {intent.expected_postcondition if intent else 'N/A'}\n"
        f"\nDiff (truncated to 100 lines if longer):\n{diff_snippet}\n\n"
        'Does this diff achieve the declared intent without unintended side effects?\n'
        'Respond: {"approved": bool, "reason": str, "suggestion": str | null}'
    )


def _parse_response(text: str) -> tuple[bool, str]:
    """Parse JSON response from LLM. Returns (approved, reason)."""
    text = text.strip()
    # Strip markdown code fences if present
    if text.startswith("```"):
        lines = text.splitlines()
        text = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])
    try:
        data = json.loads(text)
        return bool(data.get("approved", True)), str(data.get("reason", ""))
    except json.JSONDecodeError:
        logger.warning("Could not parse verifier JSON response: %s", text[:200])
        return True, "parse error — fail open"


class VerifierClient:
    def __init__(self, groq_api_key: str, gemini_api_key: str) -> None:
        self._groq_key = groq_api_key
        self._gemini_key = gemini_api_key

    def verify(
        self, tool_call: ToolCall, token: CapabilityToken
    ) -> tuple[bool, str]:
        """Return (approved, reason). Fail open on timeout."""
        user_prompt = _build_user_prompt(tool_call, token)

        approved, reason = self._try_groq(user_prompt)
        if approved is None:
            approved, reason = self._try_gemini(user_prompt)
        if approved is None:
            logger.warning("Both Groq and Gemini failed — failing open")
            return True, "verifier unavailable — fail open"
        return approved, reason

    # ------------------------------------------------------------------ #
    # Groq
    # ------------------------------------------------------------------ #

    def _try_groq(self, user_prompt: str) -> tuple[Optional[bool], str]:
        payload = {
            "model": "llama-3.3-70b-versatile",
            "messages": [
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0,
            "max_tokens": 256,
        }
        try:
            with httpx.Client(timeout=10.0) as client:
                resp = client.post(
                    _GROQ_ENDPOINT,
                    json=payload,
                    headers={"Authorization": f"Bearer {self._groq_key}"},
                )
            resp.raise_for_status()
            content = resp.json()["choices"][0]["message"]["content"]
            approved, reason = _parse_response(content)
            return approved, reason
        except httpx.TimeoutException:
            logger.warning("Groq timed out")
            return None, "timeout"
        except Exception as exc:
            logger.warning("Groq error: %s", exc)
            return None, str(exc)

    # ------------------------------------------------------------------ #
    # Gemini
    # ------------------------------------------------------------------ #

    def _try_gemini(self, user_prompt: str) -> tuple[Optional[bool], str]:
        payload = {
            "contents": [
                {
                    "parts": [
                        {"text": f"{_SYSTEM_PROMPT}\n\n{user_prompt}"}
                    ]
                }
            ],
            "generationConfig": {"temperature": 0, "maxOutputTokens": 256},
        }
        try:
            with httpx.Client(timeout=10.0) as client:
                resp = client.post(
                    _GEMINI_ENDPOINT,
                    json=payload,
                    params={"key": self._gemini_key},
                )
            resp.raise_for_status()
            content = (
                resp.json()["candidates"][0]["content"]["parts"][0]["text"]
            )
            approved, reason = _parse_response(content)
            return approved, reason
        except httpx.TimeoutException:
            logger.warning("Gemini timed out")
            return None, "timeout"
        except Exception as exc:
            logger.warning("Gemini error: %s", exc)
            return None, str(exc)
