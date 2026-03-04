"""Structured correction message builder."""

from __future__ import annotations

from .models import RejectionResult

_LAYER_NAMES = {
    1: "Scope Check",
    2: "Category Check",
    3: "Side-Effect Check",
    4: "Invariant Check",
    5: "LLM Verifier",
}


class CorrectionInjector:
    """Build human- and agent-readable RejectionResult objects."""

    def build(
        self,
        layer: int,
        detail: str,
        suggestion: str,
        retries_remaining: int,
        is_hard_stop: bool = False,
        tests_passing: bool | None = None,
        invariants_intact: bool | None = None,
    ) -> RejectionResult:
        layer_name = _LAYER_NAMES.get(layer, f"Layer {layer}")

        objective_parts: list[str] = []
        if tests_passing is not None:
            objective_parts.append(f"tests={'PASSING' if tests_passing else 'FAILING'}")
        if invariants_intact is not None:
            objective_parts.append(f"invariants={'INTACT' if invariants_intact else 'VIOLATED'}")
        objective_state = ", ".join(objective_parts) if objective_parts else "unknown"

        rejection_reason = (
            f"[{layer_name}] {detail} | "
            f"objective_state={objective_state} | "
            f"retries_remaining={retries_remaining}"
        )

        return RejectionResult(
            rejection_reason=rejection_reason,
            layer_failed=layer,
            violation_detail=detail,
            kernel_suggestion=suggestion,
            retries_remaining=retries_remaining,
            is_hard_stop=is_hard_stop,
        )
