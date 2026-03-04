"""GATE-M: OS+Python kernel wrapper for agent filesystem safety."""

from .kernel import GATEKernel
from .models import (
    ApprovalResult,
    CapabilityToken,
    IntentDeclaration,
    RejectionResult,
    ToolCall,
)

__all__ = [
    "GATEKernel",
    "CapabilityToken",
    "IntentDeclaration",
    "ToolCall",
    "RejectionResult",
    "ApprovalResult",
]
