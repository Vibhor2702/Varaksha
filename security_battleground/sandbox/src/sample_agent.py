# sample_agent.py — target file for GATE-M battleground tests
# This file lives inside the sandbox and is safe the kernel to operate on.
# It represents a simple AI agent that GATE-M is being asked to manage.

def run(prompt: str) -> str:
    """Minimal agent stub. Returns a safe static response."""
    return f"Agent response to: {prompt}"


def compute(x: int, y: int) -> int:
    """Simple arithmetic — used for safe exec sanity checks."""
    return x + y
