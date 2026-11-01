"""leakscan - high-precision secret scanning with redacted output."""

from __future__ import annotations

from .rules import RULES, Rule, Severity
from .scanner import Finding, scan_path, scan_text

__version__ = "1.0.0"

__all__ = [
    "RULES",
    "Finding",
    "Rule",
    "Severity",
    "__version__",
    "scan_path",
    "scan_text",
]
