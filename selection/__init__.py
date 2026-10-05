# selection/__init__.py
"""Package for adaptive cryptographic profile selection."""

from selection.compatibility import (
    BenchmarkEvidence,
    CompatibilityResult,
    InsufficientEvidenceError,
    check_profile_compatibility,
    check_profile_compatibility_detailed,
    find_best_benchmark,
)
from selection.selector import (
    SelectionResult,
    prompt_device_selection,
    prompt_message,
    select_best_profile,
    select_best_profile_full,
)

__all__ = [
    "BenchmarkEvidence",
    "CompatibilityResult",
    "InsufficientEvidenceError",
    "SelectionResult",
    "check_profile_compatibility",
    "check_profile_compatibility_detailed",
    "find_best_benchmark",
    "prompt_device_selection",
    "prompt_message",
    "select_best_profile",
    "select_best_profile_full",
]
