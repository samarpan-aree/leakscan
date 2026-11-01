"""Shannon entropy, used to tell a credential from a variable name.

The gate exists because regex alone cannot tell a generated key such as
``Ab3f9c2e1d8b7a5f4`` from a placeholder such as ``your_api_key_here``: both
fit the same pattern. Entropy separates them. A generated key draws from ~60
possible characters with little repetition, giving ~3.5-4.0 bits per
character. Prose and placeholders repeat letters and run at ~1.5-2.5.

The threshold is per-rule (a DATABASE_URL password needs a lower bar than a
hex API key) because a single global cut-off either misses real secrets or
floods the report.
"""

from __future__ import annotations

import math
from collections import Counter


def shannon_entropy(value: str) -> float:
    """Bits of entropy per character in *value*.

    Returns 0.0 for an empty string. A string of one repeated character also
    returns 0.0, which is the right answer: knowing one character tells you
    every character.
    """

    if not value:
        return 0.0

    counts = Counter(value)
    length = len(value)
    total = 0.0
    for count in counts.values():
        probability = count / length
        total -= probability * math.log2(probability)
    return total


def looks_random(value: str, threshold: float) -> bool:
    """True when *value* clears the entropy bar.

    A threshold of 0.0 disables the gate entirely, which is what structural
    rules want: the vendor prefix already establishes authenticity.
    """

    if threshold <= 0.0:
        return True
    return shannon_entropy(value) >= threshold


def character_class_count(value: str) -> int:
    """How many of {lower, upper, digit, symbol} appear in *value*.

    A second opinion for the generic rules: real generated credentials almost
    always mix classes, while a sentence written in a config file does not.
    """

    classes = 0
    if any(c.islower() for c in value):
        classes += 1
    if any(c.isupper() for c in value):
        classes += 1
    if any(c.isdigit() for c in value):
        classes += 1
    if any(not c.isalnum() for c in value):
        classes += 1
    return classes


__all__ = ["character_class_count", "looks_random", "shannon_entropy"]
