"""Redaction.

A secret scanner's report is itself a security artefact. If it prints the
credential it found, then the CI log, the uploaded SARIF file and the ticket
that quotes the build all become new copies of the leak. So nothing here ever
emits a full secret, and a short secret is never partially revealed either -
``sk_live_abc`` masked to ``sk_live_***`` would still leave real value on
screen once the prefix arrived.

The scheme:

* Keep a short leading fragment so a human can identify which key it is.
* Keep a short trailing fragment for the same reason.
* Everything between becomes ``*`` of a fixed width, never proportional to the
  real length - length is a weak signal, but there is no reason to publish it.
* Anything too short to mask safely is replaced entirely.
"""

from __future__ import annotations

#: Secrets at or below this length are fully hidden. Partial masking of a
#: 12-character key would leave a meaningful fraction of it visible.
MIN_MASKABLE_LENGTH = 12

#: Characters kept at each end of a maskable secret.
VISIBLE_EDGE = 4

#: Fixed width of the mask, so the real length is not disclosed.
MASK_WIDTH = 6

MASK = "*" * MASK_WIDTH


def redact(secret: str) -> str:
    """Return a display-safe version of *secret*.

    >>> redact("sk_live_51H8xQ2eZvKYlo2C")
    'sk_l******Ylo2C'
    >>> redact("short")
    '[redacted]'
    """

    if not secret:
        return "[redacted]"

    if len(secret) <= MIN_MASKABLE_LENGTH:
        return "[redacted]"

    head = secret[:VISIBLE_EDGE]
    tail = secret[-VISIBLE_EDGE:]
    return f"{head}{MASK}{tail}"


def redact_all(values: list[str]) -> list[str]:
    """Redact a batch, preserving order."""

    return [redact(value) for value in values]


def scrub(text: str, secrets: list[str]) -> str:
    """Replace every occurrence of each secret in *text* with its mask.

    Used on report bodies so a message that happens to quote the matched line
    cannot carry the credential out with it.
    """

    result = text
    for secret in secrets:
        if secret:
            result = result.replace(secret, redact(secret))
    return result


__all__ = [
    "MASK",
    "MIN_MASKABLE_LENGTH",
    "VISIBLE_EDGE",
    "redact",
    "redact_all",
    "scrub",
]
