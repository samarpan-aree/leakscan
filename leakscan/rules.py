"""Detection rules.

Precision matters more than coverage here. A secret scanner that cries wolf
gets switched off in a week, and a scanner that is switched off catches
nothing. So every rule below is either:

* a **structural pattern**: a vendor gives its credentials a fixed, verifiable
  prefix and length, so the match is almost certainly real, or
* a **gated pattern**: a suspicious key name paired with a value that must
  also pass an entropy test, which is what keeps `password = "changeme"`
  from being reported as a leak.

Nothing here uses a generic "looks base64" regex over the whole file. That is
the single biggest source of false positives in naive scanners.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Pattern


class Severity(str, Enum):
    """How urgently a hit needs rotating."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass(frozen=True)
class Rule:
    """One detection rule."""

    rule_id: str
    name: str
    pattern: Pattern[str]
    severity: Severity
    #: Minimum Shannon entropy (bits/char) the captured value must reach.
    #: 0.0 disables the gate, which is correct for structural patterns where
    #: the vendor prefix already guarantees authenticity.
    min_entropy: float = 0.0
    #: Capture group holding the secret. 0 means the whole match.
    secret_group: int = 0
    #: Human-facing note explaining why this matters.
    note: str = ""


# --------------------------------------------------------------------------
# Structural patterns: the vendor guarantees the format.
# --------------------------------------------------------------------------

_STRUCTURAL: tuple[Rule, ...] = (
    Rule(
        rule_id="aws-access-key-id",
        name="AWS access key ID",
        pattern=re.compile(r"\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b"),
        severity=Severity.CRITICAL,
        secret_group=1,
        note="AWS long-lived or temporary access key. Rotate in IAM immediately.",
    ),
    Rule(
        rule_id="aws-secret-access-key",
        name="AWS secret access key",
        pattern=re.compile(
            r"(?i)aws.{0,20}?(?:secret|key).{0,20}?['\"\s:=]+([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])"
        ),
        severity=Severity.CRITICAL,
        secret_group=1,
        min_entropy=3.5,
        note="40-character AWS secret. Full account access if the key ID is also exposed.",
    ),
    Rule(
        rule_id="github-pat",
        name="GitHub personal access token",
        pattern=re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,255})\b"),
        severity=Severity.CRITICAL,
        secret_group=1,
        note="GitHub token. Revoke at github.com/settings/tokens.",
    ),
    Rule(
        rule_id="github-fine-grained-pat",
        name="GitHub fine-grained token",
        pattern=re.compile(r"\b(github_pat_[A-Za-z0-9_]{82})\b"),
        severity=Severity.CRITICAL,
        secret_group=1,
        note="GitHub fine-grained PAT. Revoke at github.com/settings/tokens.",
    ),
    Rule(
        rule_id="github-app-token",
        name="GitHub App token",
        pattern=re.compile(r"\b(ghs_[A-Za-z0-9]{36})\b"),
        severity=Severity.CRITICAL,
        secret_group=1,
        note="GitHub App installation token. Expires, but rotate if leaked.",
    ),
    Rule(
        rule_id="stripe-secret-key",
        name="Stripe secret key",
        pattern=re.compile(r"\b(sk_live_[A-Za-z0-9]{24,})\b"),
        severity=Severity.CRITICAL,
        secret_group=1,
        note="Live Stripe key can move real money. Roll it in the dashboard.",
    ),
    Rule(
        rule_id="stripe-restricted-key",
        name="Stripe restricted key",
        pattern=re.compile(r"\b(rk_live_[A-Za-z0-9]{24,})\b"),
        severity=Severity.HIGH,
        secret_group=1,
        note="Live Stripe restricted key. Scope may still allow writes.",
    ),
    Rule(
        rule_id="slack-token",
        name="Slack token",
        pattern=re.compile(r"\b(xox[baprs]-[A-Za-z0-9-]{10,250})\b"),
        severity=Severity.CRITICAL,
        secret_group=1,
        note="Slack token grants workspace API access. Revoke in Slack admin.",
    ),
    Rule(
        rule_id="slack-webhook",
        name="Slack incoming webhook",
        pattern=re.compile(
            r"(https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24})"
        ),
        severity=Severity.HIGH,
        secret_group=1,
        note="Anyone with this URL can post into the channel.",
    ),
    Rule(
        rule_id="google-api-key",
        name="Google API key",
        pattern=re.compile(r"\b(AIza[0-9A-Za-z_-]{35})\b"),
        severity=Severity.HIGH,
        secret_group=1,
        note="Google API key. Restrict by referrer or IP, or rotate it.",
    ),
    Rule(
        rule_id="private-key-block",
        name="Private key block",
        pattern=re.compile(
            r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----)"
        ),
        severity=Severity.CRITICAL,
        secret_group=1,
        note="A committed private key. Assume it is compromised and reissue.",
    ),
    Rule(
        rule_id="npm-token",
        name="npm access token",
        pattern=re.compile(r"\b(npm_[A-Za-z0-9]{36})\b"),
        severity=Severity.HIGH,
        secret_group=1,
        note="npm token can publish packages under your identity.",
    ),
    Rule(
        rule_id="sendgrid-key",
        name="SendGrid API key",
        pattern=re.compile(r"\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})\b"),
        severity=Severity.HIGH,
        secret_group=1,
        note="SendGrid key can send mail as your domain.",
    ),
    Rule(
        rule_id="openai-key",
        name="OpenAI API key",
        pattern=re.compile(r"\b(sk-(?:proj-)?[A-Za-z0-9_-]{20,})"),
        severity=Severity.HIGH,
        secret_group=1,
        note="OpenAI key bills to your account. Revoke at platform.openai.com.",
    ),
    Rule(
        rule_id="anthropic-key",
        name="Anthropic API key",
        pattern=re.compile(r"\b(sk-ant-[A-Za-z0-9_-]{20,})"),
        severity=Severity.HIGH,
        secret_group=1,
        note="Anthropic key bills to your account.",
    ),
    Rule(
        rule_id="twilio-key",
        name="Twilio API key",
        pattern=re.compile(r"\b(SK[0-9a-fA-F]{32})\b"),
        severity=Severity.HIGH,
        secret_group=1,
        note="Twilio key can send SMS and place calls on your account.",
    ),
    Rule(
        rule_id="db-connection-string",
        name="Database URI with credentials",
        pattern=re.compile(
            r"\b((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s:/@]{1,64}:([^\s@/]{3,128})@[^\s]+)"
        ),
        severity=Severity.CRITICAL,
        secret_group=1,
        note="Connection string embeds a live password for a data store.",
    ),
    Rule(
        rule_id="jwt",
        name="JSON Web Token",
        pattern=re.compile(r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})"),
        severity=Severity.MEDIUM,
        secret_group=1,
        note="A JWT may still be within its validity window and grant access.",
    ),
)


# --------------------------------------------------------------------------
# Gated patterns: a key name plus a value that must look random.
# --------------------------------------------------------------------------

_CREDENTIAL_NAMES = (
    r"(?:api[_-]?key|apikey|secret[_-]?key|secret|access[_-]?token|auth[_-]?token"
    r"|password|passwd|pwd|client[_-]?secret|private[_-]?key|token)"
)

_GATED: tuple[Rule, ...] = (
    Rule(
        rule_id="generic-secret-assignment",
        name="Hardcoded credential assignment",
        pattern=re.compile(
            rf"""(?ix)
            \b{_CREDENTIAL_NAMES}\b
            \s*[:=]\s*
            (?:
                ["']([^"'\s]{{8,200}})["']
              | ([A-Za-z0-9_\-+/=]{{16,200}}) (?![A-Za-z0-9_\-+/=])
            )
            """
        ),
        severity=Severity.HIGH,
        secret_group=1,
        min_entropy=3.2,
        note="A credential appears hardcoded in source. Move it to an env var.",
    ),
    Rule(
        rule_id="generic-bearer-token",
        name="Bearer token in source",
        pattern=re.compile(r"""(?i)\bAuthorization\s*[:=]\s*["']?\s*Bearer\s+([A-Za-z0-9_\-\.=+/]{20,})"""),
        severity=Severity.HIGH,
        secret_group=1,
        min_entropy=3.0,
        note="A bearer token is hardcoded. These rarely expire quickly enough.",
    ),
)


#: Every rule, structural first so a specific match wins over a generic one.
RULES: tuple[Rule, ...] = _STRUCTURAL + _GATED


# Substrings that mean "this is a placeholder, not a credential". Checked
# against the lowercased secret before it is ever reported.
PLACEHOLDER_TOKENS: tuple[str, ...] = (
    "example",
    "sample",
    "placeholder",
    "changeme",
    "change_me",
    "replace",
    "your_",
    "your-",
    "xxx",
    "todo",
    "fixme",
    "dummy",
    "fake",
    "test_key",
    "test-key",
    "insert_",
    "redacted",
    "<",
    ">",
    "${",
    "{{",
    "%s",
    "0000000000",
    "aaaaaaaa",
)


#: Values that are technically assignments but carry no secret.
BENIGN_VALUES: frozenset[str] = frozenset(
    {
        "null",
        "none",
        "true",
        "false",
        "undefined",
        "nil",
        "empty",
        "string",
        "str",
        "bytes",
        "secret",
        "password",
        "token",
        "apikey",
        "api_key",
    }
)


__all__ = [
    "BENIGN_VALUES",
    "PLACEHOLDER_TOKENS",
    "RULES",
    "Rule",
    "Severity",
]
