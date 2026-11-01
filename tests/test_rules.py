"""Detection rule correctness and the entropy/placeholder gates.

Test fixtures are assembled at runtime by ``_j`` rather than written as complete
literals. GitHub's secret-scanning push protection rejects any file containing a
token-shaped string, and a secret scanner's own test suite is nothing but
token-shaped strings. Joining the parts keeps every rule exercised while the
file on disk never contains a matchable credential.
"""

from __future__ import annotations

import pytest

from leakscan.entropy import character_class_count, looks_random, shannon_entropy
from leakscan.rules import RULES, Severity
from leakscan.scanner import is_placeholder, scan_text, value_is_credential_like


def _j(*parts: str) -> str:
    """Join fragments into a credential-shaped string at runtime."""

    return "".join(parts)


def _rule(rule_id: str):
    return next(r for r in RULES if r.rule_id == rule_id)


ALNUM_36 = _j("0123456789", "abcdefghijklmnopqrstuvwxyz")
MIXED_36 = _j("AbCdEfGhIjKlMnOpQrStUvWxYz", "0123456789")

AWS_KEY = _j("AKIA", "0123456789ABCDEF")
GITHUB_PAT = _j("ghp_", ALNUM_36, "ABCDEFG")
FINE_GRAINED = _j("github_pat_", MIXED_36, MIXED_36, "AbCdEfGhIj")
GITHUB_APP = _j("ghs_", ALNUM_36)
STRIPE_LIVE = _j("sk_live_", "51H8xQ2eZvKYlo2CZx", "1234567890")
STRIPE_RESTRICTED = _j("rk_live_", "0123456789abcdefghijklmnopqr")
SLACK_TOKEN = _j("xoxb-", "123456789012-123456789012-abcdefghijklmnopqrstuvwx")
SLACK_WEBHOOK = _j(
    "https://hooks.slack.com", "/services/T00000000/B00000000/abcdefghijklmnopqrstuvwx"
)
GOOGLE_KEY = _j("AIza", MIXED_36[:-1])  # 4 + 35 = 39 chars
PRIVATE_BLOCK = _j("-----BEGIN ", "RSA PRIVATE KEY-----")
NPM_TOKEN = _j("npm_", ALNUM_36)
SENDGRID = _j("SG.", "abcdefghijklmnopqrstuv", ".", ALNUM_36, "012345", "6")
OPENAI = _j("sk-", ALNUM_36)
ANTHROPIC = _j("sk-ant-", ALNUM_36)
JWT = _j(
    "eyJhbGciOiJIUzI1NiJ9.",
    "eyJzdWIiOiIxMjM0NTY3ODkwIn0.",
    "dozjgNryP4J3jVmNHl0w5N3g1sZz",
)


class TestStructuralRules:
    @pytest.mark.parametrize(
        "rule_id,secret",
        [
            ("aws-access-key-id", AWS_KEY),
            ("github-pat", GITHUB_PAT),
            ("github-fine-grained-pat", FINE_GRAINED),
            ("github-app-token", GITHUB_APP),
            ("stripe-secret-key", STRIPE_LIVE),
            ("stripe-restricted-key", STRIPE_RESTRICTED),
            ("slack-token", SLACK_TOKEN),
            ("slack-webhook", SLACK_WEBHOOK),
            ("google-api-key", GOOGLE_KEY),
            ("private-key-block", PRIVATE_BLOCK),
            ("npm-token", NPM_TOKEN),
            ("sendgrid-key", SENDGRID),
            ("openai-key", OPENAI),
            ("anthropic-key", ANTHROPIC),
            ("jwt", JWT),
        ],
    )
    def test_structural_secret_detected(self, rule_id, secret):
        findings = scan_text('token = "' + secret + '"')
        assert any(f.rule_id == rule_id for f in findings), f"{rule_id} not detected"

    def test_aws_key_rejected_when_too_short(self):
        assert scan_text(_j("AKIA", "IOSFODNN7EXAMPL")) == []  # 15 chars, not 16

    def test_stripe_test_key_not_flagged_as_live(self):
        findings = scan_text("key = '" + _j("sk_test_", "51H8xQ2eZvKYlo2CZx", "1234567890") + "'")
        assert all(f.rule_id != "stripe-secret-key" for f in findings)


class TestEntropyGate:
    def test_placeholder_word_fails_gate(self):
        rule = _rule("generic-secret-assignment")
        assert not value_is_credential_like("your_api_key_here", rule)
        assert not value_is_credential_like("changeme", rule)

    def test_high_entropy_value_passes(self):
        rule = _rule("generic-secret-assignment")
        assert value_is_credential_like("8f2a9c1e4b7d3f6a5c2e1d", rule)

    def test_placeholder_tokens_flagged(self):
        assert is_placeholder("your_api_key_here")
        assert is_placeholder("changeme")
        assert is_placeholder("example_value")
        assert is_placeholder("fake_key")

    def test_benign_values_flagged(self):
        assert is_placeholder("null")
        assert is_placeholder("none")
        assert is_placeholder("true")

    def test_real_value_not_placeholder(self):
        assert not is_placeholder(AWS_KEY)

    def test_entropy_is_zero_for_repeats(self):
        assert shannon_entropy("aaaaaaaa") == 0.0
        assert shannon_entropy("") == 0.0

    def test_entropy_high_for_random(self):
        assert shannon_entropy("8f2a9c1e4b7d3f6a") > 3.0

    def test_looks_random_disabled_at_zero(self):
        assert looks_random("anything", 0.0) is True

    def test_character_class_count(self):
        assert character_class_count("aaaa") == 1
        assert character_class_count("aA1!") == 4


class TestGenericRules:
    def test_real_key_detected(self):
        findings = scan_text('api_key = "8f2a9c1e4b7d3f6a5c2e1d"')
        assert any(f.rule_id == "generic-secret-assignment" for f in findings)

    def test_placeholder_not_detected(self):
        assert scan_text('api_key = "your_api_key_here"') == []

    def test_password_field_with_placeholder_not_detected(self):
        assert scan_text('password = "changeme"') == []

    def test_bearer_token_detected(self):
        findings = scan_text("Authorization: Bearer 8f2a9c1e4b7d3f6a5c2e1d9f")
        assert any(f.rule_id == "generic-bearer-token" for f in findings)

    def test_bearer_with_placeholder_not_detected(self):
        assert scan_text("Authorization: Bearer your_token_here") == []


class TestNoFalsePositiveOnProse:
    def test_documentation_not_flagged(self):
        text = (
            "This section explains how the password field is used. "
            "Your password must be strong and unique. Change it often."
        )
        assert scan_text(text) == []

    def test_english_sentence_not_flagged(self):
        assert scan_text("The quick brown fox jumps over the lazy dog.") == []


class TestDeduplication:
    def test_same_secret_once(self):
        value = "8f2a9c1e4b7d3f6a5c2e1d"
        text = 'api_key = "' + value + '"\npassword = "' + value + '"'
        findings = scan_text(text)
        assert len(findings) == 1

    def test_different_secrets_both_reported(self):
        text = (
            'api_key = "8f2a9c1e4b7d3f6a5c2e1d"\n'
            'password = "9e3b0d2f5c6a7e8d1b4f3a"'
        )
        assert len(scan_text(text)) == 2


class TestLineNumbering:
    def test_line_and_column_reported(self):
        findings = scan_text('x = 1\naws_id = "' + AWS_KEY + '"')
        finding = findings[0]
        assert finding.line == 2
        assert finding.column >= 9
