"""Scanner behaviour, redaction and report rendering.

Fixtures are joined at runtime (``_j``) so this file never contains a
token-shaped literal that GitHub push protection would reject.
"""

from __future__ import annotations

import json

from leakscan.redact import redact, redact_all, scrub
from leakscan.report import to_dict, to_json, to_sarif, to_text
from leakscan.scanner import ScanResult, scan_path, scan_text, should_skip


def _j(*parts: str) -> str:
    return "".join(parts)


AWS_KEY = _j("AKIA", "0123456789ABCDEF")
STRIPE = _j("sk_live_", "51H8xQ2eZvKYlo2C")


class TestRedaction:
    def test_long_secret_masked(self):
        masked = redact(STRIPE)
        assert masked.startswith("sk_l")
        assert masked.endswith("o2C")
        assert "*" * 6 in masked
        assert "51H8xQ2eZvKYlo2C" not in masked

    def test_short_secret_fully_hidden(self):
        assert redact("short") == "[redacted]"
        assert redact("") == "[redacted]"

    def test_redact_all_preserves_order(self):
        assert redact_all(["aaaaaaaaaaa", "bbbbbbbbbbb"]) == [
            redact("aaaaaaaaaaa"),
            redact("bbbbbbbbbbb"),
        ]

    def test_scrub_replaces_secret(self):
        text = "the key is " + STRIPE + " here"
        scrubbed = scrub(text, [STRIPE])
        assert "51H8xQ2eZvKYlo2C" not in scrubbed


class TestScanner:
    def test_scan_text_finds_real_secret(self):
        findings = scan_text('aws = "' + AWS_KEY + '"')
        assert len(findings) == 1
        assert findings[0].rule_id == "aws-access-key-id"
        assert AWS_KEY not in findings[0].match

    def test_scan_text_clean_text(self):
        assert scan_text("nothing to see here") == []

    def test_should_skip_known_dirs(self):
        from pathlib import Path

        assert should_skip(Path("image.png")) is True
        assert should_skip(Path("bundle.min.js")) is True
        assert should_skip(Path("package-lock.json")) is True

    def test_scan_path_directory(self, tmp_path):
        (tmp_path / "app.py").write_text('key = "' + AWS_KEY + '"')
        (tmp_path / "README.md").write_text("nothing here")
        result = scan_path(tmp_path)
        assert result.files_scanned == 2
        assert len(result.findings) == 1


class TestReport:
    def _result(self):
        findings = scan_text('key = "' + AWS_KEY + '"')
        return ScanResult(findings=findings, files_scanned=1, files_skipped=0)

    def test_text_has_summary(self):
        text = to_text(self._result())
        assert "1 finding" in text
        assert "AWS access key ID" in text

    def test_json_shape(self):
        payload = json.loads(to_json(self._result()))
        assert payload["tool"]["name"] == "leakscan"
        assert payload["summary"]["total"] == 1
        assert payload["findings"][0]["rule_id"] == "aws-access-key-id"

    def test_sarif_shape(self):
        sarif = to_sarif(self._result())
        assert sarif["version"] == "2.1.0"
        run = sarif["runs"][0]
        assert run["tool"]["driver"]["name"] == "leakscan"
        assert run["results"][0]["ruleId"] == "aws-access-key-id"
        assert run["results"][0]["level"] == "error"

    def test_no_full_secret_in_any_render(self):
        result = self._result()
        assert AWS_KEY not in to_text(result)
        assert AWS_KEY not in to_json(result)
        assert AWS_KEY not in json.dumps(to_sarif(result))
