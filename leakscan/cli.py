"""Command-line entry point.

Design notes:

* Exit codes are CI-stable: 0 = clean or under threshold, 1 = threshold
  breached (fail the build), 2 = usage error.
* `--fail-on` accepts a severity; any finding at or above it fails the run.
  Default is critical, so a first install does not explode an existing repo
  with legacy keys, but CI can ratchet it to `high` over time.
* `--format json`/`--format sarif` are for machines; the default text renderer
  is for humans and never prints a full secret.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence

from . import __version__
from .report import to_json, to_sarif_string, to_text
from .rules import RULES
from .scanner import scan_path

EXIT_OK = 0
EXIT_FAIL = 1
EXIT_USAGE = 2

_SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="leakscan",
        description=(
            "Scan files and directories for hardcoded secrets and credentials. "
            "High-precision patterns, entropy gating and redacted output."
        ),
        epilog=(
            "Only scan repositories and files you own or are authorised to audit. "
            "Findings are redacted; never log or publish the full secret."
        ),
    )
    parser.add_argument(
        "target", nargs="?", default=".", help="file or directory (default: .)"
    )
    parser.add_argument(
        "--format",
        "-f",
        default="text",
        choices=("text", "json", "sarif"),
        help="output format (default: text)",
    )
    parser.add_argument("--output", "-o", default="", help="write report to a file")
    parser.add_argument(
        "--fail-on",
        default="critical",
        choices=("critical", "high", "medium", "low"),
        help="exit 1 if any finding at or above this severity (default: critical)",
    )
    parser.add_argument(
        "--no-redact",
        action="store_true",
        help="unsupported: findings are always redacted",
    )
    parser.add_argument(
        "--include-placeholder",
        action="store_true",
        help="report placeholder values too (for tuning rules, not for CI)",
    )
    parser.add_argument(
        "--version", action="version", version=f"leakscan {__version__}"
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    target = Path(args.target)
    if not target.exists():
        print(f"leakscan: path not found: {args.target}", file=sys.stderr)
        return EXIT_USAGE

    if args.no_redact:
        # There is deliberately no unredacted mode: findings never store the
        # full value, so there is nothing to reveal. Refuse rather than
        # pretend, because the flag coming back would be a footgun.
        print(
            "leakscan: --no-redact is intentionally unsupported; findings are "
            "always redacted. Re-run without the flag.",
            file=sys.stderr,
        )
        return EXIT_USAGE

    result = scan_path(
        target,
        rules=RULES,
        include_placeholder=args.include_placeholder,
    )

    if args.format == "json":
        rendered = to_json(result)
    elif args.format == "sarif":
        rendered = to_sarif_string(result)
    else:
        rendered = to_text(result)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(rendered)
        print(f"leakscan: wrote {args.format} report to {args.output}")
    else:
        sys.stdout.write(rendered + "\n")

    threshold = _SEVERITY_ORDER[args.fail_on]
    for finding in result.findings:
        if _SEVERITY_ORDER[finding.severity.value] <= threshold:
            return EXIT_FAIL

    return EXIT_OK


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
