"""Render findings as terminal text, JSON or SARIF 2.1.0.

SARIF is what makes leakscan useful inside a PR: the same findings that scroll
past in the terminal become annotations on the exact line of the diff. GitHub
maps ruleId -> rule and surfaces severity natively.
"""

from __future__ import annotations

import json

from .scanner import ScanResult
from .rules import Severity

SCHEMA_URL = "https://json.schemastore.org/sarif-2.1.0.json"
TOOL_URI = "https://github.com/samarpan-aree/leakscan"

_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
}


def to_text(result: ScanResult) -> str:
    """Terminal output: one line per finding plus a summary."""

    lines: list[str] = []
    lines.append(
        f"leakscan: {len(result.findings)} finding(s) across "
        f"{result.files_scanned} file(s)"
    )

    for finding in result.findings:
        lines.append(
            f"  [{finding.severity.value.upper():8}] {finding.path}:{finding.line}:{finding.column} "
            f"{finding.rule_name}  ({finding.match})"
        )
        if finding.note:
            lines.append(f"             {finding.note}")

    if result.errors:
        lines.append("")
        lines.append("Warnings:")
        for error in result.errors:
            lines.append(f"  - {error}")

    return "\n".join(lines)


def to_dict(result: ScanResult) -> dict:
    """A stable JSON shape for downstream tooling."""

    counts = result.count_by_severity()
    return {
        "tool": {"name": "leakscan", "version": "1.0.0"},
        "summary": {
            "total": len(result.findings),
            "files_scanned": result.files_scanned,
            "files_skipped": result.files_skipped,
            **counts,
        },
        "findings": [
            {
                "rule_id": f.rule_id,
                "rule_name": f.rule_name,
                "severity": f.severity.value,
                "path": f.path,
                "line": f.line,
                "column": f.column,
                "match": f.match,
                "entropy": f.entropy,
                "note": f.note,
            }
            for f in result.findings
        ],
    }


def to_json(result: ScanResult, indent: int = 2) -> str:
    return json.dumps(to_dict(result), indent=indent)


def to_sarif(result: ScanResult) -> dict:
    """SARIF 2.1.0 with one rule per detection rule, results only on failures."""

    rule_ids = sorted({f.rule_id for f in result.findings})
    rules = [
        {
            "id": rule_id,
            "name": rule_id.replace("-", " ").title().replace(" ", ""),
            "shortDescription": {"text": rule_id},
            "helpUri": TOOL_URI,
        }
        for rule_id in rule_ids
    ]

    results = []
    for finding in result.findings:
        message = finding.rule_name
        if finding.note:
            message = f"{message}. {finding.note}"
        results.append(
            {
                "ruleId": finding.rule_id,
                "level": _SARIF_LEVEL[finding.severity],
                "message": {"text": message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": finding.path,
                                "uriBaseId": "%SRCROOT%",
                            },
                            "region": {
                                "startLine": finding.line,
                                "startColumn": finding.column,
                            },
                        }
                    }
                ],
                "properties": {
                    "severity": finding.severity.value,
                    "entropy": finding.entropy,
                    "masked_value": finding.match,
                },
            }
        )

    return {
        "$schema": SCHEMA_URL,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "leakscan",
                        "version": "1.0.0",
                        "informationUri": TOOL_URI,
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }


def to_sarif_string(result: ScanResult, indent: int = 2) -> str:
    return json.dumps(to_sarif(result), indent=indent)


__all__ = [
    "SCHEMA_URL",
    "to_dict",
    "to_json",
    "to_sarif",
    "to_sarif_string",
    "to_text",
]
