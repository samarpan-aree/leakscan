"""The scan engine.

Two decisions shape this module.

**Skip what cannot hold a secret.** Binary files, minified bundles and lock
files produce noise, not findings. A short allowlist-driven skip list with a
binary NUL-byte probe keeps the run fast and the report clean.

**Deduplicate by value, not by position.** The same key copy-pasted into five
fixtures is one credential to rotate, not five findings. Collapsing on the
secret value means the report answers "how many credentials do I need to
rotate", which is the question that actually matters at 2am.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Iterator, Sequence

from .entropy import character_class_count, looks_random, shannon_entropy
from .redact import redact
from .rules import BENIGN_VALUES, PLACEHOLDER_TOKENS, RULES, Rule, Severity

#: Directories never worth descending into.
SKIP_DIRS: frozenset[str] = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "node_modules",
        "__pycache__",
        ".venv",
        "venv",
        "env",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "dist",
        "build",
        ".next",
        ".nuxt",
        "target",
        "vendor",
        ".terraform",
        "site-packages",
    }
)

#: Extensions that are binary or generated and never carry hand-written code.
SKIP_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".svg",
        ".pdf", ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar",
        ".exe", ".dll", ".so", ".dylib", ".o", ".a", ".class", ".jar",
        ".pyc", ".pyo", ".woff", ".woff2", ".ttf", ".eot", ".otf",
        ".mp3", ".mp4", ".avi", ".mov", ".wav", ".flac", ".mkv",
        ".min.js", ".min.css", ".map",
    }
)

#: Filenames that legitimately contain fake credentials.
SKIP_FILENAMES: frozenset[str] = frozenset(
    {
        "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock",
        "Pipfile.lock", "composer.lock", "Gemfile.lock", "go.sum", "Cargo.lock",
    }
)

#: Skip files larger than this. A real source file is not 2 MB.
MAX_FILE_BYTES = 2 * 1024 * 1024

#: How far into the file the NUL-byte binary probe looks.
_BINARY_PROBE_BYTES = 8192


@dataclass(frozen=True)
class Finding:
    """One credential that needs attention."""

    rule_id: str
    rule_name: str
    severity: Severity
    path: str
    line: int
    column: int
    match: str = ""          # already redacted
    entropy: float = 0.0
    note: str = ""
    line_text: str = ""      # already redacted

    @property
    def key(self) -> tuple[str, str]:
        """Deduplication identity: the same rule on the same value."""

        return (self.rule_id, self.match)

    @property
    def is_critical(self) -> bool:
        return self.severity is Severity.CRITICAL


@dataclass
class ScanResult:
    """Everything a scan produced."""

    findings: Sequence[Finding]
    files_scanned: int = 0
    files_skipped: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def critical(self) -> list[Finding]:
        return [f for f in self.findings if f.severity is Severity.CRITICAL]

    def count_by_severity(self) -> dict[str, int]:
        counts = {severity.value: 0 for severity in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts


def is_placeholder(value: str) -> bool:
    """True when *value* is obviously not a real credential."""

    lowered = value.lower().strip()
    if lowered in BENIGN_VALUES:
        return True
    for token in PLACEHOLDER_TOKENS:
        if token in lowered:
            return True
    return False


def value_is_credential_like(value: str, rule: Rule) -> bool:
    """Apply the entropy and shape gates for a gated rule."""

    if not value or is_placeholder(value):
        return False
    if len(value) < 8:
        return False
    if not looks_random(value, rule.min_entropy):
        return False
    # A generic assignment must at least mix character classes, otherwise it
    # is a sentence fragment such as "the password is stored elsewhere".
    if rule.secret_group and rule.min_entropy > 0.0:
        if character_class_count(value) < 2:
            return False
    return True


def scan_text(
    text: str,
    path: str = "<text>",
    rules: Sequence[Rule] = RULES,
    include_placeholder: bool = False,
) -> list[Finding]:
    """Scan a string and return redacted findings.

    Findings are deduplicated by (rule, redacted value) so a secret repeated
    across many lines is reported once, at its first location.
    """

    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()

    lines = text.splitlines()

    for rule in rules:
        structural = rule.min_entropy == 0.0
        for match in rule.pattern.finditer(text):
            captured = match.group(rule.secret_group)
            if not captured:
                continue

            secret = captured.strip()
            if not secret:
                continue

            if not structural and not include_placeholder:
                if not value_is_credential_like(secret, rule):
                    continue
            elif structural and not include_placeholder and is_placeholder(secret):
                continue

            masked = redact(secret)
            identity = (rule.rule_id, masked)
            if identity in seen:
                continue
            seen.add(identity)

            line_number = text.count("\n", 0, match.start()) + 1
            line_start = text.rfind("\n", 0, match.start()) + 1
            column = match.start() - line_start + 1
            raw_line = lines[line_number - 1] if line_number - 1 < len(lines) else ""

            findings.append(
                Finding(
                    rule_id=rule.rule_id,
                    rule_name=rule.name,
                    severity=rule.severity,
                    path=path,
                    line=line_number,
                    column=column,
                    match=masked,
                    entropy=round(shannon_entropy(secret), 2),
                    note=rule.note,
                    line_text=raw_line.replace(secret, masked)[:200],
                )
            )

    findings.sort(key=lambda f: (f.path, f.line, f.column))
    return findings


def _looks_binary(path: Path) -> bool:
    """A NUL byte in the first 8 KB is a reliable binary signal."""

    try:
        with path.open("rb") as handle:
            return b"\x00" in handle.read(_BINARY_PROBE_BYTES)
    except OSError:
        return True  # unreadable: treat as skip


def should_skip(path: Path) -> bool:
    """True when *path* cannot reasonably contain a hand-written secret."""

    name = path.name
    if name in SKIP_FILENAMES:
        return True
    lowered = name.lower()
    for extension in SKIP_EXTENSIONS:
        if lowered.endswith(extension):
            return True
    return False


def iter_files(root: Path) -> Iterator[Path]:
    """Yield every file under *root* that is worth scanning."""

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for filename in filenames:
            yield Path(dirpath) / filename


def scan_path(
    root: str | Path,
    rules: Sequence[Rule] = RULES,
    max_bytes: int = MAX_FILE_BYTES,
    include_placeholder: bool = False,
) -> ScanResult:
    """Scan a file or directory tree."""

    base = Path(root)
    findings: list[Finding] = []
    scanned = 0
    skipped = 0
    errors: list[str] = []
    seen: set[tuple[str, str]] = set()

    if base.is_file():
        candidates: Iterable[Path] = [base]
    elif base.is_dir():
        candidates = iter_files(base)
    else:
        return ScanResult(findings=[], errors=[f"path not found: {root}"])

    for path in candidates:
        if should_skip(path):
            skipped += 1
            continue
        try:
            if path.stat().st_size > max_bytes:
                skipped += 1
                continue
        except OSError as exc:
            errors.append(f"{path}: {exc}")
            skipped += 1
            continue

        if _looks_binary(path):
            skipped += 1
            continue

        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            errors.append(f"{path}: {exc}")
            skipped += 1
            continue

        scanned += 1
        display = str(path.relative_to(base)) if base.is_dir() else path.name
        for finding in scan_text(text, display, rules, include_placeholder):
            if finding.key in seen:
                continue
            seen.add(finding.key)
            findings.append(finding)

    findings.sort(key=lambda f: (f.path, f.line, f.column))
    return ScanResult(
        findings=findings,
        files_scanned=scanned,
        files_skipped=skipped,
        errors=errors,
    )


__all__ = [
    "MAX_FILE_BYTES",
    "SKIP_DIRS",
    "SKIP_EXTENSIONS",
    "SKIP_FILENAMES",
    "Finding",
    "ScanResult",
    "is_placeholder",
    "iter_files",
    "scan_path",
    "scan_text",
    "should_skip",
    "value_is_credential_like",
]
