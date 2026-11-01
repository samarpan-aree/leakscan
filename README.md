# leakscan

**Secret and credential scanner that stays quiet until it matters.**

Naive secret scanners fail in one of two directions: they miss real keys, or
they report every `password = "changeme"` in your fixtures until someone turns
them off. `leakscan` is built around the second failure mode, because a scanner
that gets disabled catches nothing.

[![CI](https://github.com/samarpan-aree/leakscan/actions/workflows/ci.yml/badge.svg)](https://github.com/samarpan-aree/leakscan/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.9%20%7C%203.10%20%7C%203.11%20%7C%203.12-blue)](https://www.python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Dependencies: none](https://img.shields.io/badge/dependencies-0-brightgreen)](pyproject.toml)
[![Tests: 48](https://img.shields.io/badge/tests-48-brightgreen)](tests/)

---

## Why this exists

Commit a live AWS key and it is valid for hours - attackers scan GitHub for new
credentials continuously, and the median time to exploitation of a leaked cloud
key is measured in minutes, not days. The fix is not "be careful"; it is a
scanner that runs on every push and only speaks when there is something real.

Two design choices do the work:

**Entropy gating.** A regex cannot distinguish `Ab3f9c2e1d8b7a5f4` from
`your_api_key_here` - both are 17 characters matching the same pattern. Shannon
entropy separates them: generated keys sit at ~3.5-4.0 bits/char, prose and
placeholders at ~1.5-2.5. Generic rules require both an entropy threshold *and*
at least two character classes before they report.

**Structural patterns over generic ones.** Where a vendor publishes a fixed
prefix and length (AWS `AKIA`, GitHub `ghp_`, Stripe `sk_live_`), the pattern is
verified structurally - no entropy gate needed, because the prefix is the
proof. Generic "looks like a secret" matching is the last resort, not the first.

## Result on a realistic file

```console
$ cat demo.py
aws = "<a real AWS access key id>"
api_key = "your_api_key_here"
password = "changeme"

$ leakscan demo.py
leakscan: 1 finding(s) across 1 file(s)
  [CRITICAL] demo.py:1:8 AWS access key ID  (AKIA******CDEF)
             AWS long-lived or temporary access key. Rotate in IAM immediately.
```

Three credential-shaped assignments, one real finding. The two placeholders are
silent.

## Install

```bash
pip install git+https://github.com/samarpan-aree/leakscan.git
```

No runtime dependencies. Python 3.9+.

## Usage

```bash
leakscan .                          # scan the current tree
leakscan src/ --fail-on high        # CI gate: fail on high or critical
leakscan . --format sarif -o out.sarif
leakscan . --format json -o out.json
leakscan . --include-placeholder    # tuning mode: show what the gate rejects
```

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | No finding at or above `--fail-on` |
| `1` | Threshold breached - fail the build |
| `2` | Usage error |

Default `--fail-on` is `critical`, so a first install against a legacy repo
reports without breaking CI. Ratchet it to `high` once the backlog is clear.

## What it detects

18 rules across 17 providers. Every structural rule is anchored on a published
vendor format.

| Category | Examples |
| --- | --- |
| Cloud | AWS access key + secret, Google API key |
| Source control | GitHub PAT, fine-grained PAT, App token |
| Payments | Stripe live secret, Stripe restricted |
| Comms | Slack token, Slack webhook, SendGrid, Twilio |
| AI | OpenAI, Anthropic |
| Packages | npm access token |
| Crypto | RSA/EC/OpenSSH/PGP private key blocks |
| Data stores | `postgres://`, `mysql://`, `mongodb+srv://`, `redis://`, `amqp://` with inline password |
| Generic | hardcoded credential assignment, hardcoded bearer token |

## Secrets are always redacted

A scanner's report is itself a security artefact. If it prints the key it
found, then the CI log, the uploaded SARIF file and the ticket quoting the
build all become new copies of the leak.

Every finding shows at most four characters at each end, with a fixed-width
mask between them - never the full value, and never a mask proportional to the
real length:

```
<stripe live key>   ->   sk_l******lo2C
short               ->   [redacted]
```

Secrets at or below 12 characters are hidden entirely, because masking a
12-character key would still leave most of it readable. `--no-redact` is
deliberately not implemented.

## CI integration

```yaml
- name: Secret scan
  run: |
    pip install git+https://github.com/samarpan-aree/leakscan.git
    leakscan . --fail-on high
```

For GitHub code scanning, emit SARIF and upload it - findings become
annotations on the exact line of the pull request:

```yaml
permissions:
  contents: read
  security-events: write

steps:
  - uses: actions/checkout@v4
  - run: pip install git+https://github.com/samarpan-aree/leakscan.git
  - run: leakscan . --format sarif -o leakscan.sarif
  - uses: github/codeql-action/upload-sarif@v3
    with:
      sarif_file: leakscan.sarif
```

## What it skips, and why

Scanning `node_modules` and `package-lock.json` produces noise, not findings.
Skipped by default: `.git`, `node_modules`, virtualenvs, `dist`/`build`,
`target`, `vendor`, `.terraform`; binary and media extensions; lock files; and
any file whose first 8 KB contains a NUL byte (a reliable binary signal).
Files over 2 MB are skipped too - real source is not that large.

## Architecture

```
leakscan/
  rules.py     18 detection rules + placeholder/benign allowlists
  entropy.py   Shannon entropy + character-class check
  redact.py    masking scheme (never emits a full secret)
  scanner.py   walk, skip, dedupe, gate  <- the engine
  report.py    text / JSON / SARIF 2.1.0
  cli.py       argument parsing, exit codes
```

The dependency graph is strictly one-directional: `cli` -> `scanner` ->
(`rules`, `entropy`, `redact`), and `report` reads a `ScanResult` without
knowing how it was produced. No module except `cli` touches the filesystem, and
nothing touches the network - by design, there is no HTTP client in the
codebase.

Deduplication happens by *(rule, redacted value)*, not by position. The same key
pasted into five fixtures is **one** credential to rotate, and the report
answers "how many do I need to rotate", which is the question that matters.

Deeper notes in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Tests

48 tests, no network, no fixtures on disk - every check is a pure function over
a string. Fixture values are assembled at runtime so the test file never
contains a token GitHub push protection would reject.

```bash
pip install -e ".[dev]"
pytest -q
```

CI additionally runs `leakscan leakscan` against its own package source and
asserts zero findings, so the tool must stay clean on itself.

## Roadmap

- [x] Structural + entropy-gated detection
- [x] Redaction that never leaks through any output format
- [x] SARIF 2.1.0 for GitHub code scanning
- [x] Self-scanning CI step
- [ ] Git history scanning (`--history`) - catch keys deleted from HEAD but live in the log
- [ ] Baseline file (`.leakscan-baseline`) to silence accepted findings
- [ ] Custom rule loading from YAML
- [ ] Pre-commit hook distribution
- [ ] Optional vendor validation for revoked-vs-live status

## Limitations, stated plainly

- **No history scanning yet.** A key removed in a later commit is still in the
  git log and still valid. This is the largest gap and the top roadmap item.
- **Generic rules can miss.** A low-entropy password such as
  `MyCompany2024!` will not clear the gate. Structural rules are unaffected.
- **No vendor liveness check.** A reported key may already be revoked; the
  report tells you to rotate, not whether you must.
- **Not a replacement for GitHub secret scanning.** Push protection at the
  platform level catches what never reaches the repository. Use both.

## Ethical use

`leakscan` is defensive tooling: it reads files you point it at, sends nothing
anywhere, and never prints a full secret. Only scan code you own or have written
authorisation to review. See [SECURITY.md](SECURITY.md) for the responsible
disclosure policy.

## License

MIT - see [LICENSE](LICENSE).
