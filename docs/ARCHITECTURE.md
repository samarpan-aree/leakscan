# Architecture

## Two constraints shaped everything

**Precision is the product.** A secret scanner that reports placeholders gets
disabled within a week, and a disabled scanner catches nothing. Every design
decision below is downstream of that.

**The report is itself an artefact.** Whatever the tool prints lands in CI logs,
uploaded SARIF files and tickets. If a full secret appears in any of those, the
remediation process created a new leak. So redaction happens at finding-creation
time, not at render time - there is no full secret stored anywhere after the
scan returns.

## Module graph

```
cli.py
  +-- scanner.py
        +-- rules.py    (patterns, severities, allowlists)
        +-- entropy.py  (Shannon + character classes)
        +-- redact.py   (masking)
  +-- report.py         (consumes ScanResult, never re-reads files)
```

Strictly one-directional. `report.py` depends on `scanner.ScanResult` for its
type but never calls back into scanning. There is no HTTP client anywhere in the
codebase, which makes "sends nothing anywhere" a structural guarantee rather
than a promise.

## Why entropy gating

Given this line, a generic assignment regex can match it:

```
api_key = "<something>"
```

So can a real generated key. Both are assignments to a credential-shaped name
with a string value. The difference is not syntactic, it is statistical: a
generated key draws from ~60 possible characters with little repetition, while a
placeholder is English with repeated letters.

Shannon entropy, bits per character:

| Value | Entropy | Verdict |
| --- | --- | --- |
| `aaaaaaaaaaaaaaaa` | 0.00 | reject |
| `your_api_key_here` | 3.09 | reject (placeholder token, and no digit) |
| `changeme` | 2.75 | reject (placeholder token) |
| `Ab3f9c2e1d8b7a5f4` | 4.00 | accept |
| a live Stripe key | 4.16 | accept (structural rule, gate unused) |

The generic rule requires entropy >= 3.2 **and** at least two character
classes. The class check catches `MyCompanyPassword`, which is high-entropy for
a word but is clearly not a key.

Thresholds are per-rule. A password inside a `postgres://` URI clears a lower bar
than a hex API key, because URI passwords are often short and human-chosen but
are still live credentials.

## Why structural rules carry no gate

A vendor that publishes the `AKIA` prefix and 16 base32 characters has given
us a fixed format. Any string matching it is an AWS key ID with overwhelming
probability - placeholder or not, it deserves a look, because the alternative is
missing a real one. Structural rules therefore skip the entropy gate entirely
and only run the placeholder-token check.

This is why a well-formed AWS key id is caught while `your_api_key_here` is not:
one matched a vendor format, the other matched a generic pattern and failed the
statistical gate.

## Deduplication by value

Findings are keyed on *(rule_id, redacted_value)*, not on file path and line.
A key copy-pasted into five test fixtures is one credential to rotate. The
report answers "how many secrets need rotating", which is the question someone
actually has at 2am - not "how many lines match a regex".

The trade-off: two genuinely different keys that happen to redact to the same
mask would collapse. With four visible characters at each end plus a rule-scoped
key, that requires two secrets sharing their first four and last four characters
*and* their rule - acceptable, and preferable to a report that multiplies.

## The redaction scheme

```python
redact(stripe_live_example)   # -> "sk_l******lo2C"
redact("short")               # -> "[redacted]"
```

- Four characters kept at each end, so a human can identify *which* key it is.
- A fixed six-character mask, never proportional to real length - length is a
  weak signal, but there is no reason to publish it.
- Anything <= 12 characters is hidden entirely. Masking a 12-character key to
  `sk_l***bcde` would leave most of it readable.

`scrub()` additionally replaces any occurrence of a secret in a free-text field,
so a message that quotes the matched line cannot smuggle the value out.

## Skip logic

Three cheap filters, applied in cost order:

1. **Filename and extension** - a set lookup, no I/O. Excludes lock files,
   binaries and media.
2. **Size** - `stat()` only. Files over 2 MB are not hand-written source.
3. **Binary probe** - reads the first 8 KB looking for a NUL byte. Catches
   mislabelled binaries that survived the extension check.

Directories are pruned during `os.walk` rather than filtered afterwards, so
`node_modules` with 40,000 files costs one comparison, not 40,000.

## Known limitations

- **No git history scanning.** A key deleted from HEAD but still in the log is
  a real exposure this tool does not see. This is the top roadmap item.
- **Low-entropy human passwords pass through.** `MyCompany2024!` will not clear
  the gate on a generic rule. Structural vendor patterns are unaffected.
- **No liveness check.** The tool reports that a credential exists, not whether
  it has already been revoked. Sending the key to the vendor to check would
  itself be the abuse we are trying to prevent.
- **Regex is not a parser.** A key split across two lines, or base64-embedded
  inside another value, will not be found.

## Testing approach

Every check is a pure function over a string, so the suite needs no network and
no fixture files - 48 tests run in under 50 ms. Rule tests use generated values
of the correct shape rather than documentation examples, because canonical
examples are correctly rejected as placeholders and would make a passing suite
lie about coverage.

Fixture strings are assembled at runtime from fragments. GitHub's push
protection rejects any file containing a token-shaped literal, and a secret
scanner's test suite is nothing but token-shaped strings - so the file on disk
never contains a matchable credential while every rule is still exercised.

CI adds one integration assertion the unit tests cannot make: leakscan scans its
own package source and must report zero findings. That catches a docstring or
comment that accidentally contains a real-looking credential.
