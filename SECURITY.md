# Ethical use and responsible disclosure

## Intended use

`leakscan` is a **defensive** tool. It reads files you point it at, on disk,
and reports whether they contain hardcoded credentials. It writes nothing,
sends nothing over the network, and never emits a full secret.

Use it on:

- your own repositories, before pushing
- code you have written authorisation to review (client engagements, audits)
- CI pipelines over code you own

Do **not** point it at other people's repositories, machines or private data
without permission. Reading someone else's secrets is unauthorised access in
most jurisdictions, whether or not the tool is automated.

## By design

- **No network calls.** There is no HTTP client in the codebase. Nothing is
  validated against a vendor, nothing is reported to a service.
- **No unredacted output.** Findings store at most four characters per end.
  `--no-redact` is deliberately unimplemented rather than merely discouraged.
- **No credential use.** The tool never attempts to authenticate with anything
  it finds.

## If you find a live secret

1. **Rotate first, investigate second.** Assume compromise; the median time to
   exploitation of a leaked cloud key is minutes.
2. Revoke the old credential rather than adding an IP allowlist around it.
3. Purge the value from git history (`git filter-repo`), because rewriting the
   working tree leaves it readable in the log.
4. Check the provider's audit log for use of the credential between commit and
   rotation.

## Reporting a vulnerability in leakscan

If you find a way to make `leakscan` emit a full secret, read outside the given
target, or otherwise behave unsafely, report it privately via GitHub's
[private vulnerability reporting](https://github.com/samarpan-aree/leakscan/security/advisories/new)
with the affected version, a minimal reproduction and the impact.

Acknowledgement within 72 hours; fix or mitigation within 30 days for confirmed
issues. Credit in the release notes unless you prefer otherwise.

A redaction bypass is treated as high severity: the whole value proposition is
that the report is safe to paste into a ticket.

## Supported versions

| Version | Supported |
| --- | --- |
| 1.x | yes |
