# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | ✅ |

Until 1.0, security fixes land on the latest minor release.

## Reporting a vulnerability

Please **do not open a public issue.**

Use GitHub's private reporting:
[Report a vulnerability](https://github.com/TheSoloHacker47/scrubber-rb/security/advisories/new)

Or email **thesolohacker47@gmail.com**.

Please include a minimal reproduction and the version you're on. You'll get an
acknowledgement within 72 hours and an assessment within a week.

## What counts as a vulnerability here

This gem's job is to remove sensitive data from text. So:

- **A false negative is a security bug.** If input containing a credential or PII in a
  supported format comes back unredacted, that's a vulnerability, not a feature request —
  especially if the input is attacker-controlled and shaped to evade a detector (unusual
  encodings, separator tricks, boundary manipulation).
- **A partial redaction is a security bug.** Output that leaves part of a secret visible.
- **A ReDoS or unbounded-resource path is a vulnerability.** The Rust `regex` crate is
  linear-time, so this should be impossible for built-in detectors; if you find input that
  makes scanning superlinear, we want to know.
- **A panic or crash across the FFI boundary is a vulnerability.** Every entry point is
  wrapped in `catch_unwind` and should surface as `Scrubber::InternalError`. A process abort
  means the wrapping failed.
- **Memory unsafety** in the native extension — use-after-free, out-of-bounds read, a data
  race in the shared `Engine`.

## What does not count

- **Free-form PII going unredacted.** Names, street addresses, and medical notes are an
  explicit non-goal, stated in the README. Deterministic patterns cannot find them; that needs
  an NER model. This isn't a bug, it's the documented scope.
- **A false positive.** Over-redacting is annoying and we'll fix it, but it doesn't leak
  anything. Open a normal issue.
- **Data your configuration didn't ask for.** If `:aadhaar` isn't in your `detectors:` list,
  Aadhaar numbers won't be redacted. Check your configuration before reporting.

## When you report

Please redact your own reproduction input before sending it. If the input is a real credential,
rotate it first — a bug report is not a safe place for a live key.
