# Changelog

## 0.1.0 — 2026-10-26

- First release: `scan`, `sanitize`, `spotlight` and `revealHidden`.
- Detects Unicode tag smuggling, variation-selector smuggling, zero-width and bidi characters,
  homoglyphs, hidden HTML/comments/attributes, exfiltration URLs, base64-encoded instructions and
  instruction phrases in English, Portuguese and Spanish (with leetspeak and full-width folding).
- `prompt-sentry` CLI with JSON output and CI-friendly exit codes.
