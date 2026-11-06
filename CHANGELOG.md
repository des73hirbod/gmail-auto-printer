# 0.1.0rc1

- Require exact print commands and an explicit sender allowlist.
- Isolate filename/MIME/size/PDF validation from the antivirus switch; unavailable AV blocks live submissions.
- Replace conflicting processed JSON writers with a locked SQLite per-attachment ledger and unknown-outcome holds.
- Replace print retries/fallbacks with one Sumatra argv submission and explicit FAILED/SUBMITTED/UNKNOWN results.
- Add recursive MIME handling, inline-data decoding, bounded service retries and Gmail pagination.
- Remove trashing, unsigned automatic updates, implicit live startup, Word dependency and private notifications from the candidate.
- Add an offline fixture/sink CLI, regression tests, TOML configuration, package metadata and Windows CI.
- Narrow support to passive PDF; legacy multi-format adapters and launchers are classified in the audit artifacts and excluded pending validation.

Public source preview uses the MIT license. Native printing, native Defender, real OAuth, recovery tooling and cold-install qualification remain operational release gates.
