# Contributing

Thanks for helping improve Gmail Auto Printer. This is an **experimental public source project** with important live-safety limitations.

- Open an issue describing the problem or propose a small, focused pull request.
- Work on a separate branch and include tests for behavior changes. Run `python -m pytest -q`, `python -m ruff check .`, and `python main.py dry-run` locally when dependencies are available.
- Keep the core offline-testable: no real Gmail, printer, credentials or Defender dependency during unit tests.
- Never commit or attach private OAuth files, actual email content, logs, scanned files, printer spool output, or SQLite state. Use synthetic `example.invalid` identities only.
- Do not silently enable live mode, bypass independent validation gates, retry ambiguous print submissions or change Gmail message state.
- Explain new dependencies and their licensing/security implications. Do not submit bundled proprietary applications or third-party binaries.
- For security-sensitive issues, follow [SECURITY.md](SECURITY.md); don't open a public issue with exploit details or personal information.

By contributing, you agree that your contribution will be made available under this repository's MIT license and that you have the necessary rights to submit it.
