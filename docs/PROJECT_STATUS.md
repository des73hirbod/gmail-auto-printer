# Project status — `0.1.0rc1`

**Public source preview; operational release remains BLOCKED.** Prepared 2026-11-06. Publishing this code is not an endorsement of unattended printing, deployment to other people's Gmail accounts, or Google's approval of an OAuth client.

## Evidence already available

- Source syntax compiled; original Windows audit ran 85 passed, 1 skipped, and 96 successful pytest subtests. This report's 96 subtests are not additional top-level tests.
- A subsequent isolated Linux run reproduced 85 passed, 1 skipped, 96 successful pytest subtests using a different installed `pypdf` version. Linux tests do not prove native Windows device behavior.
- Offline simulation and packaging were exercised; these do not contact Gmail, Defender or printers.
- The included GitHub Actions workflow for Windows Python 3.11/3.12/3.13 has **not** yet been observed passing on GitHub.

## Known blockers before a production-ready release

1. **Native integration:** A clean Windows install, official SumatraPDF with named printer, real copy/duplex semantics and native Defender scanning must be qualified with harmless fixtures.
2. **Gmail/OAuth:** Use a designated test account under explicit owner control. The allowlist does not authenticate message authors; independently enforced sender authentication is still required. Public OAuth distribution and Google verification are separate decisions.
3. **Recovery and upgrades:** `UNKNOWN` jobs must be reconciled manually; no tested command/workflow exists. There is no automatic legacy JSON-to-SQLite migration. Upgrading from old installations requires preserving and reconciling prior state.
4. **Supply chain and quality:** Check Windows CI status, run Ruff and dependency vulnerability auditing, and verify fresh installation before recommending real deployment. No reliable comparative performance benchmark exists.
5. **PDF compatibility:** This preview intentionally rejects many ordinary PDFs with active/interactive constructs and does not support other file types.

## Safety guarantees and non-guarantees

The SQLite ledger protects a single-state-path process from automatic repeat **submissions**. It cannot prove physical print completion. `SUBMITTED` does not mean a page was printed; `UNKNOWN` does not mean it was not printed. Never automatically resend `UNKNOWN` work and never reset the ledger as a recovery strategy.

No binaries, printer drivers, Google credentials, refresh tokens, example real messages or email attachments are included. There is no automatic updater.
