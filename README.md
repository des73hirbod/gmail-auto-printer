# Gmail Auto Printer

**Experimental, PDF-only Windows automation** that reads Gmail messages with an exact print command, validates PDF attachments, and submits them to a specifically configured printer.

## Features

- A strict subject grammar: `print`, `print 2`, `print 2 copies duplex`, or `print simplex` (case-insensitive). Unexpected instructions do not print.
- Explicit sender allowlist and attachment filename, MIME, size, structural PDF and antivirus validation.
- SQLite operation ledger with at-most-once **submission attempts**. Ambiguous submissions are held for manual review instead of retried automatically. No physical exactly-once guarantee.
- Gmail messages are never trashed. Default acknowledgment policy does not change messages; optional `mark-read` is explicit.
- Named Windows printer and single SumatraPDF command; no fallback printers or automatic software updates.
- Fully offline simulation and regression tests. Live Gmail/printing requires separate explicit CLI flags.

**Accepted PDFs:** a deliberately limited passive PDF 1.0–1.7 subset using classic xref tables, up to 200 pages and 2,000 objects. Forms, annotations, links/actions, embedded content, encryption, compressed objects, and PDF 2.0 are rejected. DOC/DOCX, image and TXT printing are **not supported** in this preview.

## Quick start — safe offline demo

Requires Python **3.11–3.13**; Python 3.12 is the principal version used in the original Windows audit. Run these commands in PowerShell from this repository folder:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe main.py dry-run
```

`dry-run` creates a synthetic PDF, validates it, stores simulated states in a temporary SQLite database, and uses an **in-memory** print sink. It opens no Gmail connection and prints nothing. The simulator should report one submission and then skip the duplicate. To use a synthetic fixture, see `python main.py dry-run --help`; **never commit private email fixtures**.

If Python 3.12 is unavailable, install it or use 3.11/3.13; the full clean-install version matrix has not yet been validated. If dependency installation fails, the offline demo cannot run until dependencies are available.

## Live setup — advanced, not yet qualified

**Do not enable live mode without controlling the mailbox, printer, and state directory.** For a personal, isolated Windows test setup only:

1. Create **your own** Google Cloud project and desktop OAuth client for the Gmail API. Keep `credentials.json` and `token.json` private. The repository contains **no** shared OAuth client.
2. Install and verify a trusted current SumatraPDF build and Windows Defender. Configure a **specific** printer; no default printer is used.
3. Copy `config.example.toml` to `config.toml`. Replace the example mailbox with a dedicated address and set absolute local paths to the private credentials, token, state directory, printer backend, and Defender executable.
4. Start with `ack_policy = "none"`. Only after reviewing the safety limitations, run the following commands deliberately, one at a time:

```powershell
.\.venv\Scripts\python.exe main.py auth --config config.toml --enable-gmail
.\.venv\Scripts\python.exe main.py run --config config.toml --enable-gmail --enable-print --once
```

`auth` can open a browser and save a personal OAuth token; `run` can read the configured mailbox and submit real print jobs. **Neither command was executed against a real environment in this repository's verification.** The `gmail.readonly` and `gmail.modify` scopes are restricted; public OAuth distribution may require Google review. Public GitHub source availability **does not** grant OAuth approval.

**Sender security:** An allowlisted `From` header is **not authenticated sender identity**. An external, independently enforced authentication policy on a dedicated inbox is required before unattended use. There is no built-in trusted DKIM/SPF/DMARC validation chain.

**Recovery safety:** The ledger distinguishes `SUBMITTED`, `FAILED`, and `UNKNOWN`. A zero backend exit code means command acceptance, not confirmed paper output. `UNKNOWN` jobs are not auto-retried, and the current preview has **no tested operator reconciliation/retry command or legacy processed-state migration**. Never delete or reset the SQLite database to force a retry: doing so can cause duplicates. Do not run two installations against the same inbox.

## Project status and how to contribute

- [Known limitations and test evidence](docs/PROJECT_STATUS.md)
- [Security policy](SECURITY.md)
- [Contribution guidelines](CONTRIBUTING.md)
- [Changelog](CHANGELOG.md)

Contributions and forks are welcome, especially for Windows integration testing (with safe fake test accounts/devices), reliable recovery workflows, accessibility and documentation. Please do **not** upload real mailbox contents, tokens or private print files to issues or pull requests.

## License

MIT — see [LICENSE](LICENSE). This license covers the repository's original project code; third-party packages and locally installed applications keep their respective licenses. Ensure you have rights to any code you add.
