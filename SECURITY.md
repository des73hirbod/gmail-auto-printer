# Security policy

## Support status

This repository is an **experimental public source preview**, not a security-audited unattended print service. It is not production-supported. The latest reviewed source version is `0.1.0rc1`.

## Report vulnerabilities privately

If GitHub's **Private vulnerability reporting** is enabled for this repository, use the repository **Security** tab to report a vulnerability. If it is not enabled, do not publish working exploits, credentials or private email/print data in public issues; ask the maintainer to establish a private disclosure route first.

## Trust boundaries and known limitations

- Gmail-supplied `From` headers and arbitrary `Authentication-Results` headers are untrusted. The allowlist is **not** cryptographic identity verification; deployments must enforce sender authentication independently.
- PDF parsing and antivirus scanning reduce risk but do not prove parser, renderer or spooler safety. Live mode fails closed if scanning is unavailable, but native Windows Defender and Sumatra integration are still unqualified.
- A fixed named printer is used, not the default. Native paper output, duplex and copy count were not independently measured.
- The SQLite ledger offers at-most-once submission attempts for one ledger owner, not exactly-once physical printing. `UNKNOWN` is held; no automatic retry or operator reconciliation command is provided.
- The original processed-state JSON is not auto-migrated. Do not reset the ledger or run multiple instances with independent state against the same inbox.
- Private Gmail identifiers and quarantined inputs can persist locally. Protect their state directory with local-user permissions and back it up before upgrades.
- Automatic updates, mailbox trashing, and unapproved network telemetry are absent. Live Gmail and print access require explicit flags.

## Secrets and dependencies

Never add `.env`, `config.toml`, `credentials.json`, `token.json`, state databases, actual email attachments, private reports, or backups to GitHub, including commit history. If an old token has been exposed, revoke/rotate it independently. This repository has no bundled OAuth client, SumatraPDF executable, or Microsoft Defender binary. Dependencies and externally installed applications retain their own licenses.

See [project status](docs/PROJECT_STATUS.md) for open release gates.
