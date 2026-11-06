#!/usr/bin/env python3
"""Single CLI. Offline simulation by default; live capabilities require explicit flags."""
import argparse
import asyncio
from dataclasses import asdict
import json
from pathlib import Path
import sys

from config import Config, ConfigValidationError


async def run_once(config, client, handler):
    """Do not acknowledge partial or unknown outcomes; never trash messages."""
    from state_store import StateStoreError
    results = []
    for message in await client.get_unread_emails():
        try:
            email_data = await client.get_email(message["id"])
            result = await handler.process_email(email_data, client)
            if result.acknowledge and config.ACK_POLICY == "mark-read":
                await client.mark_read(message["id"])
            results.append(asdict(result))
        except StateStoreError:
            raise
        except Exception:
            # Do not leak remote headers, account identifiers, paths or API error bodies.
            results.append({"failed": 1, "reason": "MESSAGE_PROCESSING_FAILED"})
    return results


def prepare_private_dir(path):
    """Refuse redirected private directories; do not silently migrate old state."""
    path = Path(path).absolute()
    for parent in (path, *path.parents):
        if parent.exists() and (parent.is_symlink() or getattr(parent, "is_junction", lambda: False)()):
            raise ConfigValidationError("Private directory may not contain links or junctions")
    if (path / "processed_ids.json").exists() or Path("processed_ids.json").exists():
        raise ConfigValidationError("Legacy processed state requires explicit migration/reconciliation before live use")
    path.mkdir(parents=True, exist_ok=True)


async def execute(args):
    if args.command in (None, "dry-run"):
        from offline import simulate
        print(json.dumps(await simulate(getattr(args, "fixture", None)), sort_keys=True))
        return 0
    if not args.enable_gmail or (args.command == "run" and not args.enable_print):
        raise ConfigValidationError("Explicit --enable-gmail and, for run, --enable-print are required")
    if sys.platform != "win32":
        raise ConfigValidationError("Live mode is supported on Windows only")
    config = Config.from_file(args.config)
    config.DRY_RUN = False
    config.validate_live()
    prepare_private_dir(config.STATE_DIR)
    from gmail_client import GmailClient
    client = GmailClient(config)
    if args.command == "auth":
        await client.initialize(authenticate=True)
        print(json.dumps({"status": "TOKEN_SAVED_LOCALLY"}))
        return 0
    from attachment_handler import AttachmentHandler
    from printer_manager import PrinterManager
    from security_validator import SecurityValidator
    # Claim exclusive state ownership before opening a network connection.
    handler = AttachmentHandler(
        config,
        printer_manager=PrinterManager(config.PRINTER_NAME, config.SUMATRA_PDF_PATH,
                                       timeout=config.TIMEOUT_SUMATRA_PRINT_SECONDS),
        security_validator=SecurityValidator(config),
    )
    try:
        await client.initialize(authenticate=False)
        while True:
            results = await run_once(config, client, handler)
            print(json.dumps({"mode": "LIVE", "results": results}, sort_keys=True), flush=True)
            if args.once:
                return 1 if any(r.get("failed", 0) or r.get("unknown", 0) for r in results) else 0
            await asyncio.sleep(config.POLL_INTERVAL_SECONDS)
    finally:
        handler.close()


def parser():
    cli = argparse.ArgumentParser(description="Gmail Auto Printer PDF candidate; default is offline simulation")
    sub = cli.add_subparsers(dest="command")
    offline = sub.add_parser("dry-run", help="Local fixture -> real validation/state -> in-memory print sink")
    offline.add_argument("--fixture", type=Path, help="Local JSON list; inline synthetic attachments only")
    for name in ("auth", "run"):
        command = sub.add_parser(name)
        command.add_argument("--config", type=Path, required=True)
        command.add_argument("--enable-gmail", action="store_true")
        if name == "run":
            command.add_argument("--enable-print", action="store_true")
            command.add_argument("--once", action="store_true")
    return cli


def main():
    args = parser().parse_args()
    try:
        return asyncio.run(execute(args))
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        # Fixed type only: exception text may contain private configuration or server payloads.
        print(json.dumps({"status": "BLOCKED", "error_type": type(exc).__name__,
                          "help": "Check configuration and troubleshooting guide; no automatic resubmission."}),
              file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
