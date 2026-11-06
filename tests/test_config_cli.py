"""Configuration boundaries and offline CLI behavior, without native backends."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


class ConfigTests(unittest.TestCase):
    def test_default_config_needs_no_mail_password(self):
        from config import Config
        config = Config()
        self.assertTrue(config.DRY_RUN)
        self.assertEqual(config.ACK_POLICY, "none")
        self.assertFalse(config.ENABLE_AUTO_UPDATE)

    def test_invalid_limits_and_unknown_keys_fail(self):
        from config import Config, ConfigValidationError
        for text in ('max_copies = 0', 'max_copies = true',
                     'max_attachment_size_mb = 999', 'ack_policy = "trash"',
                     'enable_auto_update = true', 'allowed_file_types = ["docx"]'):
            with self.subTest(text=text), tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "config.toml"
                path.write_text(text)
                with self.assertRaises(ConfigValidationError):
                    Config.from_file(path)

    def test_relative_paths_anchor_to_config_not_cwd(self):
        from config import Config
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.toml"
            path.write_text('state_dir = "private"\ncredentials_file = "oauth.json"')
            result = Config.from_file(path)
            self.assertEqual(result.STATE_DB, Path(tmp) / "private" / "state.sqlite3")
            self.assertEqual(result.CREDENTIALS_FILE, Path(tmp) / "oauth.json")

    def test_live_requires_allowlist_named_printer_and_tool(self):
        from config import Config, ConfigValidationError
        with self.assertRaises(ConfigValidationError):
            Config().validate_live()


class CLITests(unittest.TestCase):
    def test_offline_dry_run_reaches_validation_and_durable_sink(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = subprocess.run(
                [sys.executable, str(ROOT / "main.py"), "dry-run"],
                cwd=tmp, capture_output=True, text=True, timeout=40,
                env={**os.environ, "PYTHONIOENCODING": "utf-8"},
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            receipt = json.loads(result.stdout)
            self.assertEqual(receipt["mode"], "OFFLINE_SIMULATION")
            self.assertEqual(receipt["sink_submissions"], 1)
            self.assertEqual(receipt["repeat_submissions"], 0)
            self.assertEqual(list(Path(tmp).iterdir()), [])


class PollingTests(unittest.IsolatedAsyncioTestCase):
    async def test_partial_or_unknown_batch_never_acknowledges(self):
        from main import run_once
        from config import Config
        from attachment_handler import ProcessResult
        class Client:
            acknowledged = []
            async def get_unread_emails(self):
                return [{"id": "synthetic"}]
            async def get_email(self, message_id):
                return {"id": message_id}
            async def mark_read(self, message_id):
                self.acknowledged.append(message_id)
        class Handler:
            async def process_email(self, *_):
                return ProcessResult(submitted=1, unknown=1, acknowledge=False)
        client = Client()
        result = await run_once(Config(ACK_POLICY="mark-read"), client, Handler())
        self.assertEqual(client.acknowledged, [])
        self.assertEqual(result[0]["unknown"], 1)

    async def test_state_failure_aborts_poll_before_later_message(self):
        from main import run_once
        from config import Config
        from state_store import StateStoreError
        class Client:
            fetched = []
            async def get_unread_emails(self):
                return [{"id": "first"}, {"id": "second"}]
            async def get_email(self, message_id):
                self.fetched.append(message_id)
                return {"id": message_id}
        class Handler:
            async def process_email(self, *_):
                raise StateStoreError("Synthetic full disk")
        client = Client()
        with self.assertRaises(StateStoreError):
            await run_once(Config(), client, Handler())
        self.assertEqual(client.fetched, ["first"])

    def test_live_does_not_initialize_without_explicit_flags(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = subprocess.run(
                [sys.executable, str(ROOT / "main.py"), "run", "--once"],
                cwd=tmp, capture_output=True, text=True, timeout=15,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(list(Path(tmp).iterdir()), [])


if __name__ == "__main__":
    unittest.main()
