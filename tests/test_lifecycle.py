"""Real durable lifecycle with isolated external Gmail and printer boundaries."""
import asyncio
import base64
import importlib
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
try:
    handler = importlib.import_module('attachment_handler')
    state = importlib.import_module('state_store')
except ImportError:
    handler = state = None

PDF = b'%PDF-1.4\nfixture document\n%%EOF\n'


def message(parts=None, subject='print 2 duplex', sender='Sender <sender@example.com>'):
    return {'id': 'message-1', 'payload': {'headers': [
        {'name': 'From', 'value': sender}, {'name': 'Subject', 'value': subject}],
        'parts': parts if parts is not None else [part()]}}


def part(filename='sample.pdf', attachment_id='attachment-1', mime='application/pdf'):
    return {'filename': filename, 'mimeType': mime,
            'body': {'attachmentId': attachment_id, 'size': len(PDF)}}


class FixtureGmail:
    def __init__(self):
        self.calls = []
        self.response = {'data': base64.urlsafe_b64encode(PDF).decode().rstrip('='), 'size': len(PDF)}

    async def get_attachment(self, message_id, attachment_id):
        self.calls.append((message_id, attachment_id))
        return self.response


class FixtureValidator:
    def __init__(self):
        self.calls = []
        self.valid = True

    async def validate_attachment(self, sender_email, filename, file_path, mime_type='application/pdf'):
        self.calls.append((sender_email, filename, Path(file_path), mime_type))
        return {'valid': self.valid, 'reason': 'fixture rejection' if not self.valid else 'validated'}


class FixturePrinter:
    def __init__(self, status='SUBMITTED'):
        self.calls = []
        self.status = status
        self.crash = False

    async def print_file(self, file_path, copies, duplex):
        self.calls.append((Path(file_path), copies, duplex, Path(file_path).read_bytes()))
        if self.crash:
            raise RuntimeError('backend response lost')
        return SimpleNamespace(status=self.status, detail='fixture result')


class LifecycleTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.assertIsNotNone(handler, 'dependency-light durable attachment lifecycle is required')
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.config = SimpleNamespace(DOWNLOAD_DIR=root/'downloads', STATE_DB=root/'state.sqlite3',
            MAX_ATTACHMENT_SIZE_MB=1, MAX_COPIES=10, COPIES=9, ENABLE_DUPLEX=False,
            DRY_RUN=False, ACK_POLICY='mark-read', MAX_ATTACHMENTS=100,
            TARGET_SENDER='sender@example.com')
        self.gmail, self.validator, self.printer = FixtureGmail(), FixtureValidator(), FixturePrinter()
        self.store = state.StateStore(self.config.STATE_DB)
        self.addCleanup(self.store.close)
        self.handler = handler.AttachmentHandler(self.config, printer_manager=self.printer,
            security_validator=self.validator, state_store=self.store)

    async def test_success_uses_real_sender_safe_local_path_and_cleans_download(self):
        result = await self.handler.process_email(message(), self.gmail)
        self.assertEqual((result.eligible, result.submitted, result.failed, result.acknowledge), (1, 1, 0, True))
        sender, filename, path, mime = self.validator.calls[0]
        self.assertEqual((sender, filename, mime), ('sender@example.com', 'sample.pdf', 'application/pdf'))
        self.assertNotEqual(path.name, 'sample.pdf')
        self.assertFalse(path.exists())
        self.assertEqual(self.printer.calls[0][1:], (2, True, PDF))
        self.assertEqual(self.store.get('message-1', 'root.0')['status'], 'SUBMITTED')

    async def test_duplicate_and_subject_change_never_resubmit(self):
        await self.handler.process_email(message(), self.gmail)
        repeated = await self.handler.process_email(message(subject='print 3'), self.gmail)
        self.assertEqual(repeated.submitted, 0)
        self.assertTrue(repeated.acknowledge)
        self.assertEqual(len(self.printer.calls), 1)

    async def test_restart_does_not_resubmit(self):
        await self.handler.process_email(message(), self.gmail)
        self.store.close()
        self.store = state.StateStore(self.config.STATE_DB)
        self.addCleanup(self.store.close)
        restarted = handler.AttachmentHandler(self.config, printer_manager=self.printer,
            security_validator=self.validator, state_store=self.store)
        result = await restarted.process_email(message(), self.gmail)
        self.assertEqual(result.submitted, 0)
        self.assertEqual(len(self.printer.calls), 1)

    async def test_partial_batch_never_acknowledges_or_repeats_success(self):
        result = await self.handler.process_email(message([part(), part('bad.txt', 'a2', 'text/plain')]), self.gmail)
        self.assertEqual((result.submitted, result.failed, result.acknowledge), (1, 1, False))
        again = await self.handler.process_email(message([part(), part('bad.txt', 'a2', 'text/plain')]), self.gmail)
        self.assertFalse(again.acknowledge)
        self.assertEqual(len(self.printer.calls), 1)

    async def test_unnamed_attachment_cannot_be_silently_ignored_in_partial_batch(self):
        unnamed = {'mimeType': 'application/octet-stream',
                   'headers': [{'name': 'Content-Disposition', 'value': 'attachment'}],
                   'body': {'data': 'QQ', 'size': 1}}
        result = await self.handler.process_email(message([part(), unnamed]), self.gmail)
        self.assertEqual((result.submitted, result.failed, result.acknowledge), (1, 1, False))

    async def test_invalid_subject_and_sender_are_rejected_before_download(self):
        for item in [message(subject='print garbage'), message(sender='attacker@example.com'),
                     message(sender='broken sender')]:
            result = await self.handler.process_email(item, self.gmail)
            self.assertFalse(result.acknowledge)
        self.assertEqual(self.gmail.calls, [])
        self.assertEqual(self.printer.calls, [])

    async def test_malicious_remote_filenames_are_rejected_before_download(self):
        for name in ['../escape.pdf', r'C:\\escape.pdf', '/escape.pdf', 'NUL.pdf', 'file.pdf:stream']:
            item = message([part(name)])
            item['id'] = name
            result = await self.handler.process_email(item, self.gmail)
            self.assertEqual(result.failed, 1)
            self.assertFalse(result.acknowledge)
        self.assertEqual(self.gmail.calls, [])

    async def test_validation_is_never_bypassed_by_disabled_malware_scan(self):
        self.config.ENABLE_MALWARE_SCAN = False
        self.validator.valid = False
        result = await self.handler.process_email(message(), self.gmail)
        self.assertEqual((result.failed, result.acknowledge), (1, False))
        self.assertEqual(len(self.validator.calls), 1)
        self.assertEqual(self.printer.calls, [])

    async def test_missing_and_invalid_encoded_data_fail_closed(self):
        for data in [{}, {'data': ''}, {'data': '???'}, {'data': 'QQ', 'size': 99999999}]:
            self.gmail.response = data
            item = message()
            item['id'] = repr(data)
            result = await self.handler.process_email(item, self.gmail)
            self.assertEqual((result.failed, result.acknowledge), (1, False))
        self.assertEqual(self.printer.calls, [])

    async def test_metadata_size_is_checked_before_network_download(self):
        item = message()
        item['payload']['parts'][0]['body']['size'] = 100000000
        result = await self.handler.process_email(item, self.gmail)
        self.assertEqual((result.failed, result.acknowledge), (1, False))
        self.assertEqual(self.gmail.calls, [])

    async def test_nested_inline_attachment_is_processed(self):
        inline = part()
        inline['body'] = {'data': base64.urlsafe_b64encode(PDF).decode(), 'size': len(PDF)}
        item = message([{'mimeType': 'multipart/mixed', 'parts': [inline]}])
        result = await self.handler.process_email(item, self.gmail)
        self.assertEqual((result.submitted, result.acknowledge), (1, True))
        self.assertEqual(self.gmail.calls, [])

    async def test_unknown_backend_result_is_never_retried(self):
        self.printer.crash = True
        result = await self.handler.process_email(message(), self.gmail)
        self.assertEqual((result.unknown, result.acknowledge), (1, False))
        self.assertEqual(self.store.get('message-1', 'root.0')['status'], 'UNKNOWN')
        retained = self.printer.calls[0][0]
        self.assertTrue(retained.exists(), 'UNKNOWN input must remain while a backend may use it')
        self.assertEqual(self.store.get('message-1', 'root.0')['artifact_path'], str(retained))
        await self.handler.process_email(message(), self.gmail)
        self.assertEqual(len(self.printer.calls), 1)

    async def test_cancellation_after_attempt_is_durable_unknown_and_retains_input(self):
        seen = []
        async def cancel(path, copies, duplex):
            seen.append(path)
            raise asyncio.CancelledError()
        self.printer.print_file = cancel
        with self.assertRaises(asyncio.CancelledError):
            await self.handler.process_email(message(), self.gmail)
        self.assertEqual(self.store.get('message-1', 'root.0')['status'], 'UNKNOWN')
        self.assertTrue(seen[0].exists())

    async def test_mime_depth_and_part_limits_fail_before_any_submission(self):
        nested = part()
        for unused in range(22):
            nested = {'parts': [nested]}
        for payload in [[nested], [{'parts': [{} for unused in range(1001)]}]]:
            result = await self.handler.process_email(message(payload), self.gmail)
            self.assertFalse(result.acknowledge)
            self.assertEqual(result.failed, 1)
        self.assertEqual(self.gmail.calls, [])
        self.assertEqual(self.printer.calls, [])

    async def test_durable_attempt_exists_before_backend_call(self):
        original = self.printer.print_file
        async def check(path, copies, duplex):
            self.assertEqual(self.store.get('message-1', 'root.0')['status'], 'SUBMISSION_ATTEMPTED')
            return await original(path, copies, duplex)
        self.printer.print_file = check
        await self.handler.process_email(message(), self.gmail)

    async def test_empty_or_excessive_mime_batch_is_not_acknowledged(self):
        self.assertFalse((await self.handler.process_email(message([]), self.gmail)).acknowledge)
        self.config.MAX_ATTACHMENTS = 1
        self.assertFalse((await self.handler.process_email(message([part(), part()]), self.gmail)).acknowledge)
        self.assertEqual(self.printer.calls, [])

    async def test_dry_run_metadata_only_never_downloads_submits_or_claims(self):
        self.config.DRY_RUN = True
        result = await self.handler.process_email(message(), self.gmail)
        self.assertEqual((result.submitted, result.skipped, result.acknowledge), (0, 1, False))
        self.assertEqual(self.validator.calls, [])
        self.assertEqual(self.gmail.calls, [])
        self.assertEqual(self.printer.calls, [])
        self.assertIsNone(self.store.get('message-1', 'root.0'))
