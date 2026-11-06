"""Bounded PDF-only attachment handling with durable at-most-once submission."""
import base64
import binascii
from dataclasses import dataclass
from email.header import decode_header, make_header
import math
import os
from pathlib import Path
import re
import tempfile

from security_validator import normalize_sender, validate_filename
from state_store import StateStore, StateStoreError


def parse_print_subject(subject, max_copies=50, default_copies=1, default_duplex=False):
    """Accept exactly print [N [copies]] [simplex|duplex], ignoring case.

    Horizontal ASCII whitespace separates tokens. Legacy default_copies remains
    in the API, but an omitted copy count always means one.
    """
    if not isinstance(subject, str) or not isinstance(max_copies, int) or isinstance(max_copies, bool) or max_copies < 1:
        return {'error': 'Invalid print command'}
    match = re.fullmatch(r'[ \t]*print(?:[ \t]+([0-9]{1,9})(?:[ \t]+copies)?)?'
                         r'(?:[ \t]+(simplex|duplex))?[ \t]*', subject, flags=re.IGNORECASE | re.ASCII)
    if match is None:
        return {'error': 'Expected print [N [copies]] [simplex|duplex]'}
    copies = int(match.group(1)) if match.group(1) else 1
    if not 1 <= copies <= max_copies:
        return {'error': 'Copy count outside configured limit'}
    duplex = bool(default_duplex) if match.group(2) is None else match.group(2).lower() == 'duplex'
    return {'copies': copies, 'duplex': duplex}


@dataclass
class ProcessResult:
    eligible: int = 0
    submitted: int = 0
    unknown: int = 0
    failed: int = 0
    skipped: int = 0
    acknowledge: bool = False


class AttachmentHandler:
    MAX_MIME_DEPTH = 20
    MAX_MIME_PARTS = 1000

    def __init__(self, config, args=None, docx_converter=None, printer_manager=None,
                 error_notifier=None, security_validator=None, state_store=None):
        self.config = config
        self.printer_manager = printer_manager
        self.security_validator = security_validator
        self.download_dir = Path(config.DOWNLOAD_DIR)
        self._owns_state = state_store is None
        self.state_store = state_store if state_store is not None else StateStore(config.STATE_DB)

    def close(self):
        if self._owns_state:
            self.state_store.close()

    @staticmethod
    def _header(email_data, name):
        headers = email_data.get('payload', {}).get('headers', [])
        if not isinstance(headers, list):
            raise ValueError('Invalid headers')
        values = [h.get('value') for h in headers if isinstance(h, dict)
                  and isinstance(h.get('name'), str) and h['name'].lower() == name]
        if len(values) != 1 or not isinstance(values[0], str):
            raise ValueError('Missing or ambiguous header')
        return str(make_header(decode_header(values[0])))

    def _sender(self, email_data):
        sender = normalize_sender(self._header(email_data, 'from'))
        check = getattr(self.security_validator, 'validate_sender', None)
        if check is not None:
            if not check(sender):
                raise ValueError('Sender is not authorized')
        else:
            allowed = getattr(self.config, 'ALLOWED_SENDERS', ())
            if not allowed:
                target = getattr(self.config, 'TARGET_SENDER', '')
                allowed = (target,) if target else ()
            if not allowed or sender not in {normalize_sender(value) for value in allowed}:
                raise ValueError('Sender is not authorized')
        return sender

    def _attachments(self, email_data):
        """Complete the bounded MIME walk before downloading or printing."""
        found = []
        visited = 0
        maximum = getattr(self.config, 'MAX_ATTACHMENTS', 100)
        if not isinstance(maximum, int) or isinstance(maximum, bool) or not 1 <= maximum <= 100:
            raise ValueError('Invalid attachment count limit')

        def walk(node, path, depth):
            nonlocal visited
            visited += 1
            if visited > self.MAX_MIME_PARTS or depth > self.MAX_MIME_DEPTH or not isinstance(node, dict):
                raise ValueError('MIME bounds exceeded or malformed part')
            body = node.get('body', {})
            if not isinstance(body, dict):
                raise ValueError('Invalid MIME body')
            filename = node.get('filename', '')
            headers = node.get('headers', [])
            if not isinstance(headers, list):
                raise ValueError('Invalid MIME headers')
            declared_attachment = any(isinstance(h, dict) and
                str(h.get('name', '')).lower() == 'content-disposition' and
                str(h.get('value', '')).split(';', 1)[0].strip().lower() == 'attachment'
                for h in headers)
            if filename or body.get('attachmentId') or declared_attachment:
                found.append({'part_id': path, 'filename': filename,
                              'mime_type': node.get('mimeType', ''), 'body': body})
                if len(found) > maximum:
                    raise ValueError('Attachment count limit exceeded')
            children = node.get('parts', [])
            if not isinstance(children, list):
                raise ValueError('Invalid MIME children')
            for index, child in enumerate(children):
                walk(child, path + '.' + str(index), depth + 1)

        walk(email_data.get('payload', {}), 'root', 0)
        return found

    def _limit(self):
        value = getattr(self.config, 'MAX_ATTACHMENT_SIZE_MB', 0)
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
            raise ValueError('Invalid attachment size limit')
        return int(value * 1024 * 1024)

    @staticmethod
    def _check_size(metadata, limit):
        if 'size' in metadata:
            size = metadata['size']
            if isinstance(size, bool) or not isinstance(size, int) or size < 0 or size > limit:
                raise ValueError('Attachment size metadata is outside bounds')

    def _metadata(self, attachment):
        name, mime, body = attachment['filename'], attachment['mime_type'], attachment['body']
        if not isinstance(name, str) or not validate_filename(name) or Path(name).suffix.lower() != '.pdf':
            raise ValueError('Unsafe filename or unsupported attachment format')
        if not isinstance(mime, str) or mime.lower() != 'application/pdf':
            raise ValueError('Unsupported attachment MIME type')
        limit = self._limit()
        self._check_size(body, limit)
        if not body.get('attachmentId') and 'data' not in body:
            raise ValueError('Attachment data is missing')
        if body.get('attachmentId') and not isinstance(body['attachmentId'], str):
            raise ValueError('Invalid attachment identifier')
        return limit

    async def _download(self, attachment, message_id, gmail_client, limit):
        body = attachment['body']
        response = body if 'data' in body else await gmail_client.get_attachment(message_id, body['attachmentId'])
        if not isinstance(response, dict):
            raise ValueError('Invalid attachment response')
        self._check_size(response, limit)
        encoded = response.get('data')
        if not isinstance(encoded, str) or not encoded:
            raise ValueError('Attachment data is missing')
        # Bound allocations before padding, encoding, and base64 decoding.
        if len(encoded) > 4 * ((limit + 2) // 3):
            raise ValueError('Encoded attachment exceeds configured limit')
        if re.fullmatch(r'[A-Za-z0-9_-]+={0,2}', encoded) is None or len(encoded) % 4 == 1:
            raise ValueError('Invalid base64url attachment data')
        try:
            content = base64.b64decode(encoded + '=' * (-len(encoded) % 4), altchars=b'-_', validate=True)
        except (ValueError, binascii.Error) as exc:
            raise ValueError('Invalid base64url attachment data') from exc
        if not content or len(content) > limit:
            raise ValueError('Decoded attachment exceeds configured limit')
        if 'size' in response and response['size'] != len(content):
            raise ValueError('Attachment response size mismatch')
        if 'size' in body and body['size'] != len(content):
            raise ValueError('Attachment metadata size mismatch')
        return content

    async def _process_part(self, attachment, message_id, sender, command, gmail_client):
        part_id = attachment['part_id']
        if not self.state_store.claim(message_id, part_id):
            status = self.state_store.get(message_id, part_id)['status']
            return ('skipped' if status in {'SUBMITTED', 'SKIPPED'} else
                    'unknown' if status in {'UNKNOWN', 'SUBMISSION_ATTEMPTED'} else 'failed'), status in {'SUBMITTED', 'SKIPPED'}
        attempted = False
        retain = False
        temp_dir = path = None
        try:
            limit = self._metadata(attachment)
            if self.security_validator is None or self.printer_manager is None:
                raise ValueError('Validation and printer boundaries are required')
            content = await self._download(attachment, message_id, gmail_client, limit)
            self.download_dir.mkdir(parents=True, exist_ok=True)
            # No remote name is used to construct a local directory or filename.
            temp_dir = Path(tempfile.mkdtemp(prefix='quarantine-', dir=self.download_dir))
            os.chmod(temp_dir, 0o700)
            fd, local_name = tempfile.mkstemp(prefix='attachment-', suffix='.pdf', dir=temp_dir)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(content)
            path = Path(local_name)
            validation = await self.security_validator.validate_attachment(
                sender, attachment['filename'], path, mime_type=attachment['mime_type'])
            if not isinstance(validation, dict) or validation.get('valid') is not True:
                raise ValueError('Attachment validation failed')
            self.state_store.transition(message_id, part_id, 'VALIDATED')
            self.state_store.transition(message_id, part_id, 'READY', artifact_path=str(path))
            # Commit before entering any printer/backend code.
            self.state_store.transition(message_id, part_id, 'SUBMISSION_ATTEMPTED')
            attempted = retain = True
            printed = await self.printer_manager.print_file(path, command['copies'], command['duplex'])
            status = getattr(printed, 'status', 'UNKNOWN')
            if status not in {'SUBMITTED', 'FAILED', 'UNKNOWN'}:
                status = 'UNKNOWN'
            self.state_store.transition(message_id, part_id, status, 'backend_' + status.lower())
            retain = status == 'UNKNOWN'
            return status.lower(), status == 'SUBMITTED'
        except StateStoreError:
            # A failed state commit stops the complete batch immediately.
            raise
        except BaseException as exc:
            status = 'UNKNOWN' if attempted else 'FAILED'
            self.state_store.transition(message_id, part_id, status,
                'submission_requires_reconciliation' if attempted else 'attachment_rejected')
            if not isinstance(exc, Exception):
                raise
            return status.lower(), False
        finally:
            # UNKNOWN inputs remain at their original generated path while a
            # backend may still reference them. No automatic expiry or retry.
            if not retain:
                if path is not None:
                    path.unlink(missing_ok=True)
                if temp_dir is not None:
                    temp_dir.rmdir()

    async def process_email(self, email_data, gmail_client):
        result = ProcessResult()
        try:
            if not isinstance(email_data, dict):
                raise ValueError('Invalid message')
            message_id = email_data.get('id')
            if not isinstance(message_id, str) or not message_id or len(message_id) > 1024:
                raise ValueError('Missing message identity')
            sender = self._sender(email_data)
            command = parse_print_subject(self._header(email_data, 'subject'),
                max_copies=getattr(self.config, 'MAX_COPIES', 50),
                default_duplex=getattr(self.config, 'ENABLE_DUPLEX', False))
            if 'error' in command:
                raise ValueError('Invalid print command')
            attachments = self._attachments(email_data)
        except (ValueError, TypeError, AttributeError, LookupError):
            result.failed = 1
            return result
        result.eligible = len(attachments)
        if getattr(self.config, 'DRY_RUN', False):
            # Production dry run checks metadata only. The offline integration
            # simulator injects local boundaries into an isolated state store.
            for attachment in attachments:
                try:
                    self._metadata(attachment)
                    result.skipped += 1
                except ValueError:
                    result.failed += 1
            return result
        all_safe = bool(attachments)
        for attachment in attachments:
            outcome, safe = await self._process_part(attachment, message_id, sender, command, gmail_client)
            setattr(result, outcome, getattr(result, outcome) + 1)
            all_safe = all_safe and safe
        result.acknowledge = all_safe and getattr(self.config, 'ACK_POLICY', 'none') == 'mark-read'
        return result
