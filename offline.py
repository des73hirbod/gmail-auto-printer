"""Local fixtures and a print sink for the same validation/state pipeline as live mode."""
import base64
from dataclasses import asdict
import io
import json
from pathlib import Path
import tempfile


def sample_message():
    from pypdf import PdfWriter
    stream = io.BytesIO()
    writer = PdfWriter()
    writer.add_blank_page(width=72, height=72)
    writer.write(stream)
    data = stream.getvalue()
    return {
        "id": "offline-message-1",
        "payload": {
            "mimeType": "multipart/mixed",
            "headers": [
                {"name": "From", "value": "sender@example.invalid"},
                {"name": "Subject", "value": "print 1 simplex"},
            ],
            "parts": [{"partId": "1", "filename": "sample.pdf", "mimeType": "application/pdf",
                       "body": {"size": len(data), "data": base64.urlsafe_b64encode(data).decode("ascii")}}],
        },
    }


class OfflineClient:
    """No transport, credential or mailbox mutation capability."""

    async def get_attachment(self, *_):
        raise ValueError("Offline fixtures must contain inline attachment data")


class PrintSink:
    """Record validated submissions in memory; never opens an OS printer."""

    def __init__(self):
        self.submissions = 0

    async def print_file(self, file_path, copies=1, duplex=False):
        from printer_manager import PrintResult
        if not Path(file_path).is_file():
            raise ValueError("Missing simulated print input")
        self.submissions += 1
        return PrintResult("SUBMITTED", "OFFLINE_SINK_ONLY")


async def simulate(fixture=None):
    from attachment_handler import AttachmentHandler
    from config import Config
    from security_validator import SecurityValidator
    messages = [sample_message()]
    if fixture:
        path = Path(fixture)
        if path.stat().st_size > 2 * 1024 * 1024:
            raise ValueError("Offline fixture exceeds 2 MiB")
        messages = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(messages, list) or not 0 < len(messages) <= 100:
            raise ValueError("Offline fixture must contain 1 to 100 Gmail-shaped messages")
    with tempfile.TemporaryDirectory(prefix="gap-offline-") as tmp:
        config = Config(STATE_DIR=Path(tmp), DRY_RUN=False,
                        ALLOWED_SENDERS=("sender@example.invalid",), ENABLE_MALWARE_SCAN=False)
        sink = PrintSink()
        handler = AttachmentHandler(config, printer_manager=sink,
                                    security_validator=SecurityValidator(config))
        results = []
        try:
            for message in messages:
                results.append(asdict(await handler.process_email(message, OfflineClient())))
            first = sink.submissions
            for message in messages:
                await handler.process_email(message, OfflineClient())
            return {"mode": "OFFLINE_SIMULATION", "sink_submissions": first,
                    "repeat_submissions": sink.submissions - first, "results": results}
        finally:
            handler.close()
