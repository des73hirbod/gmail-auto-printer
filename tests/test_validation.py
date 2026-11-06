"""Offline attachment safety regressions; no account, printer, or AV invocation."""
import asyncio
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import malware_scanner
import security_validator


def pdf_bytes(extra=b""):
    """Small hand-assembled classic-xref PDF, independent of the parser."""
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R " + extra + b" >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] >>",
    ]
    data = b"%PDF-1.4\n"
    offsets = [0]
    for number, content in enumerate(objects, 1):
        offsets.append(len(data))
        data += str(number).encode() + b" 0 obj\n" + content + b"\nendobj\n"
    xref = len(data)
    data += b"xref\n0 4\n0000000000 65535 f \n"
    data += b"".join(f"{offset:010d} 00000 n \n".encode() for offset in offsets[1:])
    data += b"trailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n"
    return data + str(xref).encode() + b"\n%%EOF\n"


def config(scan=False, **kwargs):
    values = dict(ALLOWED_SENDERS=("trusted@example.com",), TARGET_SENDER="trusted@example.com",
                  ENABLE_MALWARE_SCAN=scan, MAX_ATTACHMENT_SIZE_MB=1,
                  TIMEOUT_DEFENDER_SCAN_SECONDS=1, DEFENDER_PATH=None)
    values.update(kwargs)
    return SimpleNamespace(**values)


class ValidationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "document.pdf"
        self.path.write_bytes(pdf_bytes())

    async def asyncTearDown(self):
        self.temp.cleanup()

    async def validate(self, *, cfg=None, scanner=None, sender="trusted@example.com",
                       filename="document.pdf", mime="application/pdf"):
        validator = security_validator.SecurityValidator(cfg or config(), scanner=scanner)
        return await validator.validate_attachment(sender, filename, self.path, mime)

    async def test_well_formed_passive_pdf_allowed_without_av(self):
        result = await self.validate()
        self.assertEqual(result, {"valid": True, "reason": "VALID_PDF_AV_DISABLED"})

    async def test_sender_must_match_exact_allowlist_even_when_av_disabled(self):
        result = await self.validate(sender="other@example.com")
        self.assertFalse(result["valid"])
        self.assertEqual(result["reason"], "SENDER_NOT_ALLOWED")

    async def test_sender_display_name_cannot_authorize_another_mailbox(self):
        result = await self.validate(sender='"trusted@example.com" <other@example.com>')
        self.assertFalse(result["valid"])

    async def test_mime_and_extension_are_independent_of_av(self):
        for name, mime in (("document.pdf", "text/plain"), ("document.txt", "application/pdf"),
                           ("document.docx", "application/pdf"), ("picture.png", "image/png")):
            with self.subTest(name=name, mime=mime):
                self.assertFalse((await self.validate(filename=name, mime=mime))["valid"])

    async def test_pdf_magic_and_eof_required_without_av(self):
        for data in (b"MZ" + pdf_bytes(), b"%PDF-1.4\nnot really a PDF\n%%EOF\n",
                     pdf_bytes().replace(b"%%EOF", b"NOEOF"), pdf_bytes() + b"MZpayload"):
            with self.subTest(data=data[:20]):
                self.path.write_bytes(data)
                self.assertFalse((await self.validate())["valid"])

    async def test_max_size_is_checked_before_parser(self):
        self.path.write_bytes(b"%PDF-1.4\n" + b"x" * 1048576 + b"\n%%EOF\n")
        result = await self.validate()
        self.assertEqual(result, {"valid": False, "reason": "ATTACHMENT_TOO_LARGE"})

    async def test_active_and_embedded_pdf_content_is_rejected(self):
        for content in (b"/OpenAction << /S /JavaScript /JS (app.alert) >>",
                        b"/Names << /EmbeddedFiles << /Names [] >> >>",
                        b"/AA << /O << /S /Launch >> >>",
                        b"/AcroForm << /Fields [] >>", b"/Open#41ction << /S /Java#53cript >>"):
            with self.subTest(content=content):
                self.path.write_bytes(pdf_bytes(content))
                self.assertEqual((await self.validate())["reason"], "PDF_ACTIVE_OR_EMBEDDED_CONTENT")

    async def test_external_stream_file_reference_rejected(self):
        self.path.write_bytes(pdf_bytes(b"/F (external-file)"))
        self.assertEqual((await self.validate())["reason"], "PDF_ACTIVE_OR_EMBEDDED_CONTENT")

    async def test_pdf_page_limit_and_encryption_fail_closed(self):
        from pypdf import PdfWriter
        writer = PdfWriter()
        for _ in range(201):
            writer.add_blank_page(width=100, height=100)
        with self.path.open("wb") as handle:
            writer.write(handle)
        self.assertEqual((await self.validate())["reason"], "PDF_PAGE_LIMIT")
        writer = PdfWriter()
        writer.add_blank_page(width=100, height=100)
        writer.encrypt("test-only")
        with self.path.open("wb") as handle:
            writer.write(handle)
        self.assertEqual((await self.validate())["reason"], "PDF_ENCRYPTED_UNSUPPORTED")

    async def test_changed_file_after_scan_rejected(self):
        async def modify(path):
            path.write_bytes(pdf_bytes(b"/Subject (changed)"))
            return malware_scanner.ScanResult("CLEAN")
        scanner = SimpleNamespace(scan_file=modify)
        self.assertEqual((await self.validate(cfg=config(scan=True), scanner=scanner))["reason"],
                         "ATTACHMENT_CHANGED_DURING_VALIDATION")

    async def test_scan_statuses_fail_closed_and_clean_can_pass(self):
        for status, expected in (("CLEAN", True), ("INFECTED", False), ("UNAVAILABLE", False),
                                 ("ERROR", False), ("bogus", False)):
            with self.subTest(status=status):
                scanner = SimpleNamespace(scan_file=AsyncMock(return_value=malware_scanner.ScanResult(status)))
                result = await self.validate(cfg=config(scan=True), scanner=scanner)
                self.assertEqual(result["valid"], expected)

    async def test_scanner_exception_and_boolean_clean_are_not_success(self):
        for scanner in (SimpleNamespace(scan_file=AsyncMock(side_effect=OSError("no scanner"))),
                        SimpleNamespace(scan_file=AsyncMock(return_value=True))):
            self.assertFalse((await self.validate(cfg=config(scan=True), scanner=scanner))["valid"])

    async def test_eicar_like_fixture_rejected_by_fake_scanner(self):
        # Deliberately not the real EICAR signature: no antivirus trigger in this offline suite.
        self.path.write_bytes(pdf_bytes(b"/Subject (EICAR_TEST_FIXTURE)"))
        scanner = SimpleNamespace(scan_file=AsyncMock(return_value=malware_scanner.ScanResult("INFECTED")))
        result = await self.validate(cfg=config(scan=True), scanner=scanner)
        self.assertEqual(result, {"valid": False, "reason": "MALWARE_INFECTED"})

    async def test_missing_parser_and_parser_timeout_fail_closed(self):
        validator = security_validator.SecurityValidator(config())
        with patch.object(validator, "_inspect_pdf", AsyncMock(return_value="PDF_PARSER_UNAVAILABLE")):
            self.assertFalse((await validator.validate_attachment("trusted@example.com", "x.pdf", self.path))["valid"])

    async def test_actual_parser_deadline_kills_child(self):
        result = await self.validate(cfg=config(PDF_VALIDATION_TIMEOUT_SECONDS=0.000001))
        self.assertEqual(result, {"valid": False, "reason": "PDF_PARSER_TIMEOUT"})

    @unittest.skipUnless(os.name == "nt", "Windows Job Object enforcement")
    async def test_windows_parser_memory_limit_is_enforced(self):
        script = ("import sys;sys.stdin.read(1);\ntry:\n x=bytearray(512*1024*1024)\n"
                  " print('UNBOUNDED')\nexcept MemoryError:\n print('MEMORY_LIMIT')")
        process = await asyncio.create_subprocess_exec(
            getattr(sys, "_base_executable", sys.executable), "-I", "-c", script, stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        job = security_validator._limit_windows_process(process.pid)
        try:
            output, errors = await asyncio.wait_for(process.communicate(b"x"), 10)
            self.assertEqual(process.returncode, 0, errors)
            self.assertEqual(output.strip(), b"MEMORY_LIMIT")
        finally:
            if process.returncode is None:
                process.kill()
                await process.wait()
            job[0].CloseHandle(job[1])

    async def test_symlink_and_reparse_point_rejected(self):
        link = self.path.with_name("link.pdf")
        try:
            link.symlink_to(self.path)
        except (OSError, NotImplementedError):
            # Windows developer mode may prohibit link creation; synthetic lstat covers the guard.
            real_lstat = Path.lstat
            def reparse(path, *args, **kwargs):
                info = real_lstat(path, *args, **kwargs)
                return SimpleNamespace(st_mode=info.st_mode, st_size=info.st_size,
                                       st_file_attributes=0x400)
            with patch.object(Path, "lstat", reparse):
                self.assertFalse((await self.validate())["valid"])
        else:
            validator = security_validator.SecurityValidator(config())
            self.assertFalse((await validator.validate_attachment("trusted@example.com", "link.pdf", link))["valid"])

    async def test_enabled_missing_scanner_fails_closed(self):
        result = await self.validate(cfg=config(scan=True, DEFENDER_PATH=Path(self.temp.name) / "missing.exe"))
        self.assertEqual(result, {"valid": False, "reason": "MALWARE_UNAVAILABLE"})


class HeaderAndFilenameTests(unittest.TestCase):
    def test_sender_single_mailbox_canonicalization(self):
        self.assertEqual(security_validator.normalize_sender("Trusted Person <Trusted@Example.COM>"),
                         "trusted@example.com")

    def test_ambiguous_and_injected_sender_headers_rejected(self):
        for header in ("", "a@example.com, trusted@example.com", "trusted@example.com\r\nBcc:x@example.com",
                       "Group:trusted@example.com;", "trusted@example.com <other@example.com>",
                       "trusted@example.com other@example.com", "x@@example.com", "a..b@example.com",
                       "trusted@example.com,", "trusted@example.com (other@example.net)"):
            with self.subTest(header=header):
                with self.assertRaises(ValueError):
                    security_validator.normalize_sender(header)

    def test_unsafe_windows_filenames_rejected(self):
        for name in ("../a.pdf", "..\\a.pdf", "C:\\a.pdf", "\\\\host\\a.pdf", "a.pdf:stream", "NUL.pdf",
                     "con.any.pdf", "COM1.pdf", "LPT9.pdf", "a.pdf ", "a.pdf.", 'a".pdf', "a'.pdf",
                     "a\n.pdf", "a\x00.pdf", "a\u202e.pdf", "CON .pdf", "a/b.pdf", "a\\b.pdf"):
            with self.subTest(name=name):
                self.assertFalse(security_validator.validate_filename(name))

    def test_normal_filename_preserved(self):
        self.assertTrue(security_validator.validate_filename("Invoice 2026-11.pdf"))


class MalwareScannerTests(unittest.IsolatedAsyncioTestCase):
    async def test_disabled_scanning_never_reports_clean(self):
        scanner = malware_scanner.MalwareScanner(config(scan=False))
        result = await scanner.scan_file(Path("unused.pdf"))
        self.assertEqual(result.status, "UNAVAILABLE")

    async def test_defender_missing_fails_closed(self):
        scanner = malware_scanner.MalwareScanner(config(scan=True, DEFENDER_PATH=Path("missing-defender.exe")))
        self.assertEqual((await scanner.scan_file(Path("unused.pdf"))).status, "UNAVAILABLE")

    async def test_defender_argv_and_return_codes_without_running_defender(self):
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "MpCmdRun.exe"
            executable.touch()
            document = Path(directory) / "valid.pdf"
            document.write_bytes(pdf_bytes())
            for code, expected in ((0, "CLEAN"), (2, "ERROR"), (1, "ERROR"), (99, "ERROR")):
                process = SimpleNamespace(returncode=code, communicate=AsyncMock(return_value=(b"", b"")))
                with patch("malware_scanner.asyncio.create_subprocess_exec", AsyncMock(return_value=process)) as spawn:
                    result = await malware_scanner.MalwareScanner(config(scan=True, DEFENDER_PATH=executable)).scan_file(document)
                self.assertEqual(result.status, expected)
                args = spawn.call_args.args
                self.assertIn("-DisableRemediation", args)
                self.assertIn(str(document.resolve()), args)
                self.assertNotIn("powershell", args)
                self.assertNotIn("shell", spawn.call_args.kwargs)

    async def test_defender_timeout_kills_and_reaps_worker(self):
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "MpCmdRun.exe"
            executable.touch()
            document = Path(directory) / "valid.pdf"
            document.write_bytes(pdf_bytes())
            async def slow():
                await asyncio.sleep(20)
            process = SimpleNamespace(returncode=None, communicate=slow, kill=lambda: None,
                                      wait=AsyncMock(return_value=1))
            with patch("malware_scanner.asyncio.create_subprocess_exec", AsyncMock(return_value=process)):
                result = await malware_scanner.MalwareScanner(config(scan=True, DEFENDER_PATH=executable,
                                                                               TIMEOUT_DEFENDER_SCAN_SECONDS=0.01)).scan_file(document)
            self.assertEqual(result.status, "ERROR")


if __name__ == "__main__":
    unittest.main()
