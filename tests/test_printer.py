"""All print requests use inert local files and an injected sink."""
import asyncio
import importlib
import inspect
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def load_manager():
    try:
        manager = importlib.import_module("printer_manager").PrinterManager
    except ImportError as exc:
        raise AssertionError("PDF printer must import without Word or optional packages") from exc
    if "runner" not in inspect.signature(manager).parameters:
        raise AssertionError("One-attempt printer adapter must accept an injected runner")
    return manager


class PrintAdapterTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.pdf = self.root / "file.pdf"
        self.pdf.write_bytes(b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n")
        self.exe = self.root / "SumatraPDF.exe"
        self.exe.write_bytes(b"INERT TEST FILE - NEVER EXECUTED")
        self.calls = []

    def tearDown(self):
        self.temp.cleanup()

    def runner(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    def manager(self, **kwargs):
        settings = dict(printer_name="Office Printer", sumatra_pdf_path=self.exe,
                        timeout=1, runner=self.runner, printer_checker=lambda name: True)
        settings.update(kwargs)
        return load_manager()(**settings)

    async def test_copies_and_duplex_are_one_sumatra_submission(self):
        result = await self.manager().print_file(self.pdf, copies=3, duplex=True)
        self.assertEqual(result.status, "SUBMITTED")
        self.assertIn("physical", result.detail.lower())
        self.assertEqual(len(self.calls), 1)
        argv, kwargs = self.calls[0]
        self.assertEqual(argv, [str(self.exe), "-print-to", "Office Printer", "-print-settings", "3x,duplex,ignore-pdf-print-settings", "-silent", str(self.pdf)])
        self.assertIs(kwargs["shell"], False)
        self.assertEqual(kwargs["timeout"], 1)

    async def test_simplex_is_explicit(self):
        result = await self.manager().print_file(self.pdf, copies=1, duplex=False)
        self.assertEqual(result.status, "SUBMITTED")
        self.assertEqual(self.calls[0][0][4], "1x,simplex,ignore-pdf-print-settings")

    async def test_missing_backend_and_offline_printer_never_submit(self):
        for settings in ({"sumatra_pdf_path": self.root / "missing.exe"},
                         {"printer_checker": lambda _: False}):
            with self.subTest(settings=settings):
                result = await self.manager(**settings).print_file(self.pdf)
                self.assertEqual(result.status, "FAILED")
        self.assertEqual(self.calls, [])

    async def test_timeout_and_nonzero_are_unknown_with_no_fallback(self):
        for outcome in (subprocess.TimeoutExpired("sumatra", 1),
                        SimpleNamespace(returncode=1, stdout="", stderr="error")):
            self.calls.clear()

            def failure(argv, **kwargs):
                self.calls.append((argv, kwargs))
                if isinstance(outcome, BaseException):
                    raise outcome
                return outcome

            result = await self.manager(runner=failure).print_file(self.pdf, copies=4)
            self.assertEqual(result.status, "UNKNOWN")
            self.assertEqual(len(self.calls), 1)

    async def test_hostile_printer_names_never_reach_runner(self):
        for name in ("-print-to-default", "/option", "Office\nOther", 'Office " -print-to X', "Office'; start-process evil"):
            with self.subTest(name=name):
                try:
                    result = await self.manager(printer_name=name).print_file(self.pdf)
                except ValueError:
                    continue
                self.assertEqual(result.status, "FAILED")
        self.assertEqual(self.calls, [])

    async def test_invalid_file_and_print_options_never_submit(self):
        bad = self.root / "bad.pdf"
        bad.write_bytes(b"this is not PDF")
        for path, copies, duplex in ((bad, 1, False), (self.pdf, 0, False),
                                      (self.pdf, True, False), (self.pdf, 100, False),
                                      (self.pdf, 1, "false")):
            with self.subTest(path=path, copies=copies, duplex=duplex):
                result = await self.manager().print_file(path, copies, duplex)
                self.assertEqual(result.status, "FAILED")
        self.assertEqual(self.calls, [])

    async def test_cancellation_after_launch_is_unknown(self):
        started = threading.Event()
        release = threading.Event()

        def delayed(argv, **kwargs):
            self.calls.append((argv, kwargs))
            started.set()
            release.wait(2)
            return SimpleNamespace(returncode=0)

        task = asyncio.create_task(self.manager(runner=delayed).print_file(self.pdf))
        await asyncio.to_thread(started.wait, 1)
        task.cancel()
        result = await task
        release.set()
        self.assertEqual(result.status, "UNKNOWN")
        self.assertEqual(len(self.calls), 1)


if __name__ == "__main__":
    unittest.main()
