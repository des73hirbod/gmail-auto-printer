"""One-attempt PDF submission through an exact named SumatraPDF backend.

SUBMITTED means exit zero; neither physical printing nor a spooler job ID
can be inferred. UNKNOWN requires manual reconciliation, never an auto retry.
"""
import asyncio
from dataclasses import dataclass
import math
import os
from pathlib import Path
import re
import subprocess
import threading


@dataclass(frozen=True)
class PrintResult:
    status: str
    detail: str


class PrinterManager:
    def __init__(self, printer_name, sumatra_pdf_path=None, debug_mode=False, timeout=60,
                 runner=None, printer_checker=None):
        self.printer_name = printer_name
        self.sumatra_pdf_path = Path(sumatra_pdf_path) if sumatra_pdf_path is not None else None
        self.debug_mode = debug_mode
        if isinstance(timeout, bool) or not isinstance(timeout, (float, int)) or not math.isfinite(timeout) or not 0 < timeout <= 300:
            raise ValueError("Invalid print timeout")
        self.timeout = timeout
        self._runner = runner if runner is not None else subprocess.run
        self._printer_checker = printer_checker if printer_checker is not None else self._windows_printer_available
        self._submission_lock = threading.Lock()

    @staticmethod
    def _valid_printer_name(name):
        return (isinstance(name, str) and bool(name) and name == name.strip() and len(name) <= 255
                and name[0] not in "-/" and not any(ord(c) < 32 or ord(c) == 127 or c in "\"'" for c in name))

    @staticmethod
    def _windows_printer_available(name):
        """Read exact printer metadata only; never create or delete a job."""
        if os.name != "nt":
            return False
        try:
            import win32print
            handle = win32print.OpenPrinter(name)
            try:
                info = win32print.GetPrinter(handle, 2)
                if info.get("pPrinterName") != name:
                    return False
                unavailable = 0x2 | 0x8 | 0x10 | 0x80 | 0x1000 | 0x100000
                return not (int(info.get("Status", 0)) & unavailable or int(info.get("Attributes", 0)) & 0x400)
            finally:
                win32print.ClosePrinter(handle)
        except Exception:
            return False

    @staticmethod
    def _validate_file(file_path):
        try:
            path = Path(file_path)
            if path.is_symlink() or not path.is_file() or path.suffix.lower() != ".pdf":
                return None
            path = path.resolve(strict=True)
            if any(ord(c) < 32 or ord(c) == 127 for c in str(path)):
                return None
            with path.open("rb") as handle:
                header = handle.read(9)
                handle.seek(0, 2)
                size = handle.tell()
                handle.seek(max(0, size - 2048))
                tail = handle.read(2048)
            if not re.match(rb"%PDF-(?:1\.[0-7]|2\.0)(?:\s|$)", header) or b"%%EOF" not in tail:
                return None
            return path
        except (OSError, ValueError, TypeError):
            return None

    async def preflight(self, file_path=None, copies=1, duplex=False):
        """Return (ready, detail) with no print submission.

        Structural PDF validation belongs to the caller's attachment validator.
        The bounded header/trailer check adds a check at the print boundary.
        """
        if not self._valid_printer_name(self.printer_name):
            return False, "Invalid exact printer name"
        if isinstance(copies, bool) or not isinstance(copies, int) or not 1 <= copies <= 99:
            return False, "Copies must be an integer from 1 to 99"
        if not isinstance(duplex, bool):
            return False, "Duplex must be boolean"
        backend = self.sumatra_pdf_path
        if backend is None or backend.is_symlink() or not backend.is_file() or backend.suffix.lower() != ".exe":
            return False, "Configured SumatraPDF executable is missing or invalid"
        if file_path is not None and self._validate_file(file_path) is None:
            return False, "PDF submission file is missing or invalid"
        try:
            ready = await asyncio.wait_for(asyncio.to_thread(self._printer_checker, self.printer_name), timeout=min(self.timeout, 10))
        except asyncio.CancelledError:
            raise
        except Exception:
            return False, "Exact printer availability could not be established"
        if ready is not True:
            return False, "Exact printer is unavailable or offline"
        return True, "Configured backend and named printer passed preflight"

    def _submit_once(self, command):
        with self._submission_lock:
            return self._runner(command, capture_output=True, text=True, timeout=self.timeout, shell=False,
                                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))

    async def print_file(self, file_path, copies=1, duplex=False):
        try:
            ready, detail = await self.preflight(file_path, copies, duplex)
        except asyncio.CancelledError:
            return PrintResult("FAILED", "Cancelled before backend submission")
        if not ready:
            return PrintResult("FAILED", detail)
        path = self._validate_file(file_path)
        if path is None:
            return PrintResult("FAILED", "PDF changed or became unavailable before submission")
        command = [str(self.sumatra_pdf_path.resolve()), "-print-to", self.printer_name,
                   "-print-settings", f"{copies}x,{'duplex' if duplex else 'simplex'},ignore-pdf-print-settings",
                   "-silent", str(path)]
        try:
            outcome = await asyncio.to_thread(self._submit_once, command)
        except asyncio.CancelledError:
            return PrintResult("UNKNOWN", "Submission cancelled after possible backend launch; manual reconciliation required")
        except subprocess.TimeoutExpired:
            return PrintResult("UNKNOWN", "Backend timed out after possible submission; manual reconciliation required")
        except (FileNotFoundError, PermissionError):
            return PrintResult("FAILED", "Backend could not be launched")
        except Exception:
            return PrintResult("UNKNOWN", "Backend outcome is ambiguous; manual reconciliation required")
        if getattr(outcome, "returncode", None) == 0:
            return PrintResult("SUBMITTED", "Backend accepted submission; physical printing is unconfirmed and no job ID is available")
        return PrintResult("UNKNOWN", "Backend returned failure after possible submission; manual reconciliation required")

    async def initialize(self):
        ready, _ = await self.preflight()
        return ready

    async def test_printer_connectivity(self):
        ready, _ = await self.preflight()
        return ready

    async def cleanup(self):
        """No shared Word/converter lifecycle exists in this PDF-only adapter."""
