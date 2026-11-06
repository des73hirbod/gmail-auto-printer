"""Independent sender/path/MIME/size/PDF gates, plus separate fail-closed AV.

From-header allowlisting is routing policy, not cryptographic authentication.
PDF parsing runs in a memory- and time-bounded subprocess.
"""
import asyncio
import hashlib
import io
import json
import math
import os
import re
import stat
import sys
import sysconfig
import unicodedata
from email import policy
from email.parser import Parser
from pathlib import Path

MAX_PDF_BYTES = 25 * 1024 * 1024
PDF_MEMORY_BYTES = 256 * 1024 * 1024
PDF_TIMEOUT_SECONDS = 10
MAX_PDF_OBJECTS = 2000
MAX_PDF_PAGES = 200
_LOCAL = re.compile(r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*\Z")
_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z")

def normalize_sender(header):
    """Return one unambiguous ASCII mailbox, canonicalized to lowercase."""
    if (not isinstance(header, str) or not header.strip() or len(header) > 998
            or header.rstrip().endswith((",", ";")) or "(" in header or ")" in header
            or any(ord(c) < 32 or ord(c) >= 127 for c in header)):
        raise ValueError("INVALID_SENDER_HEADER")
    try:
        parsed = Parser(policy=policy.default).parsestr("From: " + header + "\n\n")["From"]
        addresses = parsed.addresses
        if (parsed.defects or len(addresses) != 1
                or any(group.display_name is not None for group in parsed.groups)):
            raise ValueError("AMBIGUOUS_SENDER_HEADER")
        address = addresses[0]
        local, domain = address.username, address.domain
        labels = domain.split(".")
        if (not _LOCAL.fullmatch(local) or len(local) > 64 or len(address.addr_spec) > 254
                or len(labels) < 2 or any(not _LABEL.fullmatch(label) for label in labels)):
            raise ValueError("INVALID_SENDER_ADDRESS")
        return (local + "@" + domain).lower()
    except (AttributeError, IndexError, TypeError) as exc:
        raise ValueError("INVALID_SENDER_HEADER") from exc

def validate_filename(name):
    """Reject hostile names rather than silently repairing remote input."""
    if not isinstance(name, str) or not name or name[-1] in " ." or name[0] in " .":
        return False
    try:
        if len(name.encode("utf-8")) > 255:
            return False
    except UnicodeError:
        return False
    if (".." in name or any(c in name for c in '/\\:|<>"\'*?')
            or any(unicodedata.category(c).startswith("C") for c in name)):
        return False
    stem = name.split(".", 1)[0].rstrip(" .").upper()
    if stem in {"CON", "PRN", "AUX", "NUL", "CLOCK$", "CONIN$", "CONOUT$"}:
        return False
    return re.fullmatch(r"(?:COM|LPT)[1-9¹²³]", stem) is None

def _read_regular_file(file_path, max_bytes):
    """Bound reads, reject link/reparse ancestors, and compare opened identity."""
    path = Path(file_path).absolute()
    for item in (path, *path.parents):
        info = item.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError("UNSAFE_FILE_PATH")
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise ValueError("UNSAFE_FILE_PATH")
    if info.st_size > max_bytes:
        raise ValueError("ATTACHMENT_TOO_LARGE")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as handle:
        opened = os.fstat(handle.fileno())
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
            raise ValueError("UNSAFE_FILE_PATH")
        data = handle.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ValueError("ATTACHMENT_TOO_LARGE")
    return data

def _limit_windows_process(pid):
    """Limit stdin-blocked parser using a private Windows Job Object."""
    import ctypes
    from ctypes import wintypes
    class Basic(ctypes.Structure):
        _fields_ = [("user_time", ctypes.c_longlong), ("job_time", ctypes.c_longlong),
                    ("flags", wintypes.DWORD), ("min_working_set", ctypes.c_size_t),
                    ("max_working_set", ctypes.c_size_t), ("active_processes", wintypes.DWORD),
                    ("affinity", ctypes.c_size_t), ("priority", wintypes.DWORD), ("scheduling", wintypes.DWORD)]
    class Counters(ctypes.Structure):
        _fields_ = [(field, ctypes.c_ulonglong) for field in
                    ("read_ops", "write_ops", "other_ops", "read_bytes", "write_bytes", "other_bytes")]
    class Extended(ctypes.Structure):
        _fields_ = [("basic", Basic), ("io", Counters), ("process_memory", ctypes.c_size_t),
                    ("job_memory", ctypes.c_size_t), ("peak_process", ctypes.c_size_t), ("peak_job", ctypes.c_size_t)]
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    kernel.CreateJobObjectW.restype = wintypes.HANDLE
    kernel.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    kernel.SetInformationJobObject.restype = wintypes.BOOL
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    kernel.AssignProcessToJobObject.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    job = kernel.CreateJobObjectW(None, None)
    if not job:
        raise OSError("PDF_RESOURCE_LIMIT_UNAVAILABLE")
    process = None
    try:
        limits = Extended()
        limits.basic.flags = 0x100 | 0x2000 | 0x8
        limits.basic.active_processes = 1
        limits.process_memory = PDF_MEMORY_BYTES
        if not kernel.SetInformationJobObject(job, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
            raise OSError("PDF_RESOURCE_LIMIT_UNAVAILABLE")
        process = kernel.OpenProcess(0x100 | 0x1, False, pid)
        if not process or not kernel.AssignProcessToJobObject(job, process):
            raise OSError("PDF_RESOURCE_LIMIT_UNAVAILABLE")
        return kernel, job
    except BaseException:
        kernel.CloseHandle(job)
        raise
    finally:
        if process:
            kernel.CloseHandle(process)

class SecurityValidator:
    def __init__(self, config, error_notifier=None, scanner=None):
        from malware_scanner import MalwareScanner
        self.config = config
        self.malware_scanner = scanner if scanner is not None else MalwareScanner(config, error_notifier)

    def validate_sender(self, sender):
        try:
            canonical = normalize_sender(sender)
            allowed = tuple(normalize_sender(value) for value in self.config.ALLOWED_SENDERS)
            return bool(allowed) and canonical in allowed
        except (ValueError, TypeError, AttributeError):
            return False

    async def validate_attachment(self, sender_email, filename, file_path, mime_type="application/pdf"):
        from malware_scanner import ScanResult
        def reject(reason):
            return {"valid": False, "reason": reason}
        if not self.validate_sender(sender_email):
            return reject("SENDER_NOT_ALLOWED")
        if not validate_filename(filename):
            return reject("UNSAFE_FILENAME")
        if Path(filename).suffix.lower() != ".pdf":
            return reject("UNSUPPORTED_FILE_TYPE_PDF_ONLY")
        if mime_type != "application/pdf":
            return reject("MIME_MISMATCH")
        try:
            size_mb = float(self.config.MAX_ATTACHMENT_SIZE_MB)
            if not math.isfinite(size_mb) or size_mb <= 0 or size_mb > 25:
                return reject("INVALID_SIZE_POLICY")
            max_bytes = int(size_mb * 1024 * 1024)
            data = _read_regular_file(file_path, max_bytes)
            if not re.match(rb"%PDF-1\.[0-7](?:\r\n|\r|\n)", data):
                return reject("PDF_HEADER_INVALID")
            if not data.rstrip(b" \t\r\n").endswith(b"%%EOF"):
                return reject("PDF_EOF_INVALID")
            parser_reason = await self._inspect_pdf(data)
            if parser_reason != "VALID_PDF":
                return reject(parser_reason)
            if self.config.ENABLE_MALWARE_SCAN:
                result = await self.malware_scanner.scan_file(Path(file_path))
                if not isinstance(result, ScanResult) or result.status != "CLEAN":
                    status = result.status if isinstance(result, ScanResult) else "ERROR"
                    return reject("MALWARE_" + (status if status in {"INFECTED", "UNAVAILABLE", "ERROR"} else "ERROR"))
            after = _read_regular_file(file_path, max_bytes)
            if hashlib.sha256(after).digest() != hashlib.sha256(data).digest():
                return reject("ATTACHMENT_CHANGED_DURING_VALIDATION")
            return {"valid": True, "reason": "VALID_PDF" if self.config.ENABLE_MALWARE_SCAN else "VALID_PDF_AV_DISABLED"}
        except ValueError as exc:
            return reject(str(exc) if str(exc) in {"UNSAFE_FILE_PATH", "ATTACHMENT_TOO_LARGE"} else "VALIDATION_ERROR")
        except Exception:
            return reject("VALIDATION_ERROR")

    async def _inspect_pdf(self, data):
        process = None
        job = None
        try:
            process = await asyncio.create_subprocess_exec(
                # Windows venv python.exe is a redirector. Start the real interpreter
                # directly so its PID, rather than only a launcher, receives the job limit.
                getattr(sys, "_base_executable", sys.executable), "-I", "-S", "-c",
                "import runpy,sys;sys.path.append(sys.argv.pop(1));"
                "script=sys.argv.pop(1);runpy.run_path(script,run_name='__main__')",
                sysconfig.get_path("purelib"), str(Path(__file__).resolve()), "--inspect-pdf",
                stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
            if os.name == "nt":
                job = _limit_windows_process(process.pid)
            timeout = getattr(self.config, "PDF_VALIDATION_TIMEOUT_SECONDS", PDF_TIMEOUT_SECONDS)
            output, _ = await asyncio.wait_for(process.communicate(data), timeout=timeout)
            if process.returncode != 0 or len(output) > 1024:
                return "PDF_PARSER_FAILED"
            result = json.loads(output)
            return result["reason"] if isinstance(result.get("reason"), str) else "PDF_PARSER_FAILED"
        except asyncio.TimeoutError:
            return "PDF_PARSER_TIMEOUT"
        except (OSError, ValueError, KeyError, TypeError):
            return "PDF_RESOURCE_LIMIT_OR_PARSER_FAILED"
        finally:
            if process is not None and process.returncode is None:
                process.kill()
                await process.wait()
            if job:
                job[0].CloseHandle(job[1])

def _pdf_worker():
    """Do not return content; enforce parser limits before third-party import/read."""
    try:
        if os.name != "nt":
            import resource
            resource.setrlimit(resource.RLIMIT_AS, (PDF_MEMORY_BYTES, PDF_MEMORY_BYTES))
        data = sys.stdin.buffer.read(MAX_PDF_BYTES + 1)
        if len(data) > MAX_PDF_BYTES:
            return "ATTACHMENT_TOO_LARGE"
        try:
            from pypdf import PdfReader
            from pypdf.generic import ArrayObject, DictionaryObject, IndirectObject, NameObject
        except ImportError:
            return "PDF_PARSER_UNAVAILABLE"
        import logging
        logging.disable(logging.CRITICAL)
        reader = PdfReader(io.BytesIO(data), strict=True)
        if reader.is_encrypted:
            return "PDF_ENCRYPTED_UNSUPPORTED"
        object_ids = [(number, generation) for generation, entries in reader.xref.items()
                      for number in entries if number]
        if len(object_ids) > MAX_PDF_OBJECTS or reader.xref_objStm:
            return "PDF_OBJECT_LIMIT_OR_COMPRESSED_OBJECTS_UNSUPPORTED"
        if len(reader.pages) < 1 or len(reader.pages) > MAX_PDF_PAGES:
            return "PDF_PAGE_LIMIT"
        forbidden = {"/JavaScript", "/JS", "/OpenAction", "/AA", "/Launch", "/EmbeddedFiles",
                     "/EmbeddedFile", "/Filespec", "/EF", "/AcroForm", "/XFA", "/RichMedia",
                     "/Movie", "/Sound", "/Rendition", "/SubmitForm", "/ImportData", "/GoToR",
                     "/URI", "/Encrypt", "/Annots", "/A", "/Collection", "/F", "/FFilter", "/FDecodeParms"}
        stack = [(reader.trailer, 0)]
        stack.extend((IndirectObject(number, generation, reader), 0) for number, generation in object_ids)
        seen = set()
        budget = 50000
        while stack:
            value, depth = stack.pop()
            budget -= 1
            if budget < 0 or depth > 50:
                return "PDF_COMPLEXITY_LIMIT"
            if isinstance(value, IndirectObject):
                identity = (value.idnum, value.generation)
                if identity in seen:
                    continue
                seen.add(identity)
                value = value.get_object()
            if isinstance(value, DictionaryObject):
                if any(str(key) in forbidden for key in value):
                    return "PDF_ACTIVE_OR_EMBEDDED_CONTENT"
                stack.extend((item, depth + 1) for item in value.values())
            elif isinstance(value, ArrayObject):
                stack.extend((item, depth + 1) for item in value)
            elif isinstance(value, NameObject) and str(value) in forbidden:
                return "PDF_ACTIVE_OR_EMBEDDED_CONTENT"
        return "VALID_PDF"
    except (Exception, MemoryError):
        return "PDF_MALFORMED_OR_RESOURCE_LIMIT"

if __name__ == "__main__" and sys.argv[1:] == ["--inspect-pdf"]:
    print(json.dumps({"reason": _pdf_worker()}))
