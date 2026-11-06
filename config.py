"""Explicit local TOML configuration; no service initialization or directory creation."""
from dataclasses import dataclass, field
import os
from pathlib import Path
import tomllib


class ConfigValidationError(ValueError):
    """Unsafe or unsupported configuration."""


def _default_data_dir():
    return Path(os.environ.get("LOCALAPPDATA", Path.home() / ".local" / "share")) / "GmailAutoPrinter"


@dataclass
class Config:
    DRY_RUN: bool = True
    RUN_ONCE: bool = False
    STATE_DIR: Path = field(default_factory=_default_data_dir)
    ALLOWED_SENDERS: tuple = ()
    PRINTER_NAME: str = ""
    SUMATRA_PDF_PATH: Path | None = None
    CREDENTIALS_FILE: Path | None = None
    TOKEN_FILE: Path | None = None
    ACK_POLICY: str = "none"
    ENABLE_MALWARE_SCAN: bool = True
    DEFENDER_PATH: Path | None = None
    MAX_ATTACHMENT_SIZE_MB: float = 10
    MAX_COPIES: int = 10
    COPIES: int = 1
    ENABLE_DUPLEX: bool = False
    MAX_ATTACHMENTS: int = 100
    POLL_INTERVAL_SECONDS: int = 30
    TIMEOUT_DEFENDER_SCAN_SECONDS: int = 30
    TIMEOUT_SUMATRA_PRINT_SECONDS: int = 60
    PDF_VALIDATION_TIMEOUT_SECONDS: int = 15
    GMAIL_REQUEST_TIMEOUT_SECONDS: int = 30
    GMAIL_MAX_ATTEMPTS: int = 3
    GMAIL_MAX_PAGES: int = 20
    GMAIL_QUERY: str = "is:unread has:attachment -in:trash -in:spam"
    ENABLE_AUTO_UPDATE: bool = field(default=False, init=False)
    ERROR_NOTIFICATION_ENABLED: bool = field(default=False, init=False)
    ALLOWED_FILE_TYPES: tuple = field(default=("pdf",), init=False)

    @property
    def STATE_DB(self):
        return self.STATE_DIR / "state.sqlite3"

    @property
    def DOWNLOAD_DIR(self):
        return self.STATE_DIR / "attachments"

    @property
    def TARGET_SENDER(self):
        return self.ALLOWED_SENDERS[0] if len(self.ALLOWED_SENDERS) == 1 else ""

    @classmethod
    def from_file(cls, path):
        path = Path(path).resolve()
        try:
            with path.open("rb") as stream:
                values = tomllib.load(stream)
        except (OSError, tomllib.TOMLDecodeError) as exc:
            raise ConfigValidationError("Cannot read valid TOML configuration") from exc
        allowed = {name.lower(): name for name, spec in cls.__dataclass_fields__.items()
                   if spec.init and name not in {"DRY_RUN", "RUN_ONCE"}}
        if set(values) - set(allowed):
            raise ConfigValidationError("Unknown or unsupported configuration key")
        args = {allowed[k]: v for k, v in values.items()}
        for key in ("STATE_DIR", "SUMATRA_PDF_PATH", "CREDENTIALS_FILE", "TOKEN_FILE", "DEFENDER_PATH"):
            if key in args:
                if not isinstance(args[key], str) or not args[key].strip():
                    raise ConfigValidationError("Path values must be nonempty strings")
                p = Path(args[key]).expanduser()
                args[key] = (path.parent / p).resolve() if not p.is_absolute() else p
        if "ALLOWED_SENDERS" in args:
            if not isinstance(args["ALLOWED_SENDERS"], list) or not all(isinstance(x, str) for x in args["ALLOWED_SENDERS"]):
                raise ConfigValidationError("allowed_senders must be a list of mailboxes")
            args["ALLOWED_SENDERS"] = tuple(args["ALLOWED_SENDERS"])
        config = cls(**args)
        config.validate()
        return config

    def validate(self):
        for name, low, high in (
            ("MAX_COPIES", 1, 50), ("COPIES", 1, self.MAX_COPIES),
            ("MAX_ATTACHMENTS", 1, 100), ("POLL_INTERVAL_SECONDS", 5, 3600),
            ("TIMEOUT_DEFENDER_SCAN_SECONDS", 1, 300), ("TIMEOUT_SUMATRA_PRINT_SECONDS", 1, 300),
            ("PDF_VALIDATION_TIMEOUT_SECONDS", 1, 60), ("GMAIL_REQUEST_TIMEOUT_SECONDS", 1, 120),
            ("GMAIL_MAX_ATTEMPTS", 1, 5), ("GMAIL_MAX_PAGES", 1, 100),
        ):
            value = getattr(self, name)
            if type(value) is not int or not low <= value <= high:
                raise ConfigValidationError(f"Invalid {name} limit")
        if type(self.MAX_ATTACHMENT_SIZE_MB) not in (int, float) or not 0 < self.MAX_ATTACHMENT_SIZE_MB <= 25:
            raise ConfigValidationError("Attachment size must be above zero and at most 25 MiB")
        if self.ACK_POLICY not in ("none", "mark-read"):
            raise ConfigValidationError("ack_policy must be none or mark-read")
        for name in ("ENABLE_MALWARE_SCAN", "ENABLE_DUPLEX"):
            if type(getattr(self, name)) is not bool:
                raise ConfigValidationError(f"{name} must be boolean")
        if not isinstance(self.PRINTER_NAME, str) or not isinstance(self.GMAIL_QUERY, str):
            raise ConfigValidationError("Printer and query must be strings")
        if not self.GMAIL_QUERY.strip() or len(self.GMAIL_QUERY) > 1024:
            raise ConfigValidationError("Invalid Gmail query")
        from security_validator import normalize_sender
        try:
            self.ALLOWED_SENDERS = tuple(normalize_sender(value) for value in self.ALLOWED_SENDERS)
        except (ValueError, TypeError) as exc:
            raise ConfigValidationError("Invalid sender allowlist") from exc
        return self

    def validate_live(self):
        self.validate()
        if not self.ALLOWED_SENDERS or not self.PRINTER_NAME.strip() or not self.SUMATRA_PDF_PATH:
            raise ConfigValidationError("Live mode requires allowed_senders, printer_name and sumatra_pdf_path")
        if not self.CREDENTIALS_FILE or not self.TOKEN_FILE:
            raise ConfigValidationError("Live mode requires private credentials_file and token_file paths")
        if not self.ENABLE_MALWARE_SCAN:
            raise ConfigValidationError("Malware scanning cannot be disabled in live candidate mode")
        return self
