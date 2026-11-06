"""
Custom exceptions for the Gmail Auto Printer system.
"""
class EmailPrinterError(Exception):
    """Base exception for Email Printer errors."""
    pass
class ConfigurationError(EmailPrinterError):
    """Configuration related errors."""
    pass
class AttachmentValidationError(EmailPrinterError):
    """Attachment validation errors."""
    pass
class PrinterError(EmailPrinterError):
    """Printer related errors."""
    pass
class MalwareDetectionError(EmailPrinterError):
    """Malware detection errors."""
    pass
class NetworkError(EmailPrinterError):
    """Network related errors."""
    pass
