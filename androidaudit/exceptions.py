from __future__ import annotations

class AndroidAuditError(Exception):
    """Base exception for AndroidAudit."""

class DeviceNotFoundError(AndroidAuditError):
    """Raised when an interactive ADB device could not be found."""

class RootNotAvailableError(AndroidAuditError):
    """Raised when root access cannot be obtained."""

class FridaServerError(AndroidAuditError):
    """Raised when Frida server interactions fail."""

class ModuleError(AndroidAuditError):
    """Raised when an analysis module fails."""

