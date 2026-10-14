"""Errors suitable for displaying to a command-line user."""


class NetSentinelError(Exception):
    """Base class for expected application failures."""


class ConfigurationError(NetSentinelError):
    """Configuration is unreadable or invalid."""


class CaptureError(NetSentinelError):
    """The capture is unreadable, corrupt, or outside the supported format."""


class DetectionError(NetSentinelError):
    """Detection cannot continue without dropping observations."""


class AlertLogError(NetSentinelError):
    """An alert could not be persisted safely."""
