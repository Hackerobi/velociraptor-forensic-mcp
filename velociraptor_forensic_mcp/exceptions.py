"""Custom exceptions for the Velociraptor Forensic MCP Server."""


class VelociraptorError(Exception):
    """Base exception for Velociraptor-related errors."""


class VelociraptorAuthenticationError(VelociraptorError):
    """Raised when gRPC authentication to Velociraptor fails."""


class VelociraptorAPIError(VelociraptorError):
    """Raised when a Velociraptor API / VQL call fails."""


class ForensicToolError(Exception):
    """Base exception for local forensic tool errors."""


class SafePathError(ForensicToolError):
    """Raised when a path is outside the allowed SAFE_BASE directory."""
