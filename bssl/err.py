from .bssl import TLSError, WantReadError, WantWriteError, RaggedEOF


class ConfigurationError(TLSError):
    """An special exception that implementations can use when the provided
    configuration uses features not supported by that implementation."""
