"""Modern and flexible TLS for Python, built on BoringSSL"""

from .bssl import (
    TLSError,
    WantWriteError,
    WantReadError,
    RaggedEOF,
    TLSBuffer,
    TLSSocket,
    ClientContext,
    ExtensionType,
    CertificateCompressionAlgorithm,
)

from .err import ConfigurationError
from .enums import CipherSuite, NextProtocol, TLSVersion, Curves, SignatureAlgorithms
from .conf import TLSClientConfiguration
