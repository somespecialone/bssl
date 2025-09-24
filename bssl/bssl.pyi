"""Core implementation of the bssl package API"""

from collections.abc import Buffer
from typing import Self, overload, final
from enum import Enum

from .conf import TLSClientConfiguration

class TLSError(Exception):
    """
    The base exception for all TLS related errors from any implementation.

    Catching this error should be sufficient to catch *all* TLS errors,
    regardless of what implementation is used.
    """

class WantWriteError(TLSError):
    """
    A special signaling exception used only when non-blocking or buffer-only I/O is used.

    This error signals that the requested
    operation cannot complete until more data is written to the network,
    or until the output buffer is drained.

    This error is should only be raised when it is completely impossible
    to write any data. If a partial write is achievable then this should
    not be raised.
    """

class WantReadError(TLSError):
    """
    A special signaling exception used only when non-blocking or buffer-only I/O is used.

    This error signals that the requested
    operation cannot complete until more data is read from the network, or
    until more data is available in the input buffer.

    This error should only be raised when it is completely impossible to
    write any data. If a partial write is achievable then this should not
    be raised.
    """

class RaggedEOF(TLSError):
    """A special signaling exception used when a TLS connection has been
    closed gracelessly: that is, when a TLS CloseNotify was not received
    from the peer before the underlying TCP socket reached EOF. This is a
    so-called "ragged EOF".

    This exception is not guaranteed to be raised in the face of a ragged
    EOF: some implementations may not be able to detect or report the
    ragged EOF.

    This exception is not always a problem. Ragged EOFs are a concern only
    when protocols are vulnerable to length truncation attacks. Any
    protocol that can detect length truncation attacks at the application
    layer (e.g. HTTP/1.1 and HTTP/2) is not vulnerable to this kind of
    attack and so can ignore this exception.
    """

# https://peps.python.org/pep-0748/#buffer
@final
class TLSBuffer:
    """This class implements an in memory-channel that creates two buffers,
    wraps them in an SSL context, and provides read and write methods over
    that channel."""

    @property
    def context(self) -> "ClientContext":
        """
        The ``Context`` object this buffer is tied to.
        """

    def do_handshake(self) -> None:
        """
        Performs the TLS handshake. Also performs certificate validation
        and hostname verification.
        """

    @overload
    def read(self, amt: int) -> bytes: ...
    @overload
    def read(self, amt: int, buffer: Buffer) -> int: ...
    def read(self, amt: int, buffer: Buffer | None = None) -> int | bytes:
        """
        Read up to ``amt`` bytes of data from the input buffer and return
        the result as a ``bytes`` instance. If an optional buffer is
        provided, the result is written into the buffer and the number of
        bytes is returned instead.

        Once EOF is reached, all further calls to this method return the
        empty byte string ``b''``.

        May read "short": that is, fewer bytes may be returned than were
        requested.

        Raise ``WantReadError`` or ``WantWriteError`` if there is
        insufficient data in either the input or output buffer and the
        operation would have caused data to be written or read.

        May raise ``RaggedEOF`` if the connection has been closed without a
        graceful TLS shutdown. Whether this is an exception that should be
        ignored or not is up to the specific application.

        As at any time a re-negotiation is possible, a call to ``read()``
        can also cause write operations.
        """

    def write(self, buf: bytes) -> int:
        """
        Write ``buf`` in encrypted form to the output buffer and return the
        number of bytes written. The ``buf`` argument must be an object
        supporting the buffer interface.

        Raise ``WantReadError`` or ``WantWriteError`` if there is
        insufficient data in either the input or output buffer and the
        operation would have caused data to be written or read. In either
        case, users should endeavour to resolve that situation and then
        re-call this method. When re-calling this method users *should*
        re-use the exact same ``buf`` object, as some implementations require that
        the exact same buffer be used.

        This operation may write "short": that is, fewer bytes may be
        written than were in the buffer.

        As at any time a re-negotiation is possible, a call to ``write()``
        can also cause read operations.
        """

    def process_incoming(self, data_from_network: bytes) -> None:
        """
        Receives some TLS data from the network and stores it in an
        internal buffer.

        If the internal buffer is overfull, this method will raise
        ``WantReadError`` and store no data. At this point, the user must
        call ``read`` to remove some data from the internal buffer
        before repeating this call.
        """

    def process_outgoing(self, amount_bytes_for_network: int = ...) -> bytes:
        """
        Returns the next ``amt`` bytes of data that should be written to
        the network from the outgoing data buffer, removing it from the
        internal buffer.
        """

    def shutdown(self) -> None:
        """
        Performs a clean TLS shut down. This should generally be used
        whenever possible to signal to the remote peer that the content is
        finished.
        """

    def incoming_bytes_buffered(self) -> int:
        """
        Returns how many bytes are in the incoming buffer waiting to be processed.
        """

    def outgoing_bytes_buffered(self) -> int:
        """
        Returns how many bytes are in the outgoing buffer waiting to be sent.
        """

    def getpeercert(self) -> bytes | None:
        """
        Return the raw DER bytes of the certificate provided by the peer
        during the handshake, if applicable.
        """

    def cipher(self) -> int | None:
        """
        Returns the CipherSuite entry for the cipher that has been
        negotiated on the connection. If no connection has been negotiated,
        returns ``None``. If the cipher negotiated is not defined in
        CipherSuite, returns the 16-bit integer representing that cipher
        directly.
        """

    def negotiated_protocol(self) -> bytes | None:
        """
        Returns the protocol that was selected during the TLS handshake.
        This selection may have been made using ALPN, NPN, or some future
        negotiation mechanism.

        If the negotiated protocol is one of the protocols defined in the
        ``NextProtocol`` enum, the value from that enum will be returned.
        Otherwise, the raw bytestring of the negotiated protocol will be
        returned.

        If ``Context.set_inner_protocols()`` was not called, if the other
        party does not support protocol negotiation, if this socket does
        not support any of the peer's proposed protocols, or if the
        handshake has not happened yet, ``None`` is returned.
        """

    @property
    def negotiated_tls_version(self) -> str | None:
        """
        The version of TLS that has been negotiated on this connection.
        """

# https://peps.python.org/pep-0748/#socket
@final
class TLSSocket:
    """This class implements a socket.socket-like object that creates an OS
    socket, wraps it in an SSL context, and provides read and write methods
    over that channel."""

    @property
    def context(self) -> "ClientContext":
        """The ``Context`` object this socket is tied to."""

    def send(self, bytes: bytes) -> int:
        """Send data to the socket. The socket must be connected to a remote socket."""

    def recv(self, bufsize: int) -> bytes:
        """Receive data from the socket. The return value is a bytes object
        representing the data received. Should not work before the handshake
        is completed."""

    def getsockname(self) -> str:
        """Return the local address to which the socket is connected."""

    def getpeercert(self) -> bytes:
        """
        Return the raw DER bytes of the certificate provided by the peer
        during the handshake, if applicable.
        """

    def getpeername(self) -> str:
        """Return the remote address to which the socket is connected."""

    def cipher(self) -> int | None:
        """
        Returns the CipherSuite entry for the cipher that has been negotiated on the connection.

        If no connection has been negotiated, returns ``None``. If the cipher negotiated is not
        defined in CipherSuite, returns the 16-bit integer representing that cipher directly.
        """

    def negotiated_protocol(self) -> bytes | None:
        """
        Returns the protocol that was selected during the TLS handshake.

        This selection may have been made using ALPN or some future
        negotiation mechanism.

        If the negotiated protocol is one of the protocols defined in the
        ``NextProtocol`` enum, the value from that enum will be returned.
        Otherwise, the raw bytestring of the negotiated protocol will be
        returned.

        If ``Context.set_inner_protocols()`` was not called, if the other
        party does not support protocol negotiation, if this socket does
        not support any of the peer's proposed protocols, or if the
        handshake has not happened yet, ``None`` is returned.
        """

    @property
    def negotiated_tls_version(self) -> str | None:
        """The version of TLS that has been negotiated on this connection."""

    def listen(self, backlog: int) -> None:
        """Enable a server to accept connections. If backlog is specified, it
        specifies the number of unaccepted connections that the system will allow
        before refusing new connections."""

    def accept(self) -> tuple[Self, tuple[str | None, int]]:
        """Accept a connection. The socket must be bound to an address and listening
        for connections. The return value is a pair (conn, address) where conn is a
        new TLSSocket object usable to send and receive data on the connection, and
        address is the address bound to the socket on the other end of the connection.
        """

    def close(self, force: bool = False) -> None:
        """Shuts down the connection and mark the socket closed.
        If force is True, this method should send the close_notify alert and shut down
        the socket without waiting for the other side.
        If force is False, this method should send the close_notify alert and raise
        the WantReadError exception until a corresponding close_notify alert has been
        received from the other side.
        In either case, this method should return WantWriteError if sending the
        close_notify alert currently fails."""

# https://peps.python.org/pep-0748/#context
@final
class ClientContext:
    def __init__(self, configuration: TLSClientConfiguration) -> Self:
        """Create a new client context object from a given TLS client configuration."""

    @property
    def configuration(self) -> TLSClientConfiguration:
        """Returns the TLS client configuration that was used to create the client context."""

    def connect(self, address: tuple[str | None, int]) -> TLSSocket:
        """Creates a TLSSocket that behaves like a socket.socket, and
        contains information about the TLS exchange
        (cipher, negotiated_protocol, negotiated_tls_version, etc.).
        """

    def create_buffer(self, server_hostname: str) -> TLSBuffer:
        """Creates a TLSBuffer that acts as an in-memory channel,
        and contains information about the TLS exchange
        (cipher, negotiated_protocol, negotiated_tls_version, etc.)."""

class CertificateCompressionAlgorithm(Enum):
    """
    Certificate compression algorithms.

    See: <https://www.rfc-editor.org/rfc/rfc8879.html#name-compression-algorithms>
    """

    ZLIB = ...
    BROTLI = ...
    ZSTD = ...

class ExtensionType(Enum):
    SERVER_NAME = ...
    STATUS_REQUEST = ...
    EC_POINT_FORMATS = ...
    SIGNATURE_ALGORITHMS = ...
    SRTP = ...
    APPLICATION_LAYER_PROTOCOL_NEGOTIATION = ...
    PADDING = ...
    EXTENDED_MASTER_SECRET = ...
    QUIC_TRANSPORT_PARAMETERS_LEGACY = ...
    QUIC_TRANSPORT_PARAMETERS_STANDARD = ...
    CERT_COMPRESSION = ...
    SESSION_TICKET = ...
    SUPPORTED_GROUPS = ...
    PRE_SHARED_KEY = ...
    EARLY_DATA = ...
    SUPPORTED_VERSIONS = ...
    COOKIE = ...
    PSK_KEY_EXCHANGE_MODES = ...
    CERTIFICATE_AUTHORITIES = ...
    SIGNATURE_ALGORITHMS_CERT = ...
    KEY_SHARE = ...
    RENEGOTIATE = ...
    DELEGATED_CREDENTIAL = ...
    APPLICATION_SETTINGS = ...
    APPLICATION_SETTINGS_NEW = ...
    ENCRYPTED_CLIENT_HELLO = ...
    CERTIFICATE_TIMESTAMP = ...
    NEXT_PROTO_NEG = ...
    CHANNEL_ID = ...
    RECORD_SIZE_LIMIT = ...
