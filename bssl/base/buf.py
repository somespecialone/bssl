from abc import abstractmethod
from collections.abc import Buffer
from typing import Protocol

from .enums import NextProtocol, CipherSuite, TLSVersion
from .ctx import ClientContext, ServerContext


# https://peps.python.org/pep-0748/#buffer
class TLSBuffer(Protocol):
    """This class implements an in memory-channel that creates two buffers,
    wraps them in an SSL context, and provides read and write methods over
    that channel."""

    @abstractmethod
    def read(self, amt: int, buffer: Buffer | None) -> bytes | int:
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
        ...

    @abstractmethod
    def write(self, buf: Buffer) -> int:
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
        ...

    @abstractmethod
    def do_handshake(self) -> None:
        """
        Performs the TLS handshake. Also performs certificate validation
        and hostname verification.
        """
        ...

    @abstractmethod
    def cipher(self) -> CipherSuite | int | None:
        """
        Returns the CipherSuite entry for the cipher that has been
        negotiated on the connection. If no connection has been negotiated,
        returns ``None``. If the cipher negotiated is not defined in
        CipherSuite, returns the 16-bit integer representing that cipher
        directly.
        """
        ...

    @abstractmethod
    def negotiated_protocol(self) -> NextProtocol | bytes | None:
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
        ...

    @property
    @abstractmethod
    def context(self) -> ClientContext | ServerContext:
        """
        The ``Context`` object this buffer is tied to.
        """
        ...

    @property
    @abstractmethod
    def negotiated_tls_version(self) -> TLSVersion | None:
        """
        The version of TLS that has been negotiated on this connection.
        """
        ...

    @abstractmethod
    def shutdown(self) -> None:
        """
        Performs a clean TLS shut down. This should generally be used
        whenever possible to signal to the remote peer that the content is
        finished.
        """
        ...

    @abstractmethod
    def process_incoming(self, data_from_network: bytes) -> None:
        """
        Receives some TLS data from the network and stores it in an
        internal buffer.

        If the internal buffer is overfull, this method will raise
        ``WantReadError`` and store no data. At this point, the user must
        call ``read`` to remove some data from the internal buffer
        before repeating this call.
        """
        ...

    @abstractmethod
    def incoming_bytes_buffered(self) -> int:
        """
        Returns how many bytes are in the incoming buffer waiting to be processed.
        """
        ...

    @abstractmethod
    def process_outgoing(self, amount_bytes_for_network: int) -> bytes:
        """
        Returns the next ``amt`` bytes of data that should be written to
        the network from the outgoing data buffer, removing it from the
        internal buffer.
        """
        ...

    @abstractmethod
    def outgoing_bytes_buffered(self) -> int:
        """
        Returns how many bytes are in the outgoing buffer waiting to be sent.
        """
        ...

    @abstractmethod
    def getpeercert(self) -> bytes | None:
        """
        Return the raw DER bytes of the certificate provided by the peer
        during the handshake, if applicable.
        """
        ...
