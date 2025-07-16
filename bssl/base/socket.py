from abc import abstractmethod
from typing import Protocol, Self

from .enums import CipherSuite, TLSVersion, NextProtocol
from .ctx import ClientContext, ServerContext


# https://peps.python.org/pep-0748/#socket
class TLSSocket(Protocol):
    """This class implements a socket.socket-like object that creates an OS
    socket, wraps it in an SSL context, and provides read and write methods
    over that channel."""

    @abstractmethod
    def __init__(self, *args: tuple, **kwargs: tuple) -> None:
        """TLSSockets should not be constructed by the user.
        The implementation should implement a method to construct a TLSSocket
        object and call it in ClientContext.connect() and
        ServerContext.connect()."""
        ...

    @abstractmethod
    def recv(self, bufsize: int) -> bytes:
        """Receive data from the socket. The return value is a bytes object
        representing the data received. Should not work before the handshake
        is completed."""
        ...

    @abstractmethod
    def send(self, bytes: bytes) -> int:
        """Send data to the socket. The socket must be connected to a remote socket."""
        ...

    @abstractmethod
    def close(self, force: bool = False) -> None:
        """Shuts down the connection and mark the socket closed.
        If force is True, this method should send the close_notify alert and shut down
        the socket without waiting for the other side.
        If force is False, this method should send the close_notify alert and raise
        the WantReadError exception until a corresponding close_notify alert has been
        received from the other side.
        In either case, this method should return WantWriteError if sending the
        close_notify alert currently fails."""
        ...

    @abstractmethod
    def listen(self, backlog: int) -> None:
        """Enable a server to accept connections. If backlog is specified, it
        specifies the number of unaccepted connections that the system will allow
        before refusing new connections."""
        ...

    @abstractmethod
    def accept(self) -> tuple[Self, tuple[str | None, int]]:
        """Accept a connection. The socket must be bound to an address and listening
        for connections. The return value is a pair (conn, address) where conn is a
        new TLSSocket object usable to send and receive data on the connection, and
        address is the address bound to the socket on the other end of the connection.
        """
        ...

    @abstractmethod
    def getsockname(self) -> tuple[str | None, int]:
        """Return the local address to which the socket is connected."""
        ...

    @abstractmethod
    def getpeercert(self) -> bytes | None:
        """
        Return the raw DER bytes of the certificate provided by the peer
        during the handshake, if applicable.
        """
        ...

    @abstractmethod
    def getpeername(self) -> tuple[str | None, int]:
        """Return the remote address to which the socket is connected."""
        ...

    @property
    @abstractmethod
    def context(self) -> ClientContext | ServerContext:
        """The ``Context`` object this socket is tied to."""
        ...

    @abstractmethod
    def cipher(self) -> CipherSuite | int | None:
        """
        Returns the CipherSuite entry for the cipher that has been negotiated on the connection.

        If no connection has been negotiated, returns ``None``. If the cipher negotiated is not
        defined in CipherSuite, returns the 16-bit integer representing that cipher directly.
        """
        ...

    @abstractmethod
    def negotiated_protocol(self) -> NextProtocol | bytes | None:
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
        ...

    @property
    @abstractmethod
    def negotiated_tls_version(self) -> TLSVersion | None:
        """The version of TLS that has been negotiated on this connection."""
        ...
