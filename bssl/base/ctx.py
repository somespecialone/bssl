from abc import abstractmethod
from typing import Protocol

from .socket import TLSSocket
from .buf import TLSBuffer
from .conf import TLSClientConfiguration, TLSServerConfiguration


# https://peps.python.org/pep-0748/#context
class ClientContext(Protocol):
    @abstractmethod
    def __init__(self, configuration: TLSClientConfiguration) -> None:
        """Create a new client context object from a given TLS client configuration."""
        ...

    @property
    @abstractmethod
    def configuration(self) -> TLSClientConfiguration:
        """Returns the TLS client configuration that was used to create the client context."""
        ...

    @abstractmethod
    def connect(self, address: tuple[str | None, int]) -> TLSSocket:
        """Creates a TLSSocket that behaves like a socket.socket, and
        contains information about the TLS exchange
        (cipher, negotiated_protocol, negotiated_tls_version, etc.).
        """
        ...

    @abstractmethod
    def create_buffer(self, server_hostname: str) -> TLSBuffer:
        """Creates a TLSBuffer that acts as an in-memory channel,
        and contains information about the TLS exchange
        (cipher, negotiated_protocol, negotiated_tls_version, etc.)."""
        ...


class ServerContext(Protocol):
    @abstractmethod
    def __init__(self, configuration: TLSServerConfiguration) -> None:
        """Create a new client context object from a given TLS server configuration."""
        ...

    @property
    @abstractmethod
    def configuration(self) -> TLSServerConfiguration:
        """Returns the TLS server configuration that was used to create the client context."""
        ...

    @abstractmethod
    def connect(self, address: tuple[str | None, int]) -> TLSSocket:
        """Creates a TLSSocket that behaves like a socket.socket, and
        contains information about the TLS exchange
        (cipher, negotiated_protocol, negotiated_tls_version, etc.).
        """
        ...

    @abstractmethod
    def create_buffer(self, server_hostname: str) -> TLSBuffer:
        """Creates a TLSBuffer that acts as an in-memory channel,
        and contains information about the TLS exchange
        (cipher, negotiated_protocol, negotiated_tls_version, etc.)."""
        ...
