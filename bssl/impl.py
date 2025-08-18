from typing import Callable, Generic, TypeVar

from .conf import TLSClientConfiguration

_ClientContext = TypeVar("_ClientContext")


# https://peps.python.org/pep-0748/#runtime-access
class TLSImplementation(Generic[_ClientContext]):
    __slots__ = (
        "_client_context",
        # "_server_context",
        "_validate_config",
    )

    def __init__(
        self,
        client_context: type[_ClientContext],
        validate_config: Callable[[TLSClientConfiguration], None],
    ) -> None:
        self._client_context = client_context
        self._validate_config = validate_config

    @property
    def client_context(self) -> type[_ClientContext]:
        """The concrete implementation of the PEP 543 Client Context object,
        if this TLS implementation supports being the client on a TLS connection.
        """
        return self._client_context

    @property
    def validate_config(self) -> Callable[[TLSClientConfiguration], None]:
        """A function that reveals whether this TLS implementation supports a
        particular TLS configuration.
        """
        return self._validate_config
