from typing import Self, Sequence
from os import PathLike


# https://peps.python.org/pep-0748/#certificates
class Certificate:
    """Object representing a certificate used in TLS."""

    __slots__ = (
        "_buffer",
        "_path",
        "_id",
    )

    def __init__(
        self,
        buffer: bytes | None = None,
        path: PathLike[str] | None = None,
        id: bytes | None = None,
    ):
        """
        Creates a Certificate object from a path, buffer, or ID.

        If none of these is given, an exception is raised.
        """

        if buffer is None and path is None and id is None:
            raise ValueError("Certificate cannot be empty.")

        self._buffer = buffer
        self._path = path
        self._id = id

    @classmethod
    def from_buffer(cls, buffer: bytes) -> Self:
        """
        Creates a Certificate object from a byte buffer. This byte buffer
        may be either PEM-encoded or DER-encoded. If the buffer is PEM
        encoded it *must* begin with the standard PEM preamble (a series of
        dashes followed by the ASCII bytes "BEGIN CERTIFICATE" and another
        series of dashes). In the absence of that preamble, the
        implementation may assume that the certificate is DER-encoded
        instead.
        """
        return cls(buffer=buffer)

    @classmethod
    def from_file(cls, path: PathLike[str]) -> Self:
        """
        Creates a Certificate object from a file on disk. The file on disk
        should contain a series of bytes corresponding to a certificate that
        may be either PEM-encoded or DER-encoded. If the bytes are PEM encoded
        it *must* begin with the standard PEM preamble (a series of dashes
        followed by the ASCII bytes "BEGIN CERTIFICATE" and another series of
        dashes). In the absence of that preamble, the implementation may
        assume that the certificate is DER-encoded instead.
        """
        return cls(path=path)

    @classmethod
    def from_id(cls, id: bytes) -> Self:
        """
        Creates a Certificate object from an arbitrary identifier. This may
        be useful for implementations that rely on system certificate stores.
        """
        return cls(id=id)


# https://peps.python.org/pep-0748/#private-keys
class PrivateKey:
    """Object representing a private key corresponding to a public key
    for a certificate used in TLS."""

    __slots__ = (
        "_buffer",
        "_path",
        "_id",
    )

    def __init__(
        self,
        buffer: bytes | None = None,
        path: PathLike | None = None,
        id: bytes | None = None,
    ):
        """
        Creates a PrivateKey object from a path, buffer, or ID.

        If none of these is given, an exception is raised.
        """

        if buffer is None and path is None and id is None:
            raise ValueError("PrivateKey cannot be empty.")

        self._buffer = buffer
        self._path = path
        self._id = id

    @classmethod
    def from_buffer(cls, buffer: bytes) -> Self:
        """
        Creates a PrivateKey object from a byte buffer. This byte buffer
        may be either PEM-encoded or DER-encoded. If the buffer is PEM
        encoded it *must* begin with the standard PEM preamble (a series of
        dashes followed by the ASCII bytes "BEGIN", the key type, and
        another series of dashes). In the absence of that preamble, the
        implementation may assume that the private key is DER-encoded
        instead.
        """
        return cls(buffer=buffer)

    @classmethod
    def from_file(cls, path: PathLike) -> Self:
        """
        Creates a PrivateKey object from a file on disk. The file on disk
        should contain a series of bytes corresponding to a certificate that
        may be either PEM-encoded or DER-encoded. If the bytes are PEM encoded
        it *must* begin with the standard PEM preamble (a series of dashes
        followed by the ASCII bytes "BEGIN", the key type, and another series
        of dashes). In the absence of that preamble, the implementation may
        assume that the certificate is DER-encoded instead.
        """
        return cls(path=path)

    @classmethod
    def from_id(cls, id: bytes) -> Self:
        """
        Creates a PrivateKey object from an arbitrary identifier. This may
        be useful for implementations that rely on system private key stores.
        """
        return cls(id=id)


# https://peps.python.org/pep-0748/#signing-chain
class SigningChain:
    """Object representing a certificate chain used in TLS."""

    leaf: tuple[Certificate, PrivateKey | None]
    chain: list[Certificate]

    def __init__(
        self,
        leaf: tuple[Certificate, PrivateKey | None],
        chain: Sequence[Certificate] | None = None,
    ):
        """Initializes a SigningChain object."""
        self.leaf = leaf
        if chain is None:
            chain = []
        self.chain = list(chain)


# https://peps.python.org/pep-0748/#trust-store
class TrustStore:
    """
    The trust store that is used to verify certificate validity.
    """

    __slots__ = (
        "_buffer",
        "_path",
        "_id",
    )

    def __init__(
        self,
        buffer: bytes | None = None,
        path: PathLike | None = None,
        id: bytes | None = None,
    ):
        """
        Creates a TrustStore object from a path, buffer, or ID.

        If none of these is given, the default system trust store is used.
        """

        self._buffer = buffer
        self._path = path
        self._id = id

    @classmethod
    def system(cls) -> Self:
        """
        Returns a TrustStore object that represents the system trust
        database.
        """
        return cls()

    @classmethod
    def from_buffer(cls, buffer: bytes) -> Self:
        """
        Initializes a trust store from a buffer of PEM-encoded certificates.
        """
        return cls(buffer=buffer)

    @classmethod
    def from_file(cls, path: PathLike) -> Self:
        """
        Initializes a trust store from a single file containing PEMs.
        """
        return cls(path=path)

    @classmethod
    def from_id(cls, id: bytes) -> Self:
        """
        Initializes a trust store from an arbitrary identifier.
        """
        return cls(id=id)
