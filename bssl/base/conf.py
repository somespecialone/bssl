from typing import Sequence

from .enums import CipherSuite, NextProtocol, TLSVersion
from .store import SigningChain, TrustStore


# https://peps.python.org/pep-0748/#configuration
class TLSClientConfiguration:
    __slots__ = (
        "_certificate_chain",
        "_ciphers",
        "_inner_protocols",
        "_lowest_supported_version",
        "_highest_supported_version",
        "_trust_store",
    )

    def __init__(
        self,
        certificate_chain: SigningChain | None = None,
        ciphers: Sequence[CipherSuite] | None = None,
        inner_protocols: Sequence[NextProtocol | bytes] | None = None,
        lowest_supported_version: TLSVersion | None = None,
        highest_supported_version: TLSVersion | None = None,
        trust_store: TrustStore | None = None,
    ) -> None:
        if inner_protocols is None:
            inner_protocols = []

        self._certificate_chain = certificate_chain
        self._ciphers = ciphers
        self._inner_protocols = inner_protocols
        self._lowest_supported_version = lowest_supported_version
        self._highest_supported_version = highest_supported_version
        self._trust_store = trust_store

    @property
    def certificate_chain(self) -> SigningChain | None:
        return self._certificate_chain

    @property
    def ciphers(self) -> Sequence[CipherSuite | int] | None:
        return self._ciphers

    @property
    def inner_protocols(self) -> Sequence[NextProtocol | bytes]:
        return self._inner_protocols

    @property
    def lowest_supported_version(self) -> TLSVersion | None:
        return self._lowest_supported_version

    @property
    def highest_supported_version(self) -> TLSVersion | None:
        return self._highest_supported_version

    @property
    def trust_store(self) -> TrustStore | None:
        return self._trust_store


class TLSServerConfiguration(TLSClientConfiguration):
    __slots__ = ()

    _certificate_chain: Sequence[SigningChain] | None

    def __init__(
        self,
        certificate_chain: Sequence[SigningChain] | None = None,
        ciphers: Sequence[CipherSuite] | None = None,
        inner_protocols: Sequence[NextProtocol | bytes] | None = None,
        lowest_supported_version: TLSVersion | None = None,
        highest_supported_version: TLSVersion | None = None,
        trust_store: TrustStore | None = None,
    ) -> None:
        super().__init__(
            certificate_chain=certificate_chain,
            ciphers=ciphers,
            inner_protocols=inner_protocols,
            lowest_supported_version=lowest_supported_version,
            highest_supported_version=highest_supported_version,
            trust_store=trust_store,
        )

    @property
    def certificate_chain(self) -> Sequence[SigningChain] | None:
        return self._certificate_chain
