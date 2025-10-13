from typing import Sequence

from .enums import (
    TLSVersion,
    CipherSuite,
    NextProtocol,
    Curves,
    SignatureAlgorithms,
    CertificateCompressionAlgorithm,
    ExtensionType,
)
from .store import TrustStore, SigningChain


DEF_CIPHER_LIST = "DEFAULT:!aNULL:!eNULL:!MD5:!3DES:!DES:!RC4:!IDEA:!SEED:!aDSS:!SRP:!PSK"


class TLSClientConfiguration:
    def __init__(
        self,
        # PEP-748
        certificate_chain: SigningChain | None = None,
        ciphers: Sequence[CipherSuite] = (),
        inner_protocols: Sequence[NextProtocol | bytes] = (),
        lowest_supported_version: TLSVersion = TLSVersion.MINIMUM_SUPPORTED,
        highest_supported_version: TLSVersion = TLSVersion.MAXIMUM_SUPPORTED,
        trust_store: TrustStore | None = None,
        # impl
        raw_cipher_list: str = DEF_CIPHER_LIST,
        ocsp_stapling: bool = False,
        signed_cert_timestamps: bool = False,
        session_ticket: bool = True,
        psk_dhe_ke: bool = False,
        renegotiation: bool = True,
        grease: bool = False,
        permute_extensions: bool = True,
        curves: Sequence[Curves | str] = (),
        sigalgs: Sequence[SignatureAlgorithms | str] = (),
        delegated_credentials: Sequence[SignatureAlgorithms | str] = (),
        record_size_limit: int | None = None,
        key_shares_limit: int | None = None,
        aes_hw_override: bool = False,
        preserve_tls13_cipher_list: bool = False,
        random_aes_hw_override: bool = False,
        alps_protocols: Sequence[NextProtocol | bytes] = (),
        alps_use_new_codepoint: bool = False,
        # pre_shared_key: bool = False,
        ech_grease: bool = False,
        # psk_skip_session_ticket: bool = False,
        certificate_compression_algorithms: Sequence[CertificateCompressionAlgorithm] = (),
        extension_permutation: Sequence[ExtensionType] = (),
    ):
        if certificate_chain:
            raise NotImplementedError("certificate_chain is not yet implemented")
        # if ciphers:
        #     raise NotImplementedError("ciphers is not yet implemented")
        # if inner_protocols:
        #     raise NotImplementedError("inner_protocols is not yet implemented")
        if trust_store:
            raise NotImplementedError("trust_store is not yet implemented")

        if ciphers and raw_cipher_list and raw_cipher_list is not DEF_CIPHER_LIST:
            raise ValueError("ciphers and raw_cipher_list are mutually exclusive")

        # from PEP-748
        self._certificate_chain = certificate_chain
        self._ciphers = ciphers
        self._inner_protocols = inner_protocols
        self._lowest_supported_version = lowest_supported_version
        self._highest_supported_version = highest_supported_version
        self._trust_store = trust_store

        # from the current implementation
        self._raw_alpn_protocols_list = self._compose_next_protocols(inner_protocols) if inner_protocols else None
        self._raw_cipher_list = ":".join(c.name for c in ciphers) if ciphers else raw_cipher_list
        self._ocsp_stapling = ocsp_stapling
        self._signed_cert_timestamps = signed_cert_timestamps
        self._session_ticket = session_ticket
        self._psk_dhe_ke = psk_dhe_ke
        self._renegotiation = renegotiation
        self._grease = grease
        self._permute_extensions = permute_extensions
        self._curves = curves
        self._raw_curves_list = ":".join(s.value if isinstance(s, Curves) else s for s in curves) if curves else None

        self._sigalgs = sigalgs
        self._raw_sigalgs_list = (
            ":".join(s.name if isinstance(s, SignatureAlgorithms) else s for s in sigalgs) if sigalgs else None
        )
        self._delegated_credentials = delegated_credentials
        self._raw_delegated_credentials_list = (
            ":".join(s.name if isinstance(s, SignatureAlgorithms) else s for s in delegated_credentials)
            if delegated_credentials
            else None
        )
        self._record_size_limit = record_size_limit
        self._key_shares_limit = key_shares_limit
        self._aes_hw_override = aes_hw_override
        self._preserve_tls13_cipher_list = preserve_tls13_cipher_list
        self._random_aes_hw_override = random_aes_hw_override
        self._alps_protocols = alps_protocols
        self._raw_alps_protocols_list = (
            [p.value if isinstance(p, NextProtocol) else p for p in alps_protocols] if alps_protocols else None
        )
        self._alps_use_new_codepoint = alps_use_new_codepoint
        # self._pre_shared_key = pre_shared_key
        self._ech_grease = ech_grease
        # self._psk_skip_session_ticket = psk_skip_session_ticket
        self._certificate_compression_algorithms = certificate_compression_algorithms
        self._extension_permutation = extension_permutation

    @property
    def certificate_chain(self) -> SigningChain | None:
        return self._certificate_chain

    @property
    def ciphers(self) -> Sequence[CipherSuite]:
        return self._ciphers

    @property
    def raw_ciphers_list(self) -> str:
        return self._raw_cipher_list

    @property
    def inner_protocols(self) -> Sequence[NextProtocol | bytes]:
        return self._inner_protocols

    @property
    def lowest_supported_version(self) -> TLSVersion:
        return self._lowest_supported_version

    @property
    def highest_supported_version(self) -> TLSVersion:
        return self._highest_supported_version

    @property
    def trust_store(self) -> TrustStore | None:
        return self._trust_store

    @property
    def signed_cert_timestamps(self) -> bool:
        return self._signed_cert_timestamps

    # impl
    @property
    def ocsp_stapling(self) -> bool:
        return self._ocsp_stapling

    @property
    def session_ticket(self) -> bool:
        return self._session_ticket

    @property
    def psk_dhe_ke(self) -> bool:
        return self._psk_dhe_ke

    @property
    def renegotiation(self) -> bool:
        return self._renegotiation

    @property
    def grease(self) -> bool:
        return self._grease

    @property
    def permute_extensions(self) -> bool:
        return self._permute_extensions

    @property
    def curves(self) -> Sequence[Curves]:
        return self._curves

    @property
    def sigalgs(self) -> Sequence[SignatureAlgorithms]:
        return self._sigalgs

    @property
    def delegated_credentials(self) -> Sequence[SignatureAlgorithms]:
        return self._delegated_credentials

    @property
    def record_size_limit(self) -> int | None:
        return self._record_size_limit

    @property
    def key_shares_limit(self) -> int | None:
        return self._key_shares_limit

    @property
    def aes_hw_override(self) -> bool:
        return self._aes_hw_override

    @property
    def preserve_tls13_cipher_list(self) -> bool:
        return self._preserve_tls13_cipher_list

    @staticmethod
    def _compose_next_protocols(protos: Sequence[NextProtocol | bytes]) -> bytes:
        res = b""
        for p in protos:
            value = p.value if isinstance(p, NextProtocol) else p
            res += len(value).to_bytes()
            res += value

        return res

    def _tls_options0(self):
        return (
            self._lowest_supported_version.value,
            self._highest_supported_version.value,
            self._ocsp_stapling,
            self._signed_cert_timestamps,
            self._session_ticket,
            self._psk_dhe_ke,
            self._renegotiation,
            self._grease,
            self._permute_extensions,
            self._raw_alpn_protocols_list,
            self._raw_curves_list,
            self._raw_cipher_list,
        )

    def _tls_options1(self):
        return (
            self._raw_sigalgs_list,
            self._raw_delegated_credentials_list,
            self._record_size_limit,
            self._key_shares_limit,
            self._aes_hw_override,
            self._preserve_tls13_cipher_list,
            self._certificate_compression_algorithms,
            self._extension_permutation,
        )

    def _handshake_options(self):
        return (
            self._random_aes_hw_override,
            self._raw_alps_protocols_list,
            self._alps_use_new_codepoint,
            # self._pre_shared_key,
            self._ech_grease,
            # self._psk_skip_session_ticket,
        )
