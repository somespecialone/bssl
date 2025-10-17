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
        raw_cipher_list: str | None = None,
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
        """
        Gathers both PEP 748-style configuration knobs and some
        implementation-specific options used by this project. Unless otherwise noted,
        parameters map directly to the corresponding TLS handshake/client options.

        :param certificate_chain: Client authentication chain to present to servers.
            Not yet implemented; passing a non-None value will raise NotImplementedError.
        :param ciphers: Explicit list of cipher suites to advertise. If provided, it is
            mutually exclusive with raw_cipher_list.
        :param inner_protocols: Protocols for ALPN/NPN (e.g., b"h2", b"http/1.1"). You can
            pass NextProtocol enums or raw bytes.
        :param lowest_supported_version: Minimum TLS protocol version the client will negotiate.
        :param highest_supported_version: Maximum TLS protocol version the client will negotiate.
        :param trust_store: Custom trust store to validate server certificates.
            Not yet implemented; passing a non-None value will raise NotImplementedError.
        :param raw_cipher_list: OpenSSL-style cipher string. Ignored if ciphers is
            provided. By default uses a safe preset.
        :param ocsp_stapling: Request and validate OCSP stapling if available.
        :param signed_cert_timestamps: Request/validate Certificate Transparency SCTs.
        :param session_ticket: Enable TLS session tickets for resumption.
        :param psk_dhe_ke: Offer PSK with DHE key exchange when using PSK.
        :param renegotiation: Allow TLS renegotiation (where applicable).
        :param grease: Enable GREASE extensions to exercise server tolerance.
        :param permute_extensions: Randomize/permute extension ordering.
        :param curves: Supported (EC) curves list as Curves enums or IANA names.
        :param sigalgs: Signature algorithms to advertise.
        :param delegated_credentials: Signature algorithms allowed for delegated credentials.
        :param record_size_limit: RFC 8449 Record Size Limit to advertise, in bytes.
        :param key_shares_limit: Limit number of TLS 1.3 key shares to send.
        :param aes_hw_override: Force AES hardware capability override.
        :param preserve_tls13_cipher_list: Keep TLS 1.3 cipher list ordering as given.
        :param random_aes_hw_override: Randomize AES HW override.
        :param alps_protocols: ALPS protocol list (bytes or NextProtocol).
        :param alps_use_new_codepoint: Use the new IANA codepoint for ALPS.
        :param ech_grease: Send ECH GREASE to exercise server tolerance.
        :param certificate_compression_algorithms: Supported certificate compression
            algorithms to advertise.
        :param extension_permutation: Explicit extension ordering/permutation.

        :raises NotImplementedError: If certificate_chain or trust_store is provided.
        :raises ValueError: If both ciphers and raw_cipher_list are set.
        """

        if certificate_chain:
            raise NotImplementedError("certificate_chain is not yet implemented")
        if trust_store:
            raise NotImplementedError("trust_store is not yet implemented")

        if ciphers and raw_cipher_list:
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
        self._raw_cipher_list = ":".join(c.name for c in ciphers) if ciphers else DEF_CIPHER_LIST
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
        """Client certificate chain used for mutual TLS, if configured"""
        return self._certificate_chain

    @property
    def ciphers(self) -> Sequence[CipherSuite]:
        """Explicit list of cipher suites configured for the client"""
        return self._ciphers

    @property
    def raw_ciphers_list(self) -> str:
        """OpenSSL-style cipher string derived from ciphers or provided directly"""
        return self._raw_cipher_list

    @property
    def inner_protocols(self) -> Sequence[NextProtocol | bytes]:
        """ALPN/NPN protocol list to advertise to the server"""
        return self._inner_protocols

    @property
    def lowest_supported_version(self) -> TLSVersion:
        """Minimum TLS version allowed during negotiation"""
        return self._lowest_supported_version

    @property
    def highest_supported_version(self) -> TLSVersion:
        """Maximum TLS version allowed during negotiation"""
        return self._highest_supported_version

    @property
    def trust_store(self) -> TrustStore | None:
        """Custom trust anchors used for server certificate verification"""
        return self._trust_store

    @property
    def signed_cert_timestamps(self) -> bool:
        """Whether to request/validate Certificate Transparency SCTs"""
        return self._signed_cert_timestamps

    # impl
    @property
    def ocsp_stapling(self) -> bool:
        """Whether OCSP stapling is requested and validated"""
        return self._ocsp_stapling

    @property
    def session_ticket(self) -> bool:
        """Whether TLS session tickets are enabled for resumption"""
        return self._session_ticket

    @property
    def psk_dhe_ke(self) -> bool:
        """Offer PSK with DHE key exchange when PSK is in use"""
        return self._psk_dhe_ke

    @property
    def renegotiation(self) -> bool:
        """Whether TLS renegotiation is allowed (where applicable)"""
        return self._renegotiation

    @property
    def grease(self) -> bool:
        """Whether GREASE values are enabled to exercise server tolerance"""
        return self._grease

    @property
    def permute_extensions(self) -> bool:
        """Whether to permute/randomize the order of TLS extensions"""
        return self._permute_extensions

    @property
    def curves(self) -> Sequence[Curves]:
        """Elliptic curves supported by the client, in preference order"""
        return self._curves

    @property
    def sigalgs(self) -> Sequence[SignatureAlgorithms]:
        """Signature algorithms that the client will advertise"""
        return self._sigalgs

    @property
    def delegated_credentials(self) -> Sequence[SignatureAlgorithms]:
        """Signature algorithms accepted for delegated credentials"""
        return self._delegated_credentials

    @property
    def record_size_limit(self) -> int | None:
        """RFC 8449 record size limit to advertise (bytes), if any"""
        return self._record_size_limit

    @property
    def key_shares_limit(self) -> int | None:
        """Limit on the number of TLS 1.3 key shares to send, if any"""
        return self._key_shares_limit

    @property
    def aes_hw_override(self) -> bool:
        """Override AES hardware capability detection"""
        return self._aes_hw_override

    @property
    def preserve_tls13_cipher_list(self) -> bool:
        """Keep TLS 1.3 cipher suite ordering as specified by the configuration"""
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
