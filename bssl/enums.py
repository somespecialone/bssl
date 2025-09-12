from enum import IntEnum, Enum

from .bssl import CertificateCompressionAlgorithm, ExtensionType


# https://peps.python.org/pep-0748/#proposed-interface
class CipherSuite(IntEnum):
    """
    Known cipher suites.

    See: <https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml>
    """

    # pep
    TLS_AES_128_GCM_SHA256 = 0x1301
    TLS_AES_256_GCM_SHA384 = 0x1302
    TLS_CHACHA20_POLY1305_SHA256 = 0x1303
    TLS_AES_128_CCM_SHA256 = 0x1304
    TLS_AES_128_CCM_8_SHA256 = 0x1305
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = 0xC02B
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = 0xC02C
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0xC02F
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = 0xC030
    TLS_ECDHE_ECDSA_WITH_AES_128_CCM = 0xC0AC
    TLS_ECDHE_ECDSA_WITH_AES_256_CCM = 0xC0AD
    TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 = 0xC0AE
    TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8 = 0xC0AF
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = 0xCCA8
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = 0xCCA9
    # extended
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA = 0xC009
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA = 0xC00A
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA = 0xC013
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA = 0xC014
    TLS_RSA_WITH_AES_128_GCM_SHA256 = 0x009C
    TLS_RSA_WITH_AES_256_GCM_SHA384 = 0x009D
    TLS_RSA_WITH_AES_128_CBC_SHA = 0x002F
    TLS_RSA_WITH_AES_256_CBC_SHA = 0x0035
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 = 0xC023
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 = 0xC024
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 = 0xC027
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 = 0xC028
    TLS_RSA_WITH_AES_128_CBC_SHA256 = 0x003C
    TLS_RSA_WITH_AES_256_CBC_SHA256 = 0x003D
    TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA = 0xC008
    TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA = 0xC012
    TLS_RSA_WITH_3DES_EDE_CBC_SHA = 0x000A


# https://peps.python.org/pep-0748/#protocol-negotiation
class NextProtocol(Enum):
    """The underlying negotiated ("next") protocol."""

    # pep
    H2 = b"h2"
    H2C = b"h2c"
    HTTP1 = b"http/1.1"
    WEBRTC = b"webrtc"
    C_WEBRTC = b"c-webrtc"
    FTP = b"ftp"
    STUN = b"stun.nat-discovery"
    TURN = b"stun.turn"

    # extended
    HTTP2 = H2  # alias
    HTTP3 = b"h3"


# https://peps.python.org/pep-0748/#tls-versions
class TLSVersion(Enum):
    """
    TLS versions.

    The `MINIMUM_SUPPORTED` and `MAXIMUM_SUPPORTED` variants are "open ended",
    and refer to the "lowest mutually supported" and "highest mutually supported"
    TLS versions, respectively.
    """

    # pep
    MINIMUM_SUPPORTED = "MINIMUM_SUPPORTED"
    TLSv1_2 = "TLSv1.2"
    TLSv1_3 = "TLSv1.3"
    MAXIMUM_SUPPORTED = "MAXIMUM_SUPPORTED"
    # extended
    TLSv1_0 = "TLSv1.0"
    TLSv1_1 = "TLSv1.1"


class Curves(Enum):
    X25519 = "X25519"
    P_256 = "P-256"
    P_384 = "P-384"
    P_521 = "P-521"
    FFDHE2048 = "ffdhe2048"
    FFDHE3072 = "ffdhe3072"
    X25519KYBER768DRAFT00 = "X25519Kyber768Draft00"
    X25519MLKEM768 = "X25519MLKEM768"


class SignatureAlgorithms(IntEnum):
    """
    TLS Signature Schemes

    See: <https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-signaturescheme>
    """

    ecdsa_secp256r1_sha256 = 0x0403
    ecdsa_secp384r1_sha384 = 0x0503
    ecdsa_secp521r1_sha512 = 0x0603
    rsa_pss_rsae_sha256 = 0x0804
    rsa_pss_rsae_sha384 = 0x0805
    rsa_pss_rsae_sha512 = 0x0806
    rsa_pkcs1_sha256 = 0x0401
    rsa_pkcs1_sha384 = 0x0501
    rsa_pkcs1_sha512 = 0x0601
    ecdsa_sha1 = 0x0203
    rsa_pkcs1_sha1 = 0x0201
