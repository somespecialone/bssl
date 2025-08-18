use boring2::ssl::{ExtensionType as ET, SslVersion};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

pub trait FromPythonEnumValue<T>: Sized {
    fn from_python_enum_value(value: T) -> PyResult<Self>;
}

impl FromPythonEnumValue<&str> for SslVersion {
    fn from_python_enum_value(value: &str) -> PyResult<Self> {
        match value {
            "MINIMUM_SUPPORTED" | "TLSv1.0" => Ok(SslVersion::TLS1),
            "TLSv1.1" => Ok(SslVersion::TLS1_1),
            "TLSv1.2" => Ok(SslVersion::TLS1_2),
            "TLSv1.3" | "MAXIMUM_SUPPORTED" => Ok(SslVersion::TLS1_3),
            _ => Err(PyValueError::new_err(format!(
                "Unsupported or invalid tls version {value}"
            ))),
        }
    }
}

#[pyclass(eq)]
#[derive(Clone, Copy, PartialEq)]
pub enum CertificateCompressionAlgorithm {
    #[pyo3(name = "ZLIB")]
    Zlib,
    #[pyo3(name = "BROTLI")]
    Brotli,
    #[pyo3(name = "ZSTD")]
    Zstd,
}

#[pyclass(eq)]
#[derive(Clone, Copy, PartialEq)]
pub enum ExtensionType {
    #[pyo3(name = "SERVER_NAME")]
    ServerName,
    #[pyo3(name = "STATUS_REQUEST")]
    StatusRequest,
    #[pyo3(name = "EC_POINT_FORMATS")]
    EcPointFormats,
    #[pyo3(name = "SIGNATURE_ALGORITHMS")]
    SignatureAlgorithms,
    #[pyo3(name = "SRTP")]
    Srtp,
    #[pyo3(name = "APPLICATION_LAYER_PROTOCOL_NEGOTIATION")]
    ApplicationLayerProtocolNegotiation,
    #[pyo3(name = "PADDING")]
    Padding,
    #[pyo3(name = "EXTENDED_MASTER_SECRET")]
    ExtendedMasterSecret,
    #[pyo3(name = "QUIC_TRANSPORT_PARAMETERS_LEGACY")]
    QuicTransportParametersLegacy,
    #[pyo3(name = "QUIC_TRANSPORT_PARAMETERS_STANDARD")]
    QuicTransportParametersStandard,
    #[pyo3(name = "CERT_COMPRESSION")]
    CertCompression,
    #[pyo3(name = "SESSION_TICKET")]
    SessionTicket,
    #[pyo3(name = "SUPPORTED_GROUPS")]
    SupportedGroups,
    #[pyo3(name = "PRE_SHARED_KEY")]
    PreSharedKey,
    #[pyo3(name = "EARLY_DATA")]
    EarlyData,
    #[pyo3(name = "SUPPORTED_VERSIONS")]
    SupportedVersions,
    #[pyo3(name = "COOKIE")]
    Cookie,
    #[pyo3(name = "PSK_KEY_EXCHANGE_MODES")]
    PskKeyExchangeModes,
    #[pyo3(name = "CERTIFICATE_AUTHORITIES")]
    CertificateAuthorities,
    #[pyo3(name = "SIGNATURE_ALGORITHMS_CERT")]
    SignatureAlgorithmsCert,
    #[pyo3(name = "KEY_SHARE")]
    KeyShare,
    #[pyo3(name = "RENEGOTIATE")]
    Renegotiate,
    #[pyo3(name = "DELEGATED_CREDENTIAL")]
    DelegatedCredential,
    #[pyo3(name = "APPLICATION_SETTINGS")]
    ApplicationSettings,
    #[pyo3(name = "APPLICATION_SETTINGS_NEW")]
    ApplicationSettingsNew,
    #[pyo3(name = "ENCRYPTED_CLIENT_HELLO")]
    EncryptedClientHello,
    #[pyo3(name = "CERTIFICATE_TIMESTAMP")]
    CertificateTimestamp,
    #[pyo3(name = "NEXT_PROTO_NEG")]
    NextProtoNeg,
    #[pyo3(name = "CHANNEL_ID")]
    ChannelId,
    #[pyo3(name = "RECORD_SIZE_LIMIT")]
    RecordSizeLimit,
}

impl From<&ExtensionType> for ET {
    fn from(value: &ExtensionType) -> Self {
        match value {
            ExtensionType::ServerName => ET::SERVER_NAME,
            ExtensionType::StatusRequest => ET::STATUS_REQUEST,
            ExtensionType::EcPointFormats => ET::EC_POINT_FORMATS,
            ExtensionType::SignatureAlgorithms => ET::SIGNATURE_ALGORITHMS,
            ExtensionType::Srtp => ET::SRTP,
            ExtensionType::ApplicationLayerProtocolNegotiation => {
                ET::APPLICATION_LAYER_PROTOCOL_NEGOTIATION
            }
            ExtensionType::Padding => ET::PADDING,
            ExtensionType::ExtendedMasterSecret => ET::EXTENDED_MASTER_SECRET,
            ExtensionType::QuicTransportParametersLegacy => ET::QUIC_TRANSPORT_PARAMETERS_LEGACY,
            ExtensionType::QuicTransportParametersStandard => {
                ET::QUIC_TRANSPORT_PARAMETERS_STANDARD
            }
            ExtensionType::CertCompression => ET::CERT_COMPRESSION,
            ExtensionType::SessionTicket => ET::SESSION_TICKET,
            ExtensionType::SupportedGroups => ET::SUPPORTED_GROUPS,
            ExtensionType::PreSharedKey => ET::PRE_SHARED_KEY,
            ExtensionType::EarlyData => ET::EARLY_DATA,
            ExtensionType::SupportedVersions => ET::SUPPORTED_VERSIONS,
            ExtensionType::Cookie => ET::COOKIE,
            ExtensionType::PskKeyExchangeModes => ET::PSK_KEY_EXCHANGE_MODES,
            ExtensionType::CertificateAuthorities => ET::CERTIFICATE_AUTHORITIES,
            ExtensionType::SignatureAlgorithmsCert => ET::SIGNATURE_ALGORITHMS_CERT,
            ExtensionType::KeyShare => ET::KEY_SHARE,
            ExtensionType::Renegotiate => ET::RENEGOTIATE,
            ExtensionType::DelegatedCredential => ET::DELEGATED_CREDENTIAL,
            ExtensionType::ApplicationSettings => ET::APPLICATION_SETTINGS,
            ExtensionType::ApplicationSettingsNew => ET::APPLICATION_SETTINGS_NEW,
            ExtensionType::EncryptedClientHello => ET::ENCRYPTED_CLIENT_HELLO,
            ExtensionType::CertificateTimestamp => ET::CERTIFICATE_TIMESTAMP,
            ExtensionType::NextProtoNeg => ET::NEXT_PROTO_NEG,
            ExtensionType::ChannelId => ET::CHANNEL_ID,
            ExtensionType::RecordSizeLimit => ET::RECORD_SIZE_LIMIT,
        }
    }
}
