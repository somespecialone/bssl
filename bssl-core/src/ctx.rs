use boring2::ssl::{
    Ssl, SslContext, SslContextBuilder, SslMethod, SslMode, SslOptions, SslVerifyMode, SslVersion,
};
use boring2::x509::{X509, store::X509StoreBuilder};
use pyo3::prelude::*;
use pyo3::types::PyTuple;
use rustls_native_certs::load_native_certs;

use crate::buf::TLSBuffer;
use crate::cert_compressors::*;
use crate::enums::*;
use crate::err::{ErrToPyErr, TLSError};
use crate::sock::TLSSocket;
use crate::ssl::SslRefExt;
use crate::utils::random_bool;

struct HandshakeConfig {
    // session_cache
    random_aes_hw_override: bool,
    alps_protocols: Option<Vec<Vec<u8>>>,
    alps_use_new_codepoint: bool,
    // pre_shared_key: bool,
    ech_grease: bool,
    // psk_skip_session_ticket: bool,
}

// https://peps.python.org/pep-0748/#context
#[pyclass]
pub struct ClientContext {
    #[pyo3(get)]
    configuration: Py<PyAny>,

    ssl_ctx: SslContext,
    handshake_config: HandshakeConfig,
}

#[pymethods]
impl ClientContext {
    #[new]
    fn new(configuration: Py<PyAny>, py: Python<'_>) -> PyResult<Self> {
        let tls_opts_raw0 = configuration.call_method0(py, "_tls_options0")?.into_any();
        let tls_opts_bound0: &Bound<'_, PyTuple> = tls_opts_raw0.downcast_bound(py)?;
        let (
            min_tls_version,
            max_tls_version,
            ocsp_stapling,
            signed_cert_timestamps,
            session_ticket,
            psk_dhe_ke,
            renegotiation,
            enable_ech_grease,
            permute_extensions,
            alpn_protocols,
            curves,
            ciphers,
        ) = tls_opts_bound0.extract::<(
            String,
            String,
            bool,
            bool,
            bool,
            bool,
            bool,
            bool,
            bool,
            Option<Vec<u8>>,
            Option<String>,
            String,
        )>()?;

        let tls_opts_raw1 = configuration.call_method0(py, "_tls_options1")?.into_any();
        let tls_opts_bound1: &Bound<'_, PyTuple> = tls_opts_raw1.downcast_bound(py)?;
        let (
            sigalgs,
            delegated_credentials,
            record_size_limit,
            key_shares_limit,
            aes_hw_override,
            preserve_tls13_cipher_list,
            certificate_compression_algorithms,
            extension_permutation,
        ) = tls_opts_bound1.extract::<(
            Option<String>,
            Option<String>,
            Option<u16>,
            Option<u8>,
            bool,
            bool,
            Option<Vec<CertificateCompressionAlgorithm>>,
            Option<Vec<ExtensionType>>,
        )>()?;

        let handshake_opts_raw = configuration
            .call_method0(py, "_handshake_options")?
            .into_any();
        let handshake_opts_bound: &Bound<'_, PyTuple> = handshake_opts_raw.downcast_bound(py)?;
        let (
            random_aes_hw_override,
            alps_protocols,
            alps_use_new_codepoint,
            // pre_shared_key,
            ech_grease,
            // psk_skip_session_ticket,
        ) = handshake_opts_bound.extract::<(bool, Option<Vec<Vec<u8>>>, bool, bool)>()?;

        let mut builder =
            SslContextBuilder::new(SslMethod::tls_client()).map_err(TLSError::from_error_stack)?;

        builder
            .set_min_proto_version(Some(SslVersion::from_python_enum_value(&min_tls_version)?))
            .map_err(TLSError::from_error_stack)?;

        builder
            .set_max_proto_version(Some(SslVersion::from_python_enum_value(&max_tls_version)?))
            .map_err(TLSError::from_error_stack)?;

        if ocsp_stapling {
            builder.enable_ocsp_stapling();
        }
        if signed_cert_timestamps {
            builder.enable_signed_cert_timestamps();
        }
        builder.set_grease_enabled(enable_ech_grease);
        builder.set_permute_extensions(permute_extensions);

        if let Some(alpn_protocols) = alpn_protocols {
            builder
                .set_alpn_protos(&alpn_protocols)
                .map_err(TLSError::from_error_stack)?;
        }
        if let Some(curves) = curves {
            builder
                .set_curves_list(&curves)
                .map_err(TLSError::from_error_stack)?;
        }

        if let Some(sigalgs) = sigalgs {
            builder
                .set_sigalgs_list(&sigalgs)
                .map_err(TLSError::from_error_stack)?;
        }
        if let Some(delegated_credentials) = delegated_credentials {
            builder
                .set_delegated_credentials(&delegated_credentials)
                .map_err(TLSError::from_error_stack)?;
        }

        if let Some(record_size_limit) = record_size_limit {
            builder.set_record_size_limit(record_size_limit);
        }

        if let Some(key_shares_limit) = key_shares_limit {
            builder.set_key_shares_limit(key_shares_limit);
        }

        builder.set_aes_hw_override(aes_hw_override);

        builder.set_preserve_tls13_cipher_list(preserve_tls13_cipher_list); // before set_cipher_list
        builder
            .set_cipher_list(&ciphers)
            .map_err(TLSError::from_error_stack)?;

        if let Some(ref extension_permutation) = extension_permutation {
            let indices = extension_permutation
                .iter()
                .map(|ext| ext.into())
                .collect::<Vec<_>>();

            builder
                .set_extension_permutation(&indices)
                .map_err(TLSError::from_error_stack)?;
        }

        if let Some(ref certificate_compression_algorithms) = certificate_compression_algorithms {
            for alg in certificate_compression_algorithms {
                match *alg {
                    CertificateCompressionAlgorithm::Brotli => {
                        builder
                            .add_certificate_compression_algorithm(
                                BrotliCertificateCompressor::default(),
                            )
                            .map_err(TLSError::from_error_stack)?;
                    }
                    CertificateCompressionAlgorithm::Zlib => {
                        builder
                            .add_certificate_compression_algorithm(
                                ZlibCertificateCompressor::default(),
                            )
                            .map_err(TLSError::from_error_stack)?;
                    }
                    CertificateCompressionAlgorithm::Zstd => {
                        builder
                            .add_certificate_compression_algorithm(
                                ZstdCertificateCompressor::default(),
                            )
                            .map_err(TLSError::from_error_stack)?;
                    }
                }
            }
        }

        builder
            .set_default_verify_paths()
            .map_err(TLSError::from_error_stack)?; // Do we need this?
        builder.set_verify(SslVerifyMode::PEER);

        // defaults from SslConnector and _ssl.c
        let mut mode = SslMode::AUTO_RETRY;
        mode |= SslMode::RELEASE_BUFFERS | SslMode::ACCEPT_MOVING_WRITE_BUFFER;
        builder.set_mode(mode);

        // also python defaults
        let mut opts = SslOptions::NO_SSLV2 | SslOptions::NO_SSLV3;
        opts |= SslOptions::SINGLE_DH_USE | SslOptions::SINGLE_ECDH_USE;

        if !session_ticket {
            opts |= SslOptions::NO_TICKET;
        }

        if !psk_dhe_ke {
            opts |= SslOptions::NO_PSK_DHE_KE;
        }

        if !renegotiation {
            opts |= SslOptions::NO_RENEGOTIATION;
        }

        if certificate_compression_algorithms.is_none() {
            opts |= SslOptions::NO_COMPRESSION;
        }

        builder.set_options(opts);

        // store
        let mut store_builder = X509StoreBuilder::new().map_err(TLSError::from_error_stack)?;

        // set native certs
        let certs_res = load_native_certs();
        for cert_der in &certs_res.certs {
            let cert = X509::from_der(cert_der).map_err(TLSError::from_error_stack)?;
            store_builder
                .add_cert(cert)
                .map_err(TLSError::from_error_stack)?;
        }

        // for cert_error in certs_res.errors {
        //     // waring or similar as possible options to handle errors
        // }

        let store = store_builder.build();

        // builder.set_cert_store_builder(store_builder);
        builder.set_cert_store_ref(&store);

        let ssl_ctx = builder.build();

        let handshake_config = HandshakeConfig {
            random_aes_hw_override,
            alps_protocols,
            alps_use_new_codepoint,
            // pre_shared_key,
            ech_grease,
            // psk_skip_session_ticket,
        };

        Ok(Self {
            configuration,
            ssl_ctx,
            handshake_config,
        })
    }

    fn connect(
        self_: Py<ClientContext>,
        address: (Option<String>, i32),
        py: Python<'_>,
    ) -> PyResult<TLSSocket> {
        let (host, port) = address;
        let address_str = format!("{}:{}", host.as_deref().unwrap_or(""), port);
        let server_hostname = host.as_deref().unwrap_or("");

        let self_py = self_.clone_ref(py);
        let self_borrowed = self_.borrow(py);

        let ssl = Ssl::new(&self_borrowed.ssl_ctx).map_err(TLSError::from_error_stack)?;
        match TLSSocket::new(self_py, ssl, &address_str, server_hostname) {
            Ok(sock) => Ok(sock),
            Err(e) => Err(TLSError::new_err(e)),
        }
    }

    fn create_buffer(
        self_: Py<ClientContext>,
        server_hostname: &str,
        py: Python<'_>,
    ) -> PyResult<TLSBuffer> {
        let self_py = self_.clone_ref(py);
        let self_borrowed = self_.borrow(py);

        let mut ssl = Ssl::new(&self_borrowed.ssl_ctx).map_err(TLSError::from_error_stack)?;

        let cfg = &self_borrowed.handshake_config;

        ssl.set_enable_ech_grease(cfg.ech_grease);

        if cfg.random_aes_hw_override {
            ssl.set_aes_hw_override(random_bool());
        }

        if let Some(ref alps_protocols) = cfg.alps_protocols {
            for alps in alps_protocols {
                ssl.add_application_settings(alps)
                    .map_err(TLSError::from_error_stack)?;
            }

            if !alps_protocols.is_empty() && cfg.alps_use_new_codepoint {
                ssl.set_alps_use_new_codepoint(true);
            }
        }

        let buf =
            TLSBuffer::new(self_py, ssl, server_hostname).map_err(TLSError::from_error_stack)?;
        Ok(buf)
    }
}
