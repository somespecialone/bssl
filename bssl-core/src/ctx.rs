use boring::ssl::{
    Ssl, SslContext, SslContextBuilder, SslMethod, SslMode, SslOptions, SslVerifyMode, SslVersion,
};
use boring::x509::{X509, store::X509StoreBuilder};
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use rustls_native_certs::load_native_certs;

use crate::buf;
use crate::socket;

#[pyclass]
pub struct ClientContext {
    inner: SslContext,
}

// from python enum, better to make rust-python enum
const MINIMUM_SUPPORTED: &str = "MINIMUM_SUPPORTED";
const TLSV1_2: &str = "TLSv1.2";
const TLSV1_3: &str = "TLSv1.3";
const MAXIMUM_SUPPORTED: &str = "MAXIMUM_SUPPORTED";

// TODO how about to move/add defaults here and not at python wrapper?
#[pymethods]
impl ClientContext {
    #[new]
    fn new(
        verify: bool,
        ciphers: &str,
        min_tls_version: &str,
        max_tls_version: &str,
    ) -> PyResult<Self> {
        let mut builder = SslContextBuilder::new(SslMethod::tls_client()).unwrap();

        if verify {
            builder.set_default_verify_paths().unwrap(); // Do we need this?
            builder.set_verify(SslVerifyMode::PEER);
        } else {
            builder.set_verify(SslVerifyMode::NONE);
        }

        builder.set_cipher_list(ciphers).unwrap();

        // defaults from SslConnector and _ssl.c
        let mut mode = SslMode::AUTO_RETRY;
        mode |= SslMode::RELEASE_BUFFERS | SslMode::ACCEPT_MOVING_WRITE_BUFFER;
        builder.set_mode(mode);

        let mut opts = SslOptions::NO_SSLV2 | SslOptions::NO_SSLV3;
        opts |= SslOptions::NO_COMPRESSION;
        opts |= SslOptions::SINGLE_DH_USE | SslOptions::SINGLE_ECDH_USE;
        builder.set_options(opts);

        // explicitly select and set min version
        let min_tls_version = match min_tls_version {
            MINIMUM_SUPPORTED => SslVersion::TLS1,
            TLSV1_2 => SslVersion::TLS1_2,
            TLSV1_3 | MAXIMUM_SUPPORTED => SslVersion::TLS1_3,
            _ => {
                return Err(PyValueError::new_err(format!(
                    "Invalid tls version {}",
                    min_tls_version
                )));
            }
        };
        builder
            .set_min_proto_version(Some(min_tls_version))
            .unwrap();

        // same goes for max version
        let max_tls_version = match max_tls_version {
            MINIMUM_SUPPORTED => SslVersion::TLS1,
            TLSV1_2 => SslVersion::TLS1_2,
            TLSV1_3 | MAXIMUM_SUPPORTED => SslVersion::TLS1_3,
            _ => {
                return Err(PyValueError::new_err(format!(
                    "Invalid tls version {}",
                    max_tls_version
                )));
            }
        };
        builder
            .set_max_proto_version(Some(min_tls_version))
            .unwrap();

        // store
        let mut store_builder = X509StoreBuilder::new().unwrap();

        // set native certs
        let certs_res = load_native_certs();
        certs_res.certs.iter().for_each(|cert_der| {
            store_builder
                .add_cert(X509::from_der(cert_der).unwrap())
                .unwrap();
        });

        // for cert_error in certs_res.errors {
        //     // waring or similar as possible options to handle errors
        // }

        let store = store_builder.build();

        builder.set_cert_store(store);

        let ctx = builder.build();

        Ok(Self { inner: ctx })
    }

    fn connect(&self, address: &str, server_hostname: &str) -> PyResult<socket::TLSSocket> {
        // TODO check how other projects handle address/hostname tension
        let ssl = Ssl::new(&self.inner).unwrap();
        let sock = socket::new(ssl, address, server_hostname);
        Ok(sock)
    }

    fn create_buffer(&self, server_hostname: &str) -> PyResult<buf::TLSBuffer> {
        let ssl = Ssl::new(&self.inner).unwrap();
        let buf = buf::new(ssl, server_hostname);
        Ok(buf)
    }
}
