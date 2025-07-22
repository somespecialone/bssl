use boring::ssl::{
    Ssl, SslContext, SslContextBuilder, SslMethod, SslMode, SslOptions, SslVerifyMode, SslVersion,
};
use boring::x509::{X509, store::X509StoreBuilder};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use rustls_native_certs::load_native_certs;

use crate::buf::TLSBuffer;
use crate::sock::TLSSocket;

#[pyclass]
pub struct ClientContext {
    inner: SslContext,
}

const DEF_CIPHERS: &str = "DEFAULT:!aNULL:!eNULL:!MD5:!3DES:!DES:!RC4:!IDEA:!SEED:!aDSS:!SRP:!PSK";
const MINIMUM_SUPPORTED: &str = "MINIMUM_SUPPORTED";
const TLSV1_2: &str = "TLSv1.2";
const TLSV1_3: &str = "TLSv1.3";
const MAXIMUM_SUPPORTED: &str = "MAXIMUM_SUPPORTED";

fn get_tls_version(version: &str) -> Result<SslVersion, PyErr> {
    match version {
        MINIMUM_SUPPORTED => Ok(SslVersion::TLS1),
        TLSV1_2 => Ok(SslVersion::TLS1_2),
        TLSV1_3 | MAXIMUM_SUPPORTED => Ok(SslVersion::TLS1_3),
        _ => Err(PyValueError::new_err(format!(
            "Unsupported or invalid tls version {version}"
        ))),
    }
}

#[pymethods]
impl ClientContext {
    #[new]
    #[pyo3(signature = (verify=true, ciphers=DEF_CIPHERS, min_tls_version=MINIMUM_SUPPORTED, max_tls_version=MAXIMUM_SUPPORTED))]
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

        let min_tls_version = get_tls_version(min_tls_version)?;
        builder
            .set_min_proto_version(Some(min_tls_version))
            .unwrap();

        let max_tls_version = get_tls_version(max_tls_version)?;
        builder
            .set_max_proto_version(Some(max_tls_version))
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

    fn connect(
        self_: Py<ClientContext>,
        address: &str,
        server_hostname: &str,
        py: Python<'_>,
    ) -> PyResult<TLSSocket> {
        let py_self = self_.clone_ref(py);
        let borrowed = self_.borrow(py);
        // TODO check how other projects handle address/hostname tension
        let ssl = Ssl::new(&borrowed.inner).unwrap();
        let sock = TLSSocket::new(py_self, ssl, address, server_hostname);
        Ok(sock)
    }

    fn create_buffer(
        self_: Py<ClientContext>,
        server_hostname: &str,
        py: Python<'_>,
    ) -> PyResult<TLSBuffer> {
        let py_self = self_.clone_ref(py);
        let borrowed = self_.borrow(py);

        let ssl = Ssl::new(&borrowed.inner).unwrap();
        let buf = TLSBuffer::new(py_self, ssl, server_hostname);
        Ok(buf)
    }
}
