use std::io::{Read, Write};
use std::net::TcpStream;

use boring::ssl::{Ssl, SslStream};
use boring::x509::verify::X509CheckFlags;
use pyo3::exceptions::{PyNotImplementedError, PyRuntimeError};
use pyo3::prelude::*;

use crate::ext::SslExt;

#[pyclass]
pub struct TLSSocket {
    stream: SslStream<TcpStream>,
}

#[pymethods]
impl TLSSocket {
    fn send(&mut self, data: &[u8]) -> PyResult<usize> {
        match self.stream.write(data) {
            Ok(amount) => Ok(amount),
            Err(err) => Err(PyRuntimeError::new_err(err.to_string())),
        }
    }

    fn recv(&mut self, bufsize: usize) -> PyResult<Vec<u8>> {
        let mut buf = vec![0u8; bufsize];
        match self.stream.read(&mut buf) {
            Ok(amount) => {
                buf.truncate(amount);
                Ok(buf)
            }
            Err(err) => Err(PyRuntimeError::new_err(err.to_string())),
        }
    }

    fn do_handshake(&mut self) -> PyResult<()> {
        match self.stream.do_handshake() {
            Ok(_) => Ok(()),
            Err(err) => Err(PyRuntimeError::new_err(format!(
                "TLS handshake failed. Msg: {}, code: {}",
                err,
                err.code().as_raw()
            ))),
        }
    }

    fn getsockname(&self) -> PyResult<String> {
        Ok(self.stream.get_ref().local_addr().unwrap().to_string())
    }

    fn getpeercert(&self) -> PyResult<Vec<u8>> {
        Err(PyNotImplementedError::new_err("Not implemented"))
    }

    fn getpeername(&self) -> PyResult<String> {
        Ok(self.stream.get_ref().peer_addr().unwrap().to_string())
    }

    fn cipher(&self) -> PyResult<Option<usize>> {
        Err(PyNotImplementedError::new_err("Not implemented"))
    }

    fn negotiated_protocol(&self) -> PyResult<Option<Vec<u8>>> {
        Err(PyNotImplementedError::new_err("Not implemented"))
    }

    #[getter]
    fn negotiated_tls_version(&self) -> PyResult<Option<String>> {
        Err(PyNotImplementedError::new_err("Not implemented"))
    }

    fn listen(&self, backlog: usize) -> PyResult<()> {
        Err(PyNotImplementedError::new_err("Not implemented"))
    }

    fn accept(&self) -> PyResult<(Self, (Option<String>, usize))> {
        Err(PyNotImplementedError::new_err("Not implemented"))
    }

    #[pyo3(signature = (force=false))]
    fn close(&mut self, force: bool) -> PyResult<()> {
        match self.stream.shutdown() {
            Ok(_) => Ok(()),
            Err(err) => Err(PyRuntimeError::new_err(err.to_string())),
        }
    }
}

pub fn new(mut ssl: Ssl, address: &str, server_hostname: &str) -> TLSSocket {
    ssl.set_hostname(server_hostname).unwrap();

    let ssl_param = ssl.param_mut();
    ssl_param.set_hostflags(X509CheckFlags::NO_PARTIAL_WILDCARDS);
    ssl_param.set_host(server_hostname).unwrap();

    ssl.set_connect_state();

    let tcp_stream = TcpStream::connect(address).unwrap();
    let stream = SslStream::new(ssl, tcp_stream).unwrap();

    TLSSocket { stream }
}
