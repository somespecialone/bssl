use std::io::{ErrorKind, Read, Write};
use std::net::TcpStream;

use boring2::ssl::{ShutdownResult, Ssl, SslStream};
use boring2::x509::verify::X509CheckFlags;
use pyo3::exceptions::{
    PyConnectionAbortedError, PyConnectionError, PyConnectionResetError, PyNotImplementedError,
};
use pyo3::prelude::*;

use crate::ctx::ClientContext;
use crate::err::{ErrToPyErr, RaggedEOF, TLSError};
use crate::ssl::SslRefExt;

// https://peps.python.org/pep-0748/#socket
#[pyclass]
pub struct TLSSocket {
    #[pyo3(get)]
    context: Py<ClientContext>,

    stream: SslStream<TcpStream>,
}

impl TLSSocket {
    pub fn new(
        context: Py<ClientContext>,
        mut ssl: Ssl,
        address: &str,
        server_hostname: &str,
    ) -> Result<Self, String> {
        ssl.set_hostname(server_hostname)
            .map_err(|e| e.to_string())?;

        let ssl_param = ssl.param_mut();
        ssl_param.set_hostflags(X509CheckFlags::NO_PARTIAL_WILDCARDS);
        ssl_param
            .set_host(server_hostname)
            .map_err(|e| e.to_string())?;

        ssl.set_connect_state();

        let tcp_stream = TcpStream::connect(address).map_err(|e| e.to_string())?;
        let mut stream = SslStream::new(ssl, tcp_stream).map_err(|e| e.to_string())?;

        stream.do_handshake().map_err(|e| e.to_string())?;

        Ok(Self { context, stream })
    }
}

#[pymethods]
impl TLSSocket {
    fn send(&mut self, data: &[u8]) -> PyResult<usize> {
        match self.stream.write(data) {
            Ok(amount) => Ok(amount),
            Err(e) => match e.kind() {
                ErrorKind::UnexpectedEof => {
                    Err(RaggedEOF::new_err("Connection closed unexpectedly"))
                }
                ErrorKind::ConnectionAborted => {
                    Err(PyConnectionAbortedError::new_err(e.to_string()))
                }
                ErrorKind::ConnectionReset => Err(PyConnectionResetError::new_err(e.to_string())),
                ErrorKind::BrokenPipe => Err(PyConnectionError::new_err(e.to_string())),
                _ => Err(TLSError::new_err(format!("Write error: {e}"))),
            },
        }
    }

    fn recv(&mut self, bufsize: usize) -> PyResult<Vec<u8>> {
        let mut buf = vec![0u8; bufsize];
        match self.stream.read(&mut buf) {
            Ok(0) => Ok(vec![]),
            Ok(n) => {
                buf.truncate(n);
                Ok(buf)
            }
            Err(e) => match e.kind() {
                ErrorKind::UnexpectedEof => {
                    Err(RaggedEOF::new_err("Connection closed unexpectedly"))
                }
                ErrorKind::ConnectionAborted => {
                    Err(PyConnectionAbortedError::new_err(e.to_string()))
                }
                ErrorKind::ConnectionReset => Err(PyConnectionResetError::new_err(e.to_string())),
                ErrorKind::BrokenPipe => Err(PyConnectionError::new_err(e.to_string())),
                _ => Err(TLSError::new_err(format!("Send error: {e}"))),
            },
        }
    }

    fn getsockname(&self) -> PyResult<String> {
        Ok(self
            .stream
            .get_ref()
            .local_addr()
            .map_err(|e| TLSError::new_err(e.to_string()))?
            .to_string())
    }

    fn getpeercert(&self) -> PyResult<Option<Vec<u8>>> {
        Ok(self.stream.ssl().peer_certificate_der())
    }

    fn getpeername(&self) -> PyResult<String> {
        Ok(self
            .stream
            .get_ref()
            .peer_addr()
            .map_err(|e| TLSError::new_err(e.to_string()))?
            .to_string())
    }

    fn cipher(&self) -> PyResult<Option<u16>> {
        match self.stream.ssl().current_cipher_id() {
            None => Ok(None),
            Some(cipher) => Ok(Some(cipher)),
        }
    }

    fn negotiated_protocol(&self) -> PyResult<Option<Vec<u8>>> {
        Ok(self.stream.ssl().negotiated_protocol())
    }

    #[getter]
    fn negotiated_tls_version(&self) -> PyResult<Option<String>> {
        match self.stream.ssl().version2() {
            None => Ok(None),
            Some(version) => Ok(Some(version.to_string())),
        }
    }

    #[allow(unused_variables)]
    fn listen(&self, backlog: usize) -> PyResult<()> {
        Err(PyNotImplementedError::new_err("Not implemented"))
    }

    fn accept(&self) -> PyResult<(Self, (Option<String>, usize))> {
        Err(PyNotImplementedError::new_err("Not implemented"))
    }

    #[pyo3(signature = (force=false))]
    fn close(&mut self, force: bool) -> PyResult<()> {
        let mut try_shutdown = || {
            self.stream
                .shutdown()
                .map_err(|err| TLSError::new_err(err.to_string()))
        };

        let mut res = try_shutdown()?;

        // waiting until other side send us close msg
        while !force && res != ShutdownResult::Received {
            res = try_shutdown()?;
        }

        Ok(())
    }
}
