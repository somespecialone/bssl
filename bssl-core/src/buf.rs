use boring_sys2 as ffi;
use boring2::error::ErrorStack;
use boring2::ssl::{ErrorCode, Ssl};
use foreign_types::ForeignType;
use pyo3::IntoPyObjectExt;
use pyo3::buffer::PyBuffer;
use pyo3::exceptions::{PyOSError, PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use std::ffi::c_int;
use std::io::{Read, Write};
use std::mem::ManuallyDrop;

use crate::bio::MemBio;
use crate::ctx::ClientContext;
use crate::err::*;
use crate::ssl::SslRefExt;

// https://peps.python.org/pep-0748/#buffer
#[pyclass]
pub struct TLSBuffer {
    #[pyo3(get)]
    context: Py<ClientContext>,

    ssl: ManuallyDrop<Ssl>,
    rbio: MemBio, // incoming
    wbio: MemBio, // outgoing
}

impl Drop for TLSBuffer {
    fn drop(&mut self) {
        unsafe { ManuallyDrop::drop(&mut self.ssl) }
    }
}

impl TLSBuffer {
    pub fn new(
        context: Py<ClientContext>,
        mut ssl: Ssl,
        server_hostname: &str,
    ) -> Result<Self, ErrorStack> {
        ssl.set_hostname(server_hostname)?;
        ssl.set_connect_state();

        let rbio = MemBio::new()?;
        let wbio = MemBio::new()?;

        ssl.set_bio(&rbio, &wbio);

        Ok(Self {
            context,
            ssl: ManuallyDrop::new(ssl),
            rbio,
            wbio,
        })
    }

    fn handle_error(&self, ret: c_int) -> PyErr {
        let code = self.ssl.error_code(ret);

        match code {
            ErrorCode::WANT_READ => WantReadError::new_err("Need more data from peer"),
            ErrorCode::WANT_WRITE => WantWriteError::new_err("Need to write data to peer"),
            ErrorCode::ZERO_RETURN => RaggedEOF::new_err("Graceful shutdown from peer"),
            ErrorCode::SSL => {
                let err_stack = ErrorStack::get();
                TLSError::new_err(format!("SSl error: {err_stack}"))
            }
            ErrorCode::SYSCALL => {
                let err_stack = ErrorStack::get();
                if err_stack.errors().is_empty() {
                    RaggedEOF::new_err("Unexpected EOF")
                } else {
                    PyOSError::new_err(format!("System error: {err_stack}"))
                }
            }
            err_code => TLSError::new_err(("Unknown SSL error: {}", err_code.as_raw())),
        }
    }
}

#[pymethods]
impl TLSBuffer {
    fn do_handshake(&mut self) -> PyResult<()> {
        let ret = unsafe { ffi::SSL_do_handshake(self.ssl.as_ptr()) };

        if ret > 0 {
            Ok(())
        } else {
            Err(self.handle_error(ret))
        }
    }

    #[pyo3(signature = (amt, buffer=None))]
    fn read(
        &mut self,
        amt: usize,
        buffer: Option<PyBuffer<u8>>,
        py: Python,
    ) -> PyResult<Py<PyAny>> {
        let len = usize::min(c_int::MAX as usize, amt) as c_int;
        let ret;

        match buffer {
            None => {
                let mut buf = vec![0u8; amt];
                let ptr = buf.as_mut_ptr();
                ret = unsafe { ffi::SSL_read(self.ssl.as_ptr(), ptr.cast(), len) };
                if ret > 0 {
                    buf.truncate(ret as usize);
                    return buf.into_py_any(py);
                } else if ret == 0 {
                    return Vec::<u8>::new().into_py_any(py);
                }
            }
            Some(buffer) => {
                if buffer.readonly() {
                    return Err(PyValueError::new_err("Buffer is read-only"));
                }

                let buf_slice = buffer.as_mut_slice(py).unwrap();
                let ptr = buf_slice.as_ptr() as *mut u8;
                ret = unsafe { ffi::SSL_read(self.ssl.as_ptr(), ptr.cast(), len) };
                if ret >= 0 {
                    return ret.into_py_any(py);
                }
            }
        }

        Err(self.handle_error(ret))
    }

    fn write(&mut self, buf: &[u8]) -> PyResult<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        let len = usize::min(c_int::MAX as usize, buf.len()) as c_int;
        let ret = unsafe { ffi::SSL_write(self.ssl.as_ptr(), buf.as_ptr().cast(), len) };

        if ret > 0 {
            Ok(ret as usize)
        } else {
            Err(self.handle_error(ret))
        }
    }

    fn process_incoming(&mut self, data_from_network: &[u8]) -> PyResult<()> {
        #[allow(clippy::unused_io_amount)]
        match self.rbio.write(data_from_network) {
            Ok(_) => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    #[pyo3(signature = (amount_bytes_for_network=-1))]
    fn process_outgoing(&mut self, amount_bytes_for_network: isize) -> PyResult<Vec<u8>> {
        let avail = self.outgoing_bytes_buffered();
        let len = if (amount_bytes_for_network < 0) || ((avail as isize) < amount_bytes_for_network)
        {
            avail
        } else {
            amount_bytes_for_network as usize
        };

        let mut buf = vec![0u8; len];
        match self.wbio.read(&mut buf) {
            Ok(0) => Ok(Vec::new()), // nothing to read
            Ok(_) => Ok(buf),        // there should never be any short read so no truncation
            Err(e) => Err(PyRuntimeError::new_err(format!("BIO read failed: {e}"))),
        }
    }

    fn incoming_bytes_buffered(&self) -> usize {
        self.rbio.pending_bytes()
    }

    fn outgoing_bytes_buffered(&self) -> usize {
        self.wbio.pending_bytes()
    }

    fn shutdown(&mut self) -> PyResult<()> {
        match unsafe { ffi::SSL_shutdown(self.ssl.as_ptr()) } {
            0 | 1 => Ok(()), // sent and received
            ret => Err(self.handle_error(ret)),
        }
    }

    fn getpeercert(&self) -> PyResult<Option<Vec<u8>>> {
        Ok(self.ssl.peer_certificate_der())
    }

    fn cipher(&self) -> PyResult<Option<u16>> {
        match self.ssl.current_cipher_id() {
            None => Ok(None),
            Some(cipher) => Ok(Some(cipher)),
        }
    }

    fn negotiated_protocol(&self) -> PyResult<Option<Vec<u8>>> {
        Ok(self.ssl.negotiated_protocol())
    }

    #[getter]
    fn negotiated_tls_version(&self) -> PyResult<Option<String>> {
        match self.ssl.version2() {
            None => Ok(None),
            Some(version) => Ok(Some(version.to_string())),
        }
    }
}
