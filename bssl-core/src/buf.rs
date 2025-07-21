use boring::error::ErrorStack;
use boring::ssl::{ErrorCode, Ssl, SslRef};
use boring_sys as ffi;
use foreign_types::ForeignType;
use foreign_types::ForeignTypeRef;
use pyo3::IntoPyObjectExt;
use pyo3::buffer::PyBuffer;
use pyo3::exceptions::{PyNotImplementedError, PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use std::ffi::c_int;
use std::io::{Read, Write};
use std::mem::ManuallyDrop;

use crate::bio::MemBio;
use crate::ctx::ClientContext;
use crate::err;
use crate::ext::SslRefExt;

// fn make_error(ssl: &Ssl, ret: c_int) {
//     let code = ssl.error_code(ret);
//
//     let cause = match code {
//         ErrorCode::SSL => Some(InnerError::Ssl(ErrorStack::get())),
//         ErrorCode::SYSCALL => {
//             let errs = ErrorStack::get();
//             if errs.errors().is_empty() {
//                 self.get_bio_error().map(InnerError::Io)
//             } else {
//                 Some(InnerError::Ssl(errs))
//             }
//         }
//         ErrorCode::ZERO_RETURN => None,
//         ErrorCode::WANT_READ | ErrorCode::WANT_WRITE => self.get_bio_error().map(InnerError::Io),
//         _ => None,
//     };
// }

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
        unsafe {
            ManuallyDrop::drop(&mut self.ssl);
        }
    }
}

#[pymethods]
impl TLSBuffer {
    fn do_handshake(&mut self) -> PyResult<()> {
        let ret = unsafe { ffi::SSL_do_handshake(self.ssl.as_ptr()) };
        // TODO appropriate errors

        if ret > 0 {
            Ok(())
        } else {
            Err(PyRuntimeError::new_err("SSL_do_handshake failed"))
        }
    }

    #[pyo3(signature = (amt, buffer=None))]
    fn read(&mut self, amt: usize, buffer: Option<PyBuffer<u8>>, py: Python) -> PyResult<PyObject> {
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
                }
            }
            Some(buffer) => {
                if buffer.readonly() {
                    return Err(PyValueError::new_err("Buffer is read-only"));
                }

                let buf_slice = buffer.as_mut_slice(py).unwrap();
                let ptr = buf_slice.as_ptr() as *mut u8;
                ret = unsafe { ffi::SSL_read(self.ssl.as_ptr(), ptr.cast(), len) };
                if ret > 0 {
                    return ret.into_py_any(py);
                }
            }
        }

        // TODO appropriate errors
        Err(PyRuntimeError::new_err("SSL_read failed"))
    }

    fn write(&mut self, buf: &[u8]) -> PyResult<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        let len = usize::min(c_int::MAX as usize, buf.len()) as c_int;
        let ret = unsafe { ffi::SSL_write(self.ssl.as_ptr(), buf.as_ptr().cast(), len) };
        // TODO appropriate errors

        if ret > 0 {
            Ok(ret as usize)
        } else {
            Err(PyRuntimeError::new_err("SSL_write failed"))
        }
    }

    fn process_incoming(&mut self, data_from_network: &[u8]) -> PyResult<()> {
        let _ = self.rbio.write(data_from_network).unwrap();
        Ok(())
    }

    fn process_outgoing(&mut self, amt: usize) -> PyResult<Vec<u8>> {
        let mut buf = vec![0u8; amt];
        match self.wbio.read(&mut buf) {
            Ok(n) if n > 0 => {
                buf.truncate(n);
                Ok(buf)
            }
            Ok(_) => Ok(Vec::new()), // nothing to read
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
        // TODO errors also
        match unsafe { ffi::SSL_shutdown(self.ssl.as_ptr()) } {
            0 | 1 => Ok(()),
            _ => Err(PyRuntimeError::new_err("SSL_shutdown failed")),
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

pub fn new(context: Py<ClientContext>, mut ssl: Ssl, server_hostname: &str) -> TLSBuffer {
    ssl.set_hostname(server_hostname).unwrap();
    ssl.set_connect_state();

    let rbio = MemBio::new().unwrap();
    let wbio = MemBio::new().unwrap();

    ssl.set_bio(&rbio, &wbio);

    TLSBuffer {
        context,
        ssl: ManuallyDrop::new(ssl),
        rbio,
        wbio,
    }
}
