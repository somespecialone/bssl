use boring::ssl::Ssl;
use boring_sys as ffi;
use foreign_types::ForeignType;
use pyo3::buffer::PyBuffer;
use pyo3::exceptions::{PyNotImplementedError, PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use std::ffi::c_int;
use std::io::{Read, Write};

use crate::bio::MemBio;
use crate::ext::SslExt;

#[pyclass]
pub struct TLSBuffer {
    ssl: Ssl,
    rbio: MemBio,
    wbio: MemBio,
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

    fn read(&mut self, amt: usize) -> PyResult<Vec<u8>> {
        let mut buf = vec![0u8; amt];

        let len = usize::min(c_int::MAX as usize, buf.len()) as c_int;
        let ret = unsafe { ffi::SSL_read(self.ssl.as_ptr(), buf.as_mut_ptr().cast(), len) };
        // TODO appropriate errors

        if ret > 0 {
            Ok(buf)
        } else {
            Err(PyRuntimeError::new_err("SSL_read failed"))
        }
    }

    fn read_to_buf(&mut self, buffer: PyBuffer<u8>, py: Python) -> PyResult<usize> {
        if buffer.readonly() {
            return Err(PyValueError::new_err("Buffer is read-only"));
        }

        let buf_slice = unsafe { buffer.as_mut_slice(py).unwrap() };
        let ptr = buf_slice.as_ptr() as *mut u8;

        let len = usize::min(c_int::MAX as usize, buf_slice.len()) as c_int;
        let ret = unsafe { ffi::SSL_read(self.ssl.as_ptr(), ptr.cast(), len) };
        // TODO appropriate errors

        if ret > 0 {
            Ok(ret as usize)
        } else {
            Err(PyRuntimeError::new_err("SSL_read failed"))
        }
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
        self.wbio.read_exact(&mut buf).unwrap();
        Ok(buf)
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
            0 => Ok(()),
            1 => Ok(()),
            _ => Err(PyRuntimeError::new_err("SSL_shutdown failed")),
        }
    }

    fn getpeercert(&self) -> PyResult<Vec<u8>> {
        Err(PyNotImplementedError::new_err("Not implemented"))
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
}

pub fn new(mut ssl: Ssl, server_hostname: &str) -> TLSBuffer {
    ssl.set_hostname(server_hostname).unwrap();
    ssl.set_connect_state();

    let rbio = MemBio::new().unwrap();
    let wbio = MemBio::new().unwrap();

    ssl.set_bio(&rbio, &wbio);

    TLSBuffer { ssl, rbio, wbio }
}
