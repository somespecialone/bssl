use std::ffi::c_int;
use std::io::{Read, Result as IoResult, Write};

use boring_sys2 as ffi;
use boring2::error::ErrorStack;

use crate::utils::cvt_p;

pub struct MemBio(*mut ffi::BIO);

impl Drop for MemBio {
    fn drop(&mut self) {
        unsafe { ffi::BIO_free(self.0) };
    }
}

unsafe impl Send for MemBio {}
unsafe impl Sync for MemBio {}

impl Read for MemBio {
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        let len = usize::min(c_int::MAX as usize, buf.len()) as c_int;
        let ret = unsafe { ffi::BIO_read(self.0, buf.as_mut_ptr().cast(), len) };

        if ret >= 0 {
            Ok(ret as usize)
        } else {
            let errors = ErrorStack::get();
            if errors.errors().is_empty() {
                Ok(0)
            } else {
                Err(errors.into())
            }
        }
    }
}

impl Write for MemBio {
    fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        let len = usize::min(c_int::MAX as usize, buf.len()) as c_int;
        let ret = unsafe { ffi::BIO_write(self.0, buf.as_ptr().cast(), len) };

        if ret >= 0 {
            Ok(ret as usize)
        } else {
            Err(ErrorStack::get().into())
        }
    }

    // Do we need write_all ??

    fn flush(&mut self) -> IoResult<()> {
        let ret = unsafe { ffi::BIO_flush(self.0) };
        if ret == 1 {
            Ok(())
        } else {
            Err(ErrorStack::get().into())
        }
    }
}

impl MemBio {
    pub fn new() -> Result<MemBio, ErrorStack> {
        ffi::init();

        let method = unsafe { ffi::BIO_s_mem() };
        let bio = unsafe { cvt_p(ffi::BIO_new(method))? };

        // corresponding to _ssl.c
        unsafe {
            ffi::BIO_set_nbio(bio, 1);
            ffi::BIO_up_ref(bio);
        };

        Ok(MemBio(bio))
    }

    pub fn pending_bytes(&self) -> usize {
        unsafe { ffi::BIO_ctrl_pending(self.0) as usize }
    }

    pub fn as_ptr(&self) -> *mut ffi::BIO {
        self.0
    }
}
