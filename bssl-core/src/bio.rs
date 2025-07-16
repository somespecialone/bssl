use std::ffi::c_int;
use std::io::{Error as IoError, Read, Result as IoResult, Write};
use std::{ptr, slice};

use boring::error::ErrorStack;
use boring_sys as ffi;

// partial copy of boring::bio as it private
fn cvt_p<T>(r: *mut T) -> Result<*mut T, ErrorStack> {
    if r.is_null() {
        Err(ErrorStack::get())
    } else {
        Ok(r)
    }
}

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

        // TODO get specific error from ret

        if ret > 0 {
            Ok(ret as usize)
        } else {
            Err(IoError::last_os_error())
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

        // TODO get specific error from ret

        if ret > 0 {
            Ok(ret as usize)
        } else {
            Err(IoError::last_os_error())
        }
    }

    fn flush(&mut self) -> IoResult<()> {
        Ok(())
    }
}

impl MemBio {
    pub fn new() -> Result<MemBio, ErrorStack> {
        ffi::init();

        let bio = unsafe { cvt_p(ffi::BIO_new(ffi::BIO_s_mem()))? };

        // corresponding to _ssl.c
        unsafe { ffi::BIO_up_ref(bio) };

        Ok(MemBio(bio))
    }

    pub fn pending_bytes(&self) -> usize {
        unsafe { ffi::BIO_ctrl_pending(self.0) as usize }
    }

    pub fn as_ptr(&self) -> *mut ffi::BIO {
        self.0
    }

    pub fn get_buf(&self) -> &[u8] {
        unsafe {
            let mut ptr = ptr::null_mut();
            let len = ffi::BIO_get_mem_data(self.0, &mut ptr);
            slice::from_raw_parts(ptr as *const _ as *const _, len as usize)
        }
    }
}
