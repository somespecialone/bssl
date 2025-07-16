use boring::ssl::Ssl;
use boring_sys as ffi;
use foreign_types::ForeignType;

use crate::bio::MemBio;

pub trait SslExt {
    fn set_connect_state(&self);

    fn set_bio(&self, rbio: &MemBio, wbio: &MemBio);
}

impl SslExt for Ssl {
    fn set_connect_state(&self) {
        unsafe { ffi::SSL_set_connect_state(self.as_ptr()) }
    }

    fn set_bio(&self, rbio: &MemBio, wbio: &MemBio) {
        unsafe { ffi::SSL_set_bio(self.as_ptr(), rbio.as_ptr(), wbio.as_ptr()) }
    }
}
