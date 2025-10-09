use boring_sys2 as ffi;
use boring2::error::ErrorStack;
use boring2::ssl::SslRef;
use foreign_types::ForeignTypeRef;

use crate::bio::MemBio;
use crate::utils::cvt;

pub trait SslRefExt {
    fn set_connect_state(&self);
    fn set_bio(&self, rbio: &MemBio, wbio: &MemBio);
    fn current_cipher_id(&self) -> Option<u16>;
    fn negotiated_protocol(&self) -> Option<Vec<u8>>;
    fn peer_certificate_der(&self) -> Option<Vec<u8>>;
    fn set_aes_hw_override(&self, enable: bool);
    fn add_application_settings(&mut self, alps: &[u8]) -> Result<(), ErrorStack>;
    fn set_alps_use_new_codepoint(&mut self, use_new: bool);
}

impl SslRefExt for SslRef {
    fn set_connect_state(&self) {
        unsafe { ffi::SSL_set_connect_state(self.as_ptr()) }
    }

    fn set_bio(&self, rbio: &MemBio, wbio: &MemBio) {
        unsafe { ffi::SSL_set_bio(self.as_ptr(), rbio.as_ptr(), wbio.as_ptr()) }
    }

    fn current_cipher_id(&self) -> Option<u16> {
        self.current_cipher()
            .map(|cipher| unsafe { ffi::SSL_CIPHER_get_protocol_id(cipher.as_ptr()) })
    }

    fn negotiated_protocol(&self) -> Option<Vec<u8>> {
        let mut data: *const u8 = std::ptr::null();
        let mut len: u32 = 0;

        unsafe { ffi::SSL_get0_alpn_selected(self.as_ptr(), &mut data, &mut len) };

        if data.is_null() || len == 0 {
            None
        } else {
            Some(unsafe { std::slice::from_raw_parts(data, len as usize).to_vec() })
        }
    }

    fn peer_certificate_der(&self) -> Option<Vec<u8>> {
        self.peer_certificate().map(|cert| cert.to_der().unwrap())
    }

    fn set_aes_hw_override(&self, enable: bool) {
        unsafe { ffi::SSL_set_aes_hw_override(self.as_ptr(), enable as _) }
    }

    fn add_application_settings(&mut self, alps: &[u8]) -> Result<(), ErrorStack> {
        unsafe {
            cvt(ffi::SSL_add_application_settings(
                self.as_ptr(),
                alps.as_ptr(),
                alps.len(),
                std::ptr::null(),
                0,
            ))
            .map(|_| ())
        }
    }

    fn set_alps_use_new_codepoint(&mut self, use_new: bool) {
        unsafe { ffi::SSL_set_alps_use_new_codepoint(self.as_ptr(), use_new as _) }
    }
}
