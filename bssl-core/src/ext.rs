use boring::ssl::SslRef;
use boring_sys as ffi;
use foreign_types::ForeignTypeRef;

use crate::bio::MemBio;

pub trait SslRefExt {
    fn set_connect_state(&self);
    fn set_bio(&self, rbio: &MemBio, wbio: &MemBio);
    fn current_cipher_id(&self) -> Option<u16>;
    fn negotiated_protocol(&self) -> Option<Vec<u8>>;
    fn peer_certificate_der(&self) -> Option<Vec<u8>>;
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

        unsafe { ffi::SSL_get0_next_proto_negotiated(self.as_ptr(), &mut data, &mut len) };

        if data.is_null() || len == 0 {
            None
        } else {
            Some(unsafe { std::slice::from_raw_parts(data, len as usize).to_vec() })
        }
    }

    fn peer_certificate_der(&self) -> Option<Vec<u8>> {
        self.peer_certificate().map(|cert| cert.to_der().unwrap())
    }
}
