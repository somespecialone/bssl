use pyo3::prelude::*;

mod bio;
mod buf;
mod cert_compressors;
mod ctx;
mod enums;
mod err;
mod sock;
mod ssl;
mod utils;

#[pymodule]
fn bssl(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // errors
    m.add_class::<err::TLSError>()?;
    m.add_class::<err::WantWriteError>()?;
    m.add_class::<err::WantReadError>()?;
    m.add_class::<err::RaggedEOF>()?;
    // enums
    m.add_class::<enums::CertificateCompressionAlgorithm>()?;
    m.add_class::<enums::ExtensionType>()?;
    // main classes
    m.add_class::<sock::TLSSocket>()?;
    m.add_class::<buf::TLSBuffer>()?;
    m.add_class::<ctx::ClientContext>()?;
    Ok(())
}
