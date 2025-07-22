use pyo3::prelude::*;

mod bio;
mod buf;
mod ctx;
mod err;
mod ext;
mod sock;

#[pymodule]
fn bssl_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // errors
    m.add_class::<err::TLSError>()?;
    m.add_class::<err::WantWriteError>()?;
    m.add_class::<err::WantReadError>()?;
    m.add_class::<err::RaggedEOF>()?;
    // main
    m.add_class::<sock::TLSSocket>()?;
    m.add_class::<buf::TLSBuffer>()?;
    m.add_class::<ctx::ClientContext>()?;
    Ok(())
}
