use pyo3::prelude::*;

mod bio;
mod buf;
mod ctx;
mod err;
mod ext;
mod sock;

#[pymodule]
fn bssl_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<sock::TLSSocket>()?;
    m.add_class::<buf::TLSBuffer>()?;
    m.add_class::<ctx::ClientContext>()?;
    Ok(())
}
