use pyo3::prelude::*;

mod bio;
mod buf;
mod ctx;
mod ext;
mod socket;

#[pymodule]
fn bssl_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<socket::TLSSocket>()?;
    m.add_class::<buf::TLSBuffer>()?;
    m.add_class::<ctx::ClientContext>()?;
    Ok(())
}
