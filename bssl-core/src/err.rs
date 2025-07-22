use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyTuple};

#[pyclass(extends=PyException, subclass)]
pub struct TLSError;

#[pymethods]
impl TLSError {
    #[new]
    #[pyo3(signature = (*args, **kwargs))]
    #[allow(unused_variables)]
    fn new(args: &Bound<'_, PyTuple>, kwargs: Option<&Bound<'_, PyDict>>) -> Self {
        Self {}
    }
}

#[pyclass(extends=TLSError)]
pub struct WantWriteError;

#[pymethods]
impl WantWriteError {
    #[new]
    #[pyo3(signature = (*args, **kwargs))]
    #[allow(unused_variables)]
    fn new(args: &Bound<'_, PyTuple>, kwargs: Option<&Bound<'_, PyDict>>) -> (Self, TLSError) {
        (Self {}, TLSError {})
    }
}

#[pyclass(extends=TLSError)]
pub struct WantReadError;

#[pymethods]
impl WantReadError {
    #[new]
    #[pyo3(signature = (*args, **kwargs))]
    #[allow(unused_variables)]
    fn new(args: &Bound<'_, PyTuple>, kwargs: Option<&Bound<'_, PyDict>>) -> (Self, TLSError) {
        (Self {}, TLSError {})
    }
}

#[pyclass(extends=TLSError)]
pub struct RaggedEOF;

#[pymethods]
impl RaggedEOF {
    #[new]
    #[pyo3(signature = (*args, **kwargs))]
    #[allow(unused_variables)]
    fn new(args: &Bound<'_, PyTuple>, kwargs: Option<&Bound<'_, PyDict>>) -> (Self, TLSError) {
        (Self {}, TLSError {})
    }
}

// ConfigurationError at python level
