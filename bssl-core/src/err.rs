use boring2::error::ErrorStack;
use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyTuple};

pub trait ErrToPyErr<T>
where
    T: pyo3::PyTypeInfo,
{
    fn new_err<A>(arg: A) -> PyErr
    where
        A: pyo3::PyErrArguments + std::marker::Send + std::marker::Sync + 'static,
    {
        PyErr::new::<T, A>(arg)
    }
}

#[pyclass(extends=PyException, subclass)]
pub struct TLSError;

impl TLSError {
    pub fn from_error_stack(error_stack: ErrorStack) -> PyErr {
        Self::new_err(error_stack.to_string())
    }
}

impl ErrToPyErr<TLSError> for TLSError {}

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

impl ErrToPyErr<WantWriteError> for WantWriteError {}

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

impl ErrToPyErr<WantReadError> for WantReadError {}

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

impl ErrToPyErr<RaggedEOF> for RaggedEOF {}

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
