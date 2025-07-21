use pyo3::exceptions::PyException;
use pyo3::prelude::*;

#[pyclass(extends=PyException, subclass)]
pub struct TLSError;

#[pyclass(extends=TLSError)]
pub struct WantWriteError;

#[pyclass(extends=TLSError)]
pub struct WantReadError;

#[pyclass(extends=TLSError)]
pub struct RaggedEOF;

// ConfigurationError at python level
