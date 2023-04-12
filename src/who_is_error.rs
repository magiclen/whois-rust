use std::{
    error::Error,
    fmt::{self, Display, Formatter},
    io,
};

use validators::HostError;

#[cfg(feature = "tokio")]
use crate::tokio;

#[derive(Debug)]
pub enum WhoIsError {
    SerdeJsonError(serde_json::Error),
    IOError(io::Error),
    HostError(HostError),
    #[cfg(feature = "tokio")]
    Elapsed(tokio::time::error::Elapsed),
    /// This kind of errors is recommended to be panic!
    MapError(&'static str),
}

impl From<serde_json::Error> for WhoIsError {
    #[inline]
    fn from(error: serde_json::Error) -> Self {
        WhoIsError::SerdeJsonError(error)
    }
}

impl From<io::Error> for WhoIsError {
    #[inline]
    fn from(error: io::Error) -> Self {
        WhoIsError::IOError(error)
    }
}

impl From<HostError> for WhoIsError {
    #[inline]
    fn from(error: HostError) -> Self {
        WhoIsError::HostError(error)
    }
}

#[cfg(feature = "tokio")]
impl From<tokio::time::error::Elapsed> for WhoIsError {
    #[inline]
    fn from(error: tokio::time::error::Elapsed) -> Self {
        WhoIsError::Elapsed(error)
    }
}

impl Display for WhoIsError {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            WhoIsError::SerdeJsonError(error) => Display::fmt(error, f),
            WhoIsError::IOError(error) => Display::fmt(error, f),
            WhoIsError::HostError(error) => Display::fmt(error, f),
            #[cfg(feature = "tokio")]
            WhoIsError::Elapsed(error) => Display::fmt(error, f),
            WhoIsError::MapError(text) => f.write_str(text),
        }
    }
}

impl Error for WhoIsError {}
