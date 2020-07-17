use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::io;

use crate::serde_json;

use crate::validators::HostError;

#[derive(Debug)]
pub enum WhoIsError {
    SerdeJsonError(serde_json::Error),
    IOError(io::Error),
    HostError(HostError),
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

impl Display for WhoIsError {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            WhoIsError::SerdeJsonError(error) => Display::fmt(error, f),
            WhoIsError::IOError(error) => Display::fmt(error, f),
            WhoIsError::HostError(error) => Display::fmt(error, f),
            WhoIsError::MapError(text) => f.write_str(text),
        }
    }
}

impl Error for WhoIsError {}
