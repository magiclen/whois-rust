use std::time::Duration;

use crate::validators::prelude::*;

use crate::{Target, WhoIsError, WhoIsServerValue};

const DEFAULT_FOLLOW: u16 = 2;
const DEFAULT_TIMEOUT: u64 = 60000;

/// The options about how to lookup.
#[derive(Debug, Clone)]
pub struct WhoIsLookupOptions {
    /// The target that you want to lookup.
    pub target: Target,
    /// The WHOIS server that you want to use. If it is **None**, an appropriate WHOIS server will be chosen from the list of WHOIS servers that the `WhoIs` instance have. The default value is **None**.
    pub server: Option<WhoIsServerValue>,
    /// Number of times to follow redirects. The default value is 2.
    pub follow: u16,
    /// Socket timeout in milliseconds. The default value is 60000.
    pub timeout: Option<Duration>,
}

impl WhoIsLookupOptions {
    #[inline]
    pub fn from_target(target: Target) -> WhoIsLookupOptions {
        WhoIsLookupOptions {
            target,
            server: None,
            follow: DEFAULT_FOLLOW,
            timeout: Some(Duration::from_millis(DEFAULT_TIMEOUT)),
        }
    }

    #[allow(clippy::should_implement_trait)]
    #[inline]
    pub fn from_str<S: AsRef<str>>(s: S) -> Result<WhoIsLookupOptions, WhoIsError> {
        Ok(Self::from_target(Target::parse_str(s)?))
    }

    #[inline]
    pub fn from_string<S: Into<String>>(s: S) -> Result<WhoIsLookupOptions, WhoIsError> {
        Ok(Self::from_target(Target::parse_string(s)?))
    }
}
