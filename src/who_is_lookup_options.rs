use std::time::Duration;

use validators::prelude::*;

use crate::{Target, WhoIsError, WhoIsServerValue};

const DEFAULT_FOLLOW: u16 = 2;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);
const DEFAULT_MAX_RESPONSE_SIZE: usize = 4 * 1024 * 1024;

/// The options about how to lookup.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct WhoIsLookupOptions {
    /// The target that you want to lookup.
    pub target:            Target,
    /// The WHOIS server that you want to use. If it is **None**, an appropriate WHOIS server will be chosen from the list of WHOIS servers that the `WhoIs` instance have. The default value is **None**.
    pub server:            Option<WhoIsServerValue>,
    /// Number of times to follow redirects. The default value is 2.
    pub follow:            u16,
    /// The timeout of each connection to a WHOIS server. **None** means no timeout at all. The default value is 60 seconds.
    ///
    /// The timeout is a budget for one connection: it covers resolving the address of the server, connecting to it (even when the server has several addresses to try) and reading the whole response. A lookup which follows referrals spends one budget per connection, so it can take up to `follow + 1` times this value.
    pub timeout:           Option<Duration>,
    /// The maximum number of bytes to accept from a WHOIS server. A bigger response makes the lookup fail instead of being truncated. **None** means no limit at all, which lets a broken or malicious server exhaust the memory. The default value is 4 MiB.
    pub max_response_size: Option<usize>,
}

impl WhoIsLookupOptions {
    /// Create options with the default settings for a target.
    #[inline]
    pub fn from_target(target: Target) -> WhoIsLookupOptions {
        WhoIsLookupOptions {
            target,
            server: None,
            follow: DEFAULT_FOLLOW,
            timeout: Some(DEFAULT_TIMEOUT),
            max_response_size: Some(DEFAULT_MAX_RESPONSE_SIZE),
        }
    }

    /// Parse a domain or an IP into a target and create options with the default settings.
    #[allow(clippy::should_implement_trait)]
    #[inline]
    pub fn from_str<S: AsRef<str>>(s: S) -> Result<WhoIsLookupOptions, WhoIsError> {
        Ok(Self::from_target(Target::parse_str(s)?))
    }

    /// Parse a domain or an IP into a target and create options with the default settings. The string may be reused as the target, avoiding an allocation.
    #[inline]
    pub fn from_string<S: Into<String>>(s: S) -> Result<WhoIsLookupOptions, WhoIsError> {
        Ok(Self::from_target(Target::parse_string(s)?))
    }
}
