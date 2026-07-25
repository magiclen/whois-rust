use validators::prelude::*;
use validators_prelude::Host;

/// The host of a WHOIS server, with an optional port.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Validator)]
#[validator(host)]
pub struct WhoIsHost {
    pub(crate) host: Host,
    pub(crate) port: Option<u16>,
}

impl WhoIsHost {
    /// Get the host part.
    #[inline]
    pub const fn host(&self) -> &Host {
        &self.host
    }

    /// Get the port part. `None` means the default WHOIS port (43) is used.
    #[inline]
    pub const fn port(&self) -> Option<u16> {
        self.port
    }

    pub(crate) fn to_addr_string(&self, default_port: u16) -> String {
        let port = self.port.unwrap_or(default_port);

        match &self.host {
            Host::IPv4(ip) => format!("{}:{}", ip, port),
            Host::IPv6(ip) => format!("[{}]:{}", ip, port),
            Host::Domain(domain) => format!("{}:{}", domain, port),
        }
    }
}
