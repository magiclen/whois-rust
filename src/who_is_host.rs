use validators::prelude::*;
use validators_prelude::Host;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Validator)]
#[validator(host)]
pub struct WhoIsHost {
    pub(crate) host: Host,
    pub(crate) port: Option<u16>,
}

impl WhoIsHost {
    pub(crate) fn to_addr_string(&self, default_port: u16) -> String {
        let port = self.port.unwrap_or(default_port);

        match &self.host {
            Host::IPv4(ip) => format!("{}:{}", ip, port),
            Host::IPv6(ip) => format!("[{}]:{}", ip, port),
            Host::Domain(domain) => format!("{}:{}", domain, port),
        }
    }
}
