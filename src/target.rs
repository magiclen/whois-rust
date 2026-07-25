use validators::prelude::*;
use validators_prelude::Host;

use crate::WhoIsError;

/// The target of a lookup: a domain or an IP address, without a port.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Validator)]
#[validator(host(port(Disallow)))]
pub struct Target(pub(crate) Host);

impl Target {
    /// Create a `Target` from a `Host`. A `Host` can be built by hand, so a domain is validated again, which also turns a Unicode domain into its ASCII (Punycode) form.
    #[inline]
    pub fn from_host(host: Host) -> Result<Target, WhoIsError> {
        match host {
            Host::Domain(domain) => Ok(Target::parse_string(domain)?),
            host => Ok(Target(host)),
        }
    }

    /// Get the host of this target.
    #[inline]
    pub const fn host(&self) -> &Host {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_host_rejects_a_domain_which_is_not_one_line() {
        // A second line would be a second request, which RFC 3912 does not allow.
        assert!(
            Target::from_host(Host::Domain(String::from("magiclen.org\r\nexample.com"))).is_err()
        );

        assert!(Target::from_host(Host::Domain(String::from("magiclen.org"))).is_ok());
    }
}
