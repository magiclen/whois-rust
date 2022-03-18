use validators::prelude::*;
use validators_prelude::Host;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Validator)]
#[validator(host(port(NotAllow)))]
pub struct Target(pub(crate) Host);

impl Target {
    #[allow(clippy::missing_safety_doc)]
    #[inline]
    pub const unsafe fn from_host_unchecked(host: Host) -> Target {
        Target(host)
    }
}
