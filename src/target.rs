use crate::validators::models::Host;
use crate::validators::prelude::*;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Validator)]
#[validator(host(port(NotAllow)))]
pub struct Target(pub(crate) Host);

impl Target {
    #[inline]
    pub const unsafe fn from_host_unchecked(host: Host) -> Target {
        Target(host)
    }
}
