use crate::validators::models::Host;
use crate::validators::prelude::*;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Validator)]
#[validator(host(port(NotAllow)))]
pub struct Target(pub(crate) Host);
