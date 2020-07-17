use crate::validators::models::Host;
use crate::validators::prelude::*;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Validator)]
#[validator(host)]
pub struct WhoIsHost {
    pub(crate) host: Host,
    pub(crate) port: Option<u16>,
}
