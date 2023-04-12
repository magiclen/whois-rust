use serde_json::Value;
use validators::prelude::*;

use crate::{WhoIsError, WhoIsHost};

const DEFAULT_PUNYCODE: bool = true;

/// The model of a WHOIS server.
#[derive(Debug, Clone)]
pub struct WhoIsServerValue {
    pub host:     WhoIsHost,
    pub query:    Option<String>,
    pub punycode: bool,
}

impl WhoIsServerValue {
    pub fn from_value(value: &Value) -> Result<WhoIsServerValue, WhoIsError> {
        match value {
            Value::Object(map) => match map.get("host") {
                Some(Value::String(host)) => {
                    let host = match WhoIsHost::parse_str(host) {
                        Ok(host) => host,
                        Err(_) => {
                            return Err(WhoIsError::MapError(
                                "The server value is an object, but it has not a correct host \
                                 string.",
                            ))
                        },
                    };

                    let query = match map.get("query") {
                        Some(query) => {
                            if let Value::String(query) = query {
                                Some(String::from(query))
                            } else {
                                return Err(WhoIsError::MapError(
                                    "The server value is an object, but it has an incorrect query \
                                     string.",
                                ));
                            }
                        },
                        None => None,
                    };

                    let punycode = match map.get("punycode") {
                        Some(punycode) => {
                            if let Value::Bool(punycode) = punycode {
                                *punycode
                            } else {
                                return Err(WhoIsError::MapError(
                                    "The server value is an object, but it has an incorrect \
                                     punycode boolean value.",
                                ));
                            }
                        },
                        None => DEFAULT_PUNYCODE,
                    };

                    Ok(WhoIsServerValue {
                        host,
                        query,
                        punycode,
                    })
                },
                _ => Err(WhoIsError::MapError(
                    "The server value is an object, but it has not a host string.",
                )),
            },
            Value::String(host) => Self::from_string(host),
            _ => Err(WhoIsError::MapError("The server value is not an object or a host string.")),
        }
    }

    #[inline]
    pub fn from_string<S: AsRef<str>>(string: S) -> Result<WhoIsServerValue, WhoIsError> {
        let host = string.as_ref();

        let host = match WhoIsHost::parse_str(host) {
            Ok(host) => host,
            Err(_) => {
                return Err(WhoIsError::MapError("The server value is not a correct host string."))
            },
        };

        Ok(WhoIsServerValue {
            host,
            query: None,
            punycode: DEFAULT_PUNYCODE,
        })
    }
}
