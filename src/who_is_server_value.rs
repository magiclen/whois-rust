use std::borrow::Cow;

use serde_json::Value;
use validators::prelude::*;

use crate::{WhoIsError, WhoIsHost};

const DEFAULT_PUNYCODE: bool = true;

/// The model of a WHOIS server.
#[derive(Debug, Clone)]
pub struct WhoIsServerValue {
    /// The host of this server.
    pub host:     WhoIsHost,
    /// The query to send, where `$addr` is replaced by the target. **None** means the default query, `"$addr\r\n"`.
    pub query:    Option<String>,
    /// Whether this server wants a domain in its ASCII (Punycode) form. The default value is **true**.
    pub punycode: bool,
}

impl WhoIsServerValue {
    /// Read a server from an entry of a server list. The entry is either a host string, or an object with a `host` string and optional `query` and `punycode` fields.
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
                            ));
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

    /// Read a server from a host string, using the default query and the default `punycode` setting.
    #[inline]
    pub fn from_string<S: AsRef<str>>(string: S) -> Result<WhoIsServerValue, WhoIsError> {
        let host = string.as_ref();

        let host = match WhoIsHost::parse_str(host) {
            Ok(host) => host,
            Err(_) => {
                return Err(WhoIsError::MapError("The server value is not a correct host string."));
            },
        };

        Ok(WhoIsServerValue {
            host,
            query: None,
            punycode: DEFAULT_PUNYCODE,
        })
    }

    /// Return the domain text to send to this server. The input is expected to be already ASCII (Punycode) encoded. When `punycode` is `false`, it is decoded back to Unicode, which some servers (e.g. DENIC for `.de`) require.
    pub(crate) fn encode_domain<'a>(&self, domain: &'a str) -> Cow<'a, str> {
        if self.punycode {
            Cow::Borrowed(domain)
        } else {
            Cow::Owned(validators::idna::domain_to_unicode(domain).0)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_domain_honors_punycode_flag() {
        let mut server = WhoIsServerValue::from_string("whois.denic.de").unwrap();

        // The default keeps the ASCII (Punycode) form.
        assert_eq!("xn--mller-kva.de", server.encode_domain("xn--mller-kva.de").as_ref());

        // A server with `punycode: false` receives the Unicode form.
        server.punycode = false;
        assert_eq!("müller.de", server.encode_domain("xn--mller-kva.de").as_ref());
    }
}
