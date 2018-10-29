pub extern crate serde_json;
pub extern crate validators;
extern crate regex;

#[macro_use]
extern crate lazy_static;

use std::path::Path;
use std::fs::File;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use serde_json::{Map, Value};
use validators::domain::{DomainError, DomainUnlocalhostableWithoutPort};
use validators::ipv4::{IPv4Error, IPv4LocalableWithoutPort};
use validators::host::{Host, HostLocalable};

use regex::Regex;

lazy_static! {
    static ref REF_SERVER_RE: Regex = {
        Regex::new(r"(ReferralServer|Registrar Whois|Whois Server|WHOIS Server|Registrar WHOIS Server):[^\S\n]*(r?whois://)?(.*)").unwrap()
    };
}

#[derive(Debug)]
pub enum WhoIsError {
    SerdeJsonError(serde_json::Error),
    IOError(io::Error),
    DomainError(DomainError),
    IPv4Error(IPv4Error),
    MapError(&'static str),
}

#[derive(Debug)]
pub enum Target {
    Domain(DomainUnlocalhostableWithoutPort),
    IPv4(IPv4LocalableWithoutPort),
}

#[derive(Debug)]
pub struct WhoIsLookupOptions {
    pub target: Target,
    pub server: Option<WhoIsServerValue>,
    pub follow: u16,
    pub timeout: Option<Duration>,
}

#[derive(Debug)]
pub struct WhoIsServerValue {
    host: HostLocalable,
    query: Option<String>,
}

impl WhoIsServerValue {
    fn from_value(value: &Value) -> Result<WhoIsServerValue, WhoIsError> {
        if let Some(obj) = value.as_object() {
            match obj.get("host") {
                Some(host) => {
                    if let Some(host) = host.as_str() {
                        let host = match HostLocalable::from_str(host) {
                            Ok(host) => host,
                            Err(_) => return Err(WhoIsError::MapError("The server value is an object, but it has not a correct host string."))
                        };
                        let query = match obj.get("query") {
                            Some(query) => {
                                if let Some(query) = query.as_str() {
                                    Some(query.to_string())
                                } else {
                                    return Err(WhoIsError::MapError("The server value is an object, but it has a incorrect query string."));
                                }
                            }
                            None => None
                        };
                        Ok(WhoIsServerValue {
                            host,
                            query,
                        })
                    } else {
                        Err(WhoIsError::MapError("The server value is an object, but it has not a host string."))
                    }
                }
                None => {
                    Err(WhoIsError::MapError("The server value is an object, but it has not a host string."))
                }
            }
        } else if let Some(host) = value.as_str() {
            Self::from_string(host)
        } else {
            Err(WhoIsError::MapError("The server value is not an object or a host string."))
        }
    }

    fn from_string<S: AsRef<str>>(string: S) -> Result<WhoIsServerValue, WhoIsError> {
        let host = string.as_ref();
        let host = match HostLocalable::from_str(host) {
            Ok(host) => host,
            Err(_) => return Err(WhoIsError::MapError("The server value is not a correct host string."))
        };
        Ok(WhoIsServerValue {
            host,
            query: None,
        })
    }
}

const DEFAULT_FOLLOW: u16 = 2;
const DEFAULT_TIMEOUT: u64 = 60000;
const DEFAULT_WHOIS_HOST_PORT: u64 = 43;
const DEFAULT_WHOIS_HOST_QUERY: &str = "$addr\r\n";

impl WhoIsLookupOptions {
    pub fn from_target(target: Target) -> WhoIsLookupOptions {
        WhoIsLookupOptions {
            target,
            server: None,
            follow: DEFAULT_FOLLOW,
            timeout: Some(Duration::from_millis(DEFAULT_TIMEOUT)),
        }
    }

    pub fn from_domain<S: AsRef<str>>(domain: S) -> Result<WhoIsLookupOptions, WhoIsError> {
        let domain = domain.as_ref();

        let domain = DomainUnlocalhostableWithoutPort::from_str(domain).map_err(|err| WhoIsError::DomainError(err))?;
        let server = Target::Domain(domain);

        Ok(Self::from_target(server))
    }

    pub fn from_ipv4<S: AsRef<str>>(ipv4: S) -> Result<WhoIsLookupOptions, WhoIsError> {
        let ipv4 = ipv4.as_ref();

        let ipv4 = IPv4LocalableWithoutPort::from_str(ipv4).map_err(|err| WhoIsError::IPv4Error(err))?;
        let server = Target::IPv4(ipv4);

        Ok(Self::from_target(server))
    }

    pub fn from_string<S: AsRef<str>>(string: S) -> Result<WhoIsLookupOptions, WhoIsError> {
        match Self::from_ipv4(&string) {
            Ok(opt) => Ok(opt),
            Err(_) => Self::from_domain(&string)
        }
    }
}

pub struct WhoIs {
    map: Map<String, Value>
}

impl WhoIs {
    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<WhoIs, WhoIsError> {
        let path = path.as_ref();

        let file = File::open(path).map_err(|err| WhoIsError::IOError(err))?;

        let map: Map<String, Value> = serde_json::from_reader(file).map_err(|err| WhoIsError::SerdeJsonError(err))?;

        Ok(WhoIs { map })
    }

    pub fn from_string<S: AsRef<str>>(string: S) -> Result<WhoIs, WhoIsError> {
        let string = string.as_ref();

        let map: Map<String, Value> = serde_json::from_str(string).map_err(|err| WhoIsError::SerdeJsonError(err))?;

        Ok(WhoIs { map })
    }

    fn lookup_inner(server: WhoIsServerValue, text: &str, timeout: Option<Duration>, follow: u16) -> Result<String, WhoIsError> {
        let addr;

        let mut client = match &server.host.as_host() {
            Host::Domain(domain) => {
                if let Some(_) = domain.get_port() {
                    addr = domain.get_full_domain().to_string();
                    TcpStream::connect(&addr).map_err(|err| WhoIsError::IOError(err))?
                } else {
                    addr = format!("{}:{}", domain.get_full_domain(), DEFAULT_WHOIS_HOST_PORT);
                    TcpStream::connect(&addr).map_err(|err| WhoIsError::IOError(err))?
                }
            }
            Host::IPv4(ipv4) => {
                if let Some(_) = ipv4.get_port() {
                    addr = ipv4.get_full_ipv4().to_string();
                    TcpStream::connect(&addr).map_err(|err| WhoIsError::IOError(err))?
                } else {
                    addr = format!("{}:{}", ipv4.get_full_ipv4(), DEFAULT_WHOIS_HOST_PORT);
                    TcpStream::connect(&addr).map_err(|err| WhoIsError::IOError(err))?
                }
            }
            Host::IPv6(ipv6) => {
                if let Some(_) = ipv6.get_port() {
                    addr = ipv6.get_full_ipv6().to_string();
                    TcpStream::connect(&addr).map_err(|err| WhoIsError::IOError(err))?
                } else {
                    addr = format!("[{}]:{}", ipv6.get_full_ipv6(), DEFAULT_WHOIS_HOST_PORT);
                    TcpStream::connect(&addr).map_err(|err| WhoIsError::IOError(err))?
                }
            }
        };

        if let Some(timeout) = timeout {
            client.set_read_timeout(Some(timeout)).map_err(|err| WhoIsError::IOError(err))?;
            client.set_write_timeout(Some(timeout)).map_err(|err| WhoIsError::IOError(err))?;
        }

        if let Some(query) = server.query {
            client.write_all(query.replace("$addr", text).as_bytes()).map_err(|err| WhoIsError::IOError(err))?;
        } else {
            client.write_all(DEFAULT_WHOIS_HOST_QUERY.replace("$addr", text).as_bytes()).map_err(|err| WhoIsError::IOError(err))?;
        }

        client.flush().map_err(|err| WhoIsError::IOError(err))?;

        let mut query_result = String::new();

        client.read_to_string(&mut query_result).map_err(|err| WhoIsError::IOError(err))?;

        if follow > 0 {
            if let Some(c) = REF_SERVER_RE.captures(&query_result) {
                if let Some(h) = c.get(3) {
                    let h = h.as_str();
                    if h.ne(&addr) {
                        if let Ok(server) = WhoIsServerValue::from_string(h) {
                            return Self::lookup_inner(server, text, timeout, follow - 1);
                        }
                    }
                }
            }
        }

        return Ok(query_result);
    }

    pub fn lookup(&self, options: WhoIsLookupOptions) -> Result<String, WhoIsError> {
        let (server, text) = {
            match &options.target {
                Target::IPv4(ipv4) => {
                    let server = match options.server {
                        Some(server) => server,
                        None => {
                            match self.map.get("_") {
                                Some(server) => {
                                    if !server.is_object() {
                                        return Err(WhoIsError::MapError("`_` in the map is not an object."));
                                    }
                                    match server.get("ip") {
                                        Some(server) => {
                                            if server.is_null() {
                                                return Err(WhoIsError::MapError("`ip` in the `_` object in the map is null."));
                                            }
                                            WhoIsServerValue::from_value(server)?
                                        }
                                        None => return Err(WhoIsError::MapError("Cannot find `ip` in the `_` object in the map."))
                                    }
                                }
                                None => return Err(WhoIsError::MapError("Cannot find `_` in the map."))
                            }
                        }
                    };
                    (server, ipv4.get_full_ipv4())
                }
                Target::Domain(domain) => {
                    let mut tld = domain.get_full_domain();
                    let server = match options.server {
                        Some(server) => server,
                        None => {
                            let mut server;
                            loop {
                                server = self.map.get(tld);

                                if let Some(s) = server {
                                    if s.is_null() {
                                        server = None;
                                    } else {
                                        break;
                                    }
                                }

                                if tld.is_empty() {
                                    break;
                                }

                                match tld.find(".") {
                                    Some(index) => {
                                        tld = &tld[index + 1..];
                                    }
                                    None => {
                                        tld = "";
                                    }
                                }
                            }
                            match server {
                                Some(server) => WhoIsServerValue::from_value(server)?,
                                None => return Err(WhoIsError::MapError("No whois server is known for this kind of object."))
                            }
                        }
                    };

                    (server, domain.get_full_domain())
                }
            }
        };

        Self::lookup_inner(server, text, options.timeout, options.follow)
    }
}