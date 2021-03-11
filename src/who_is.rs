extern crate once_cell;
extern crate regex;

use std::collections::HashMap;
use std::fs::File;
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::Path;
use std::time::Duration;
#[cfg(feature = "async")]
use tokio::net::TcpStream;
#[cfg(feature = "async")]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(feature = "async")]
use tokio::time::timeout;
#[cfg(not(feature = "async"))]
use std::net::TcpStream;
#[cfg(not(feature = "async"))]
use std::io::{Read, Write};

use crate::serde_json::{self, Map, Value};
use crate::validators::models::Host;

use crate::{WhoIsError, WhoIsLookupOptions, WhoIsServerValue};

use once_cell::sync::Lazy;
use regex::Regex;

const DEFAULT_WHOIS_HOST_PORT: u16 = 43;
const DEFAULT_WHOIS_HOST_QUERY: &str = "$addr\r\n";

static RE_SERVER: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(ReferralServer|Registrar Whois|Whois Server|WHOIS Server|Registrar WHOIS Server):[^\S\n]*(r?whois://)?(.*)").unwrap()
});

/// The `WhoIs` structure stores the list of WHOIS servers in-memory.
#[derive(Debug, Clone)]
pub struct WhoIs {
    map: HashMap<String, WhoIsServerValue>,
    ip: WhoIsServerValue,
}

impl WhoIs {
    /// Read the list of WHOIS servers (JSON data) from a file to create a `WhoIs` instance.
    #[inline]
    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<WhoIs, WhoIsError> {
        let path = path.as_ref();

        let file = File::open(path)?;

        let map: Map<String, Value> = serde_json::from_reader(file)?;

        Self::from_inner(map)
    }

    /// Read the list of WHOIS servers (JSON data) from a string to create a `WhoIs` instance.
    #[inline]
    pub fn from_string<S: AsRef<str>>(string: S) -> Result<WhoIs, WhoIsError> {
        let string = string.as_ref();

        let map: Map<String, Value> = serde_json::from_str(string)?;

        Self::from_inner(map)
    }

    fn from_inner(mut map: Map<String, Value>) -> Result<WhoIs, WhoIsError> {
        let ip = match map.remove("_") {
            Some(server) => {
                if let Value::Object(server) = server {
                    match server.get("ip") {
                        Some(server) => {
                            if server.is_null() {
                                return Err(WhoIsError::MapError(
                                    "`ip` in the `_` object in the server list is null.",
                                ));
                            }

                            WhoIsServerValue::from_value(server)?
                        }
                        None => {
                            return Err(WhoIsError::MapError(
                                "Cannot find `ip` in the `_` object in the server list.",
                            ))
                        }
                    }
                } else {
                    return Err(WhoIsError::MapError("`_` in the server list is not an object."));
                }
            }
            None => return Err(WhoIsError::MapError("Cannot find `_` in the server list.")),
        };

        let mut new_map: HashMap<String, WhoIsServerValue> = HashMap::with_capacity(map.len());

        for (k, v) in map {
            if !v.is_null() {
                let server_value = WhoIsServerValue::from_value(&v)?;
                new_map.insert(k, server_value);
            }
        }

        Ok(WhoIs {
            map: new_map,
            ip,
        })
    }
}

#[cfg(not(feature = "async"))]
impl WhoIs {
    fn lookup_inner(
        server: &WhoIsServerValue,
        text: &str,
        timeout: Option<Duration>,
        follow: u16,
    ) -> Result<String, WhoIsError> {
        let port = server.host.port.unwrap_or(DEFAULT_WHOIS_HOST_PORT);

        let addr = match &server.host.host {
            Host::IPv4(ip) => format!("{}:{}", ip, port),
            Host::IPv6(ip) => format!("[{}]:{}", ip, port),
            Host::Domain(domain) => format!("{}:{}", domain, port),
        };

        let mut client = if let Some(timeout) = timeout {
            let socket_addrs: Vec<SocketAddr> = addr.to_socket_addrs()?.collect();

            let mut client = None;

            for socket_addr in socket_addrs.iter().take(socket_addrs.len() - 1) {
                if let Ok(c) = TcpStream::connect_timeout(&socket_addr, timeout) {
                    client = Some(c);
                    break;
                }
            }

            let client = if let Some(client) = client {
                client
            } else {
                let socket_addr = &socket_addrs[socket_addrs.len() - 1];
                TcpStream::connect_timeout(&socket_addr, timeout)?
            };

            client.set_read_timeout(Some(timeout))?;
            client.set_write_timeout(Some(timeout))?;
            client
        } else {
            TcpStream::connect(&addr)?
        };

        if let Some(query) = &server.query {
            client.write_all(query.replace("$addr", text).as_bytes())?;
        } else {
            client.write_all(DEFAULT_WHOIS_HOST_QUERY.replace("$addr", text).as_bytes())?;
        }

        client.flush()?;

        let mut query_result = String::new();

        client.read_to_string(&mut query_result)?;

        if follow > 0 {
            if let Some(c) = RE_SERVER.captures(&query_result) {
                if let Some(h) = c.get(3) {
                    let h = h.as_str();
                    if h.ne(&addr) {
                        if let Ok(server) = WhoIsServerValue::from_string(h) {
                            return Self::lookup_inner(&server, text, timeout, follow - 1);
                        }
                    }
                }
            }
        }

        Ok(query_result)
    }

    /// Lookup a domain or an IP.
    pub fn lookup(&self, options: WhoIsLookupOptions) -> Result<String, WhoIsError> {
        match &options.target.0 {
            Host::IPv4(_) | Host::IPv6(_) => {
                let server = match &options.server {
                    Some(server) => server,
                    None => &self.ip,
                };

                Self::lookup_inner(
                    server,
                    options.target.to_uri_authority_string().as_ref(),
                    options.timeout,
                    options.follow,
                )
            }
            Host::Domain(domain) => {
                let mut tld = domain.as_str();

                let server = match &options.server {
                    Some(server) => server,
                    None => {
                        let mut server;
                        loop {
                            server = self.map.get(tld);

                            if server.is_some() {
                                break;
                            }

                            if tld.is_empty() {
                                break;
                            }

                            match tld.find('.') {
                                Some(index) => {
                                    tld = &tld[index + 1..];
                                }
                                None => {
                                    tld = "";
                                }
                            }
                        }
                        match server {
                            Some(server) => server,
                            None => {
                                return Err(WhoIsError::MapError(
                                    "No whois server is known for this kind of object.",
                                ))
                            }
                        }
                    }
                };

                // punycode check is not necessary because the domain has been ascii-encoded

                Self::lookup_inner(server, domain, options.timeout, options.follow)
            }
        }
    }
}

#[cfg(feature = "async")]
impl WhoIs {
    async fn lookup_inner_once(
        server: &WhoIsServerValue,
        text: &str,
        request_timeout: Option<Duration>,
    ) -> Result<(String,String), WhoIsError> {
        let port = server.host.port.unwrap_or(DEFAULT_WHOIS_HOST_PORT);

        let addr = match &server.host.host {
            Host::IPv4(ip) => format!("{}:{}", ip, port),
            Host::IPv6(ip) => format!("[{}]:{}", ip, port),
            Host::Domain(domain) => format!("{}:{}", domain, port),
        };

        let mut client = if let Some(request_timeout) = request_timeout {
            let socket_addrs: Vec<SocketAddr> = addr.to_socket_addrs()?.collect();

            let mut client = None;

            for socket_addr in socket_addrs.iter().take(socket_addrs.len() - 1) {
                
                if let Ok(ct) = timeout(request_timeout,TcpStream::connect(&socket_addr)).await {
                    if let Ok(c) = ct {
                        client = Some(c);
                        break;
                    }
                }
            }

            let client = if let Some(client) = client {
                client
            } else {
                let socket_addr = &socket_addrs[socket_addrs.len() - 1];
                TcpStream::connect(&socket_addr).await?
            };
            client
        } else {
            TcpStream::connect(&addr).await?
        };
        let query_future=async {
            client.write_all((if let Some(query) = &server.query {
                query.as_str()
            } else {
                DEFAULT_WHOIS_HOST_QUERY
            }).replace("$addr", text).as_bytes()).await?;
            client.flush().await?;
            let mut query_result = String::new();
            client.read_to_string(&mut query_result).await?;
            Result::<String,WhoIsError>::Ok(query_result)
        };
        let query_result = if let Some(request_timeout) = request_timeout {
            timeout(request_timeout,query_future).await??
        } else {
            query_future.await?
        };
        Ok((query_result,addr))
    }

    async fn lookup_inner(
        server: &WhoIsServerValue,
        text: &str,
        timeout: Option<Duration>,
        mut follow: u16
    ) -> Result<String, WhoIsError> {
        let mut query_result = match Self::lookup_inner_once(server, text, timeout).await {
            Err(e) => return Err(e),
            Ok(s) => s
        };
        while follow>0 {
            follow-=1;
            if let Some(c) = RE_SERVER.captures(&query_result.0) {
                if let Some(h) = c.get(3) {
                    let h = h.as_str();
                    if h.ne(&query_result.1) {
                        if let Ok(server) = WhoIsServerValue::from_string(h) {
                            query_result=Self::lookup_inner_once(&server, text, timeout).await?;
                        } else {
                            break;
                        }
                    } else {
                        break;
                    }
                } else {
                    break;
                }
            } else {
                break;
            }
        }
        return Ok(query_result.0)
    }

    /// Lookup a domain or an IP.
    pub async fn lookup(&self, options: WhoIsLookupOptions) -> Result<String, WhoIsError> {
        match &options.target.0 {
            Host::IPv4(_) | Host::IPv6(_) => {
                let server = match &options.server {
                    Some(server) => server,
                    None => &self.ip,
                };

                Self::lookup_inner(
                    server,
                    options.target.to_uri_authority_string().as_ref(),
                    options.timeout,
                    options.follow,
                ).await
            }
            Host::Domain(domain) => {
                let mut tld = domain.as_str();

                let server = match &options.server {
                    Some(server) => server,
                    None => {
                        let mut server;
                        loop {
                            server = self.map.get(tld);

                            if server.is_some() {
                                break;
                            }

                            if tld.is_empty() {
                                break;
                            }

                            match tld.find('.') {
                                Some(index) => {
                                    tld = &tld[index + 1..];
                                }
                                None => {
                                    tld = "";
                                }
                            }
                        }
                        match server {
                            Some(server) => server,
                            None => {
                                return Err(WhoIsError::MapError(
                                    "No whois server is known for this kind of object.",
                                ))
                            }
                        }
                    }
                };

                // punycode check is not necessary because the domain has been ascii-encoded

                Self::lookup_inner(server, domain, options.timeout, options.follow).await
            }
        }
    }
}
