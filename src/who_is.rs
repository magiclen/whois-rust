use std::{
    collections::HashMap,
    fs::File,
    io::{Read, Write},
    net::{SocketAddr, TcpStream, ToSocketAddrs},
    path::Path,
    str::FromStr,
    time::Duration,
};

use once_cell::sync::Lazy;
use regex::Regex;
use serde_json::{Map, Value};
#[cfg(feature = "tokio")]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use trust_dns_client::{
    client::{Client, SyncClient},
    op::DnsResponse,
    rr::{DNSClass, Name, RData, Record, RecordType},
    udp::UdpClientConnection,
};
use validators::{models::Host, prelude::*};

use crate::{WhoIsError, WhoIsLookupOptions, WhoIsServerValue};

const DEFAULT_WHOIS_HOST_PORT: u16 = 43;
const DEFAULT_WHOIS_HOST_QUERY: &str = "$addr\r\n";

static RE_SERVER: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(ReferralServer|Registrar Whois|Whois Server|WHOIS Server|Registrar WHOIS Server|whois):[^\S\n]*(r?whois://)?(.*)").unwrap()
});

/// The `WhoIs` structure stores the list of WHOIS servers in-memory.
#[derive(Debug, Clone)]
pub struct WhoIs {
    map: HashMap<String, WhoIsServerValue>,
    ip:  WhoIsServerValue,
}

impl WhoIs {
    /// Create a `WhoIs` instance which doesn't have a WHOIS server list. You should provide the host that is used for query ip. You may want to use the host `"whois.arin.net"`.
    pub fn from_host<T: AsRef<str>>(host: T) -> Result<WhoIs, WhoIsError> {
        Ok(Self {
            map: HashMap::new(), ip: WhoIsServerValue::from_string(host)?
        })
    }

    /// Read the list of WHOIS servers (JSON data) from a file to create a `WhoIs` instance.
    #[inline]
    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<WhoIs, WhoIsError> {
        let path = path.as_ref();

        let file = File::open(path)?;

        let map: Map<String, Value> = serde_json::from_reader(file)?;

        Self::from_inner(map)
    }

    #[cfg(feature = "tokio")]
    /// Read the list of WHOIS servers (JSON data) from a file to create a `WhoIs` instance. For `serde_json` doesn't support async functions, consider just using the `from_path` function.
    #[inline]
    pub async fn from_path_async<P: AsRef<Path>>(path: P) -> Result<WhoIs, WhoIsError> {
        let file = tokio::fs::read(path).await?;

        let map: Map<String, Value> = serde_json::from_slice(file.as_slice())?;

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
                        },
                        None => {
                            return Err(WhoIsError::MapError(
                                "Cannot find `ip` in the `_` object in the server list.",
                            ));
                        },
                    }
                } else {
                    return Err(WhoIsError::MapError("`_` in the server list is not an object."));
                }
            },
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

impl WhoIs {
    pub fn can_find_server_for_tld<T: AsRef<str>, D: AsRef<str>>(
        &mut self,
        tld: T,
        dns_server: D,
    ) -> bool {
        let mut tld = tld.as_ref();
        let dns_server = dns_server.as_ref();

        let address = dns_server.parse().unwrap();
        let conn = UdpClientConnection::new(address).unwrap();
        let client = SyncClient::new(conn);

        loop {
            if self.map.contains_key(tld) {
                break;
            }

            match tld.find('.') {
                Some(index) => {
                    tld = &tld[index + 1..];
                },
                None => {
                    tld = "";
                },
            }

            if tld.is_empty() {
                break;
            }

            let name = Name::from_str(&format!("_nicname._tcp.{}.", tld)).unwrap();
            let response: DnsResponse = client.query(&name, DNSClass::IN, RecordType::SRV).unwrap();
            let answers: &[Record] = response.answers();

            for record in answers {
                if let Some(RData::SRV(record)) = record.data() {
                    let target = record.target().to_string();
                    let new_server =
                        match WhoIsServerValue::from_string(&target[..target.len() - 1]) {
                            Ok(new_server) => new_server,
                            Err(_error) => continue,
                        };

                    self.map.insert(tld.to_string(), new_server);

                    return true;
                }
            }
        }

        false
    }

    fn get_server_by_tld(&self, mut tld: &str) -> Option<&WhoIsServerValue> {
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
                },
                None => {
                    tld = "";
                },
            }
        }

        server
    }

    fn lookup_once(
        server: &WhoIsServerValue,
        text: &str,
        timeout: Option<Duration>,
    ) -> Result<(String, String), WhoIsError> {
        let addr = server.host.to_addr_string(DEFAULT_WHOIS_HOST_PORT);

        let mut client = if let Some(timeout) = timeout {
            let socket_addrs: Vec<SocketAddr> = addr.to_socket_addrs()?.collect();

            let mut client = None;

            for socket_addr in socket_addrs.iter().take(socket_addrs.len() - 1) {
                if let Ok(c) = TcpStream::connect_timeout(socket_addr, timeout) {
                    client = Some(c);
                    break;
                }
            }

            let client = if let Some(client) = client {
                client
            } else {
                let socket_addr = &socket_addrs[socket_addrs.len() - 1];
                TcpStream::connect_timeout(socket_addr, timeout)?
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

        Ok((addr, query_result))
    }

    fn lookup_inner(
        server: &WhoIsServerValue,
        text: &str,
        timeout: Option<Duration>,
        mut follow: u16,
    ) -> Result<String, WhoIsError> {
        let mut query_result = Self::lookup_once(server, text, timeout)?;

        while follow > 0 {
            if let Some(c) = RE_SERVER.captures(&query_result.1) {
                if let Some(h) = c.get(3) {
                    let h = h.as_str();
                    if h.ne(&query_result.0) {
                        if let Ok(server) = WhoIsServerValue::from_string(h) {
                            query_result = Self::lookup_once(&server, text, timeout)?;

                            follow -= 1;

                            continue;
                        }
                    }
                }
            }

            break;
        }

        Ok(query_result.1)
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
            },
            Host::Domain(domain) => {
                let server = match &options.server {
                    Some(server) => server,
                    None => match self.get_server_by_tld(domain.as_str()) {
                        Some(server) => server,
                        None => {
                            return Err(WhoIsError::MapError(
                                "No whois server is known for this kind of object.",
                            ));
                        },
                    },
                };

                // punycode check is not necessary because the domain has been ascii-encoded

                Self::lookup_inner(server, domain, options.timeout, options.follow)
            },
        }
    }
}

#[cfg(feature = "tokio")]
impl WhoIs {
    async fn lookup_inner_once_async<'a>(
        server: &WhoIsServerValue,
        text: &str,
        timeout: Option<Duration>,
    ) -> Result<(String, String), WhoIsError> {
        let addr = server.host.to_addr_string(DEFAULT_WHOIS_HOST_PORT);

        if let Some(timeout) = timeout {
            let socket_addrs: Vec<SocketAddr> = addr.to_socket_addrs()?.collect();

            let mut client = None;

            for socket_addr in socket_addrs.iter().take(socket_addrs.len() - 1) {
                if let Ok(c) =
                    tokio::time::timeout(timeout, tokio::net::TcpStream::connect(&socket_addr))
                        .await?
                {
                    client = Some(c);
                    break;
                }
            }

            let mut client = if let Some(client) = client {
                client
            } else {
                let socket_addr = &socket_addrs[socket_addrs.len() - 1];
                tokio::time::timeout(timeout, tokio::net::TcpStream::connect(socket_addr)).await??
            };

            if let Some(query) = &server.query {
                tokio::time::timeout(
                    timeout,
                    client.write_all(query.replace("$addr", text).as_bytes()),
                )
                .await??;
            } else {
                tokio::time::timeout(
                    timeout,
                    client.write_all(DEFAULT_WHOIS_HOST_QUERY.replace("$addr", text).as_bytes()),
                )
                .await??;
            }

            tokio::time::timeout(timeout, client.flush()).await??;

            let mut query_result = String::new();

            tokio::time::timeout(timeout, client.read_to_string(&mut query_result)).await??;

            Ok((addr, query_result))
        } else {
            let mut client = tokio::net::TcpStream::connect(&addr).await?;

            if let Some(query) = &server.query {
                client.write_all(query.replace("$addr", text).as_bytes()).await?;
            } else {
                client
                    .write_all(DEFAULT_WHOIS_HOST_QUERY.replace("$addr", text).as_bytes())
                    .await?;
            }

            client.flush().await?;

            let mut query_result = String::new();

            client.read_to_string(&mut query_result).await?;

            Ok((addr, query_result))
        }
    }

    async fn lookup_inner_async<'a>(
        server: &'a WhoIsServerValue,
        text: &'a str,
        timeout: Option<Duration>,
        mut follow: u16,
    ) -> Result<String, WhoIsError> {
        let mut query_result = Self::lookup_inner_once_async(server, text, timeout).await?;

        while follow > 0 {
            if let Some(c) = RE_SERVER.captures(&query_result.1) {
                if let Some(h) = c.get(3) {
                    let h = h.as_str();
                    if h.ne(&query_result.0) {
                        if let Ok(server) = WhoIsServerValue::from_string(h) {
                            query_result =
                                Self::lookup_inner_once_async(&server, text, timeout).await?;

                            follow -= 1;

                            continue;
                        }
                    }
                }
            }

            break;
        }

        Ok(query_result.1)
    }

    /// Lookup a domain or an IP.
    pub async fn lookup_async(&self, options: WhoIsLookupOptions) -> Result<String, WhoIsError> {
        match &options.target.0 {
            Host::IPv4(_) | Host::IPv6(_) => {
                let server = match &options.server {
                    Some(server) => server,
                    None => &self.ip,
                };

                Self::lookup_inner_async(
                    server,
                    options.target.to_uri_authority_string().as_ref(),
                    options.timeout,
                    options.follow,
                )
                .await
            },
            Host::Domain(domain) => {
                let server = match &options.server {
                    Some(server) => server,
                    None => match self.get_server_by_tld(domain.as_str()) {
                        Some(server) => server,
                        None => {
                            return Err(WhoIsError::MapError(
                                "No whois server is known for this kind of object.",
                            ));
                        },
                    },
                };

                // punycode check is not necessary because the domain has been ascii-encoded

                Self::lookup_inner_async(server, domain, options.timeout, options.follow).await
            },
        }
    }
}
