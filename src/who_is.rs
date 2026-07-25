#[cfg(feature = "srv")]
use std::str::FromStr;
use std::{
    borrow::Cow,
    collections::HashMap,
    fs::File,
    io::{self, Read, Write},
    net::{SocketAddr, TcpStream, ToSocketAddrs},
    path::Path,
    sync::LazyLock,
    time::{Duration, Instant},
};

#[cfg(feature = "srv")]
use hickory_client::{
    client::{Client, ClientHandle},
    proto::{
        rr::{DNSClass, Name, RData, RecordType},
        runtime::TokioRuntimeProvider,
        udp::UdpClientStream,
    },
};
use regex::bytes::Regex;
use serde_json::{Map, Value};
#[cfg(feature = "tokio")]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use validators::models::Host;

use crate::{WhoIsError, WhoIsHost, WhoIsLookupOptions, WhoIsServerValue};

const DEFAULT_WHOIS_HOST_PORT: u16 = 43;
const DEFAULT_WHOIS_HOST_QUERY: &str = "$addr\r\n";
const READ_BUFFER_SIZE: usize = 8 * 1024;

// The pattern is matched against the raw response, so Unicode mode is turned off to let `\S` mean "any non-whitespace byte". A field name has to start its own line, otherwise a mention of it in the legal notice of a response would be picked up.
static RE_SERVER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m-u)^[^\S\n]*(?:Registrar[^\S\n]+)?(?:ReferralServer|Registrar Whois|Whois Server|WHOIS Server|Registrar WHOIS Server):[^\S\n]*(?:r?whois://)?(\S*)").unwrap()
});

/// Extract the referral WHOIS host from a query result. The response is not decoded first because a host is always ASCII, and only the first token of the value is taken because responses usually end lines with CRLF and some servers append a note to the host.
fn extract_referral_host(query_result: &[u8]) -> Option<&str> {
    let host = RE_SERVER.captures(query_result)?.get(1)?.as_bytes();
    let host = std::str::from_utf8(host).ok()?;

    if host.is_empty() { None } else { Some(host) }
}

/// Decode the raw bytes of a WHOIS response into a `String`. Valid UTF-8 always passes through without being copied. When the `charset` feature is disabled, invalid UTF-8 falls back to a lossy conversion (malformed bytes become `U+FFFD`), and the TLD hint is unused.
#[cfg(not(feature = "charset"))]
fn decode_response(bytes: Vec<u8>, _tld: Option<&str>) -> String {
    match String::from_utf8(bytes) {
        Ok(s) => s,
        Err(error) => String::from_utf8_lossy(error.as_bytes()).into_owned(),
    }
}

/// Decode the raw bytes of a WHOIS response into a `String`. Valid UTF-8 always passes through without being copied. Otherwise the encoding is detected with `chardetng` and decoded with `encoding_rs` (malformed bytes become `U+FFFD`). The TLD hint biases the detector towards the encodings that are common in that TLD, which matters for CJK ccTLDs.
#[cfg(feature = "charset")]
fn decode_response(bytes: Vec<u8>, tld: Option<&str>) -> String {
    use chardetng::{EncodingDetector, Iso2022JpDetection, Utf8Detection};

    let bytes = match String::from_utf8(bytes) {
        Ok(s) => return s,
        Err(error) => error.into_bytes(),
    };

    let mut detector = EncodingDetector::new(Iso2022JpDetection::Allow);

    detector.feed(&bytes, true);

    detector.guess(tld.map(str::as_bytes), Utf8Detection::Allow).decode(&bytes).0.into_owned()
}

/// Get the TLD of a target to hint the charset detector with. `chardetng` requires it to be ASCII without upper case letters, so an upper case TLD is lower cased and a non-ASCII one gives `None`.
fn tld_hint(host: &Host) -> Option<Cow<'_, str>> {
    let Host::Domain(domain) = host else {
        return None;
    };

    let tld = match domain.rfind('.') {
        Some(index) => &domain[index + 1..],
        None => domain.as_str(),
    };

    if tld.is_empty() || !tld.is_ascii() {
        return None;
    }

    if tld.bytes().any(|b| b.is_ascii_uppercase()) {
        Some(Cow::Owned(tld.to_ascii_lowercase()))
    } else {
        Some(Cow::Borrowed(tld))
    }
}

/// Build the text of a target to send to a server. Unlike a URI authority, IPv6 addresses are **not** wrapped in `[` and `]`, which is what WHOIS servers expect.
fn query_text<'a>(server: &WhoIsServerValue, host: &'a Host) -> Cow<'a, str> {
    match host {
        // The domain is already ASCII (Punycode) encoded; decode it back to Unicode for servers that require it.
        Host::Domain(domain) => server.encode_domain(domain),
        Host::IPv4(ip) => Cow::Owned(ip.to_string()),
        Host::IPv6(ip) => Cow::Owned(ip.to_string()),
    }
}

/// Build the request to send to a server. RFC 3912 requires a request to be terminated with CRLF, so a query which is not is fixed up instead of being sent as it is.
fn build_request(server: &WhoIsServerValue, text: &str) -> String {
    let query = server.query.as_deref().unwrap_or(DEFAULT_WHOIS_HOST_QUERY);

    let mut request = query.replace("$addr", text);

    if !request.ends_with("\r\n") {
        if request.ends_with('\n') {
            request.pop();
        }

        request.push_str("\r\n");
    }

    request
}

/// Whether two hosts point at the same WHOIS server. Domains are compared case insensitively, because a referral does not have to spell its host the same way as the server list does.
fn same_host(a: &Host, b: &Host) -> bool {
    match (a, b) {
        (Host::Domain(a), Host::Domain(b)) => a.eq_ignore_ascii_case(b),
        _ => a == b,
    }
}

/// A timeout budget shared by every step of one connection, so that a host with several addresses cannot make a lookup take the timeout once per address.
#[derive(Debug)]
struct Deadline {
    start:   Instant,
    timeout: Duration,
}

impl Deadline {
    #[inline]
    fn new(timeout: Duration) -> Self {
        Deadline {
            start: Instant::now(),
            timeout,
        }
    }

    /// Get the part of the budget which is still available, or an error if it has run out.
    fn remaining(&self) -> Result<Duration, io::Error> {
        match self.timeout.checked_sub(self.start.elapsed()) {
            Some(remaining) if !remaining.is_zero() => Ok(remaining),
            _ => Err(io::Error::new(io::ErrorKind::TimedOut, "the WHOIS lookup timed out")),
        }
    }
}

/// The error to report when a host has no address left to try.
#[inline]
fn no_address_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::AddrNotAvailable,
        "the host is not resolved to any socket address",
    )
}

/// Connect to the first address which accepts the connection, spending one shared budget on all of the attempts.
fn connect(socket_addrs: &[SocketAddr], deadline: &Deadline) -> io::Result<TcpStream> {
    let mut last_error = None;

    for socket_addr in socket_addrs {
        match TcpStream::connect_timeout(socket_addr, deadline.remaining()?) {
            Ok(client) => return Ok(client),
            Err(error) => last_error = Some(error),
        }
    }

    Err(last_error.unwrap_or_else(no_address_error))
}

/// Read a whole WHOIS response, failing instead of truncating when it is bigger than the given limit. The deadline, when there is one, bounds the whole response instead of each read, so that a server which trickles its response out cannot hold the connection for longer than the timeout.
fn read_response(
    client: &mut TcpStream,
    max_response_size: Option<usize>,
    deadline: Option<&Deadline>,
) -> io::Result<Vec<u8>> {
    let mut query_result = Vec::new();
    let mut buffer = [0u8; READ_BUFFER_SIZE];

    loop {
        if let Some(deadline) = deadline {
            client.set_read_timeout(Some(deadline.remaining()?))?;
        }

        // RFC 3912: the response is over when the server closes the connection.
        let read = client.read(&mut buffer)?;

        if read == 0 {
            break;
        }

        if let Some(max) = max_response_size
            && query_result.len() + read > max
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the WHOIS response is too big",
            ));
        }

        query_result.extend_from_slice(&buffer[..read]);
    }

    Ok(query_result)
}

/// Connect to the first address which accepts the connection, spending one shared budget on all of the attempts.
#[cfg(feature = "tokio")]
async fn connect_async(
    socket_addrs: &[SocketAddr],
    deadline: &Deadline,
) -> Result<tokio::net::TcpStream, WhoIsError> {
    let mut last_error = None;

    for socket_addr in socket_addrs {
        match tokio::time::timeout(
            deadline.remaining()?,
            tokio::net::TcpStream::connect(socket_addr),
        )
        .await
        {
            Ok(Ok(client)) => return Ok(client),
            Ok(Err(error)) => last_error = Some(WhoIsError::IOError(error)),
            Err(error) => last_error = Some(WhoIsError::Elapsed(error)),
        }
    }

    Err(last_error.unwrap_or_else(|| WhoIsError::IOError(no_address_error())))
}

/// Read the address of the DNS server to query the SRV records through.
#[cfg(feature = "srv")]
fn parse_dns_server(dns_server: &str) -> Result<SocketAddr, WhoIsError> {
    dns_server
        .parse()
        .map_err(|_error| WhoIsError::MapError("The DNS server address is incorrect."))
}

/// Strip the leftmost label off a TLD/domain, giving `None` when there is nothing left to query.
#[cfg(feature = "srv")]
fn strip_label(tld: &str) -> Option<&str> {
    let parent = &tld[tld.find('.')? + 1..];

    if parent.is_empty() { None } else { Some(parent) }
}

/// Query the SRV records of a name through a DNS server, returning the target of every answer.
#[cfg(feature = "srv")]
async fn query_srv_targets_async(
    dns_server: SocketAddr,
    name: Name,
) -> Result<Vec<String>, WhoIsError> {
    let stream = UdpClientStream::builder(dns_server, TokioRuntimeProvider::new()).build();

    let (mut client, background) = Client::connect(stream).await.map_err(io::Error::other)?;

    // The connection is driven by this task, so the query cannot make any progress without it.
    let background = tokio::spawn(background);

    let response = client.query(name, DNSClass::IN, RecordType::SRV).await;

    background.abort();

    let response = response.map_err(io::Error::other)?;

    Ok(response
        .answers()
        .iter()
        .filter_map(|record| match record.data() {
            RData::SRV(srv) => Some(srv.target().to_string()),
            _ => None,
        })
        .collect())
}

/// Query the SRV records of a name through a DNS server, returning the target of every answer. `hickory-client` is async only, so the query is run on a thread of its own with a runtime of its own, which keeps this usable from inside an async runtime as well.
#[cfg(feature = "srv")]
fn query_srv_targets(dns_server: SocketAddr, name: Name) -> Result<Vec<String>, WhoIsError> {
    let thread = std::thread::spawn(move || -> Result<Vec<String>, WhoIsError> {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;

        runtime.block_on(query_srv_targets_async(dns_server, name))
    });

    match thread.join() {
        Ok(targets) => targets,
        Err(error) => std::panic::resume_unwind(error),
    }
}

/// Read a whole WHOIS response, failing instead of truncating when it is bigger than the given limit. The caller bounds the time this takes by awaiting it with a timeout.
#[cfg(feature = "tokio")]
async fn read_response_async(
    client: &mut tokio::net::TcpStream,
    max_response_size: Option<usize>,
) -> io::Result<Vec<u8>> {
    let mut query_result = Vec::new();

    match max_response_size {
        Some(max) => {
            // One byte past the limit is read so that a response which is too big can be told apart from one which exactly fits.
            client.take(max.saturating_add(1) as u64).read_to_end(&mut query_result).await?;

            if query_result.len() > max {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "the WHOIS response is too big",
                ));
            }
        },
        None => {
            client.read_to_end(&mut query_result).await?;
        },
    }

    Ok(query_result)
}

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

    /// Read the list of WHOIS servers (JSON data) from a file to create a `WhoIs` instance. For `serde_json` doesn't support async functions, consider just using the `from_path` function.
    #[cfg(feature = "tokio")]
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

#[cfg(feature = "srv")]
impl WhoIs {
    /// Cache the first target which is a valid host as the server of a TLD. Returns whether one of them was.
    fn cache_first_server(&mut self, tld: &str, targets: Vec<String>) -> bool {
        for target in targets {
            let Ok(new_server) = WhoIsServerValue::from_string(target.trim_end_matches('.')) else {
                continue;
            };

            self.map.insert(tld.to_string(), new_server);

            return true;
        }

        false
    }

    /// Try to find a WHOIS server for a TLD by querying the `_nicname._tcp.<tld>` SRV records through the given DNS server, caching any server that is found for later lookups. Returns whether a server is available for the TLD (already known or newly discovered).
    ///
    /// One label is stripped off before each query, so pass `".example.com"` to have `example.com` itself queried. A TLD which is already in the server list is never replaced by a discovered one.
    ///
    /// This method blocks. It may be called from inside an async runtime, but `can_find_server_for_tld_async` (which needs the `tokio` feature) is the one to use there.
    pub fn can_find_server_for_tld<T: AsRef<str>, D: AsRef<str>>(
        &mut self,
        tld: T,
        dns_server: D,
    ) -> Result<bool, WhoIsError> {
        let mut tld = tld.as_ref();

        // The TLD as given may already be known, in which case nothing else has to be set up.
        if self.map.contains_key(tld) {
            return Ok(true);
        }

        let address = parse_dns_server(dns_server.as_ref())?;

        loop {
            let Some(parent) = strip_label(tld) else {
                return Ok(false);
            };

            tld = parent;

            // The parent is checked before it is queried, so a known server is never queried for nor overwritten.
            if self.map.contains_key(tld) {
                return Ok(true);
            }

            let name =
                Name::from_str(&format!("_nicname._tcp.{tld}.")).map_err(io::Error::other)?;

            if self.cache_first_server(tld, query_srv_targets(address, name)?) {
                return Ok(true);
            }
        }
    }
}

#[cfg(all(feature = "srv", feature = "tokio"))]
impl WhoIs {
    /// Try to find a WHOIS server for a TLD by querying the `_nicname._tcp.<tld>` SRV records through the given DNS server, caching any server that is found for later lookups. Returns whether a server is available for the TLD (already known or newly discovered).
    ///
    /// One label is stripped off before each query, so pass `".example.com"` to have `example.com` itself queried. A TLD which is already in the server list is never replaced by a discovered one.
    pub async fn can_find_server_for_tld_async<T: AsRef<str>, D: AsRef<str>>(
        &mut self,
        tld: T,
        dns_server: D,
    ) -> Result<bool, WhoIsError> {
        let mut tld = tld.as_ref();

        // The TLD as given may already be known, in which case nothing else has to be set up.
        if self.map.contains_key(tld) {
            return Ok(true);
        }

        let address = parse_dns_server(dns_server.as_ref())?;

        loop {
            let Some(parent) = strip_label(tld) else {
                return Ok(false);
            };

            tld = parent;

            // The parent is checked before it is queried, so a known server is never queried for nor overwritten.
            if self.map.contains_key(tld) {
                return Ok(true);
            }

            let name =
                Name::from_str(&format!("_nicname._tcp.{tld}.")).map_err(io::Error::other)?;

            if self.cache_first_server(tld, query_srv_targets_async(address, name).await?) {
                return Ok(true);
            }
        }
    }
}

impl WhoIs {
    /// Try to find a WHOIS server for a TLD from the in-memory server list, walking up the labels of the given TLD/domain (e.g. `a.b.example` -> `b.example` -> `example` -> `""`) until a match is found. Returns the matched server, if any.
    pub fn get_server_by_tld(&self, mut tld: &str) -> Option<&WhoIsServerValue> {
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

    /// Find the entry of the server list which is served by a host, so that following a referral to a known server keeps that server's `query` and `punycode` settings.
    fn get_server_by_host(&self, host: &WhoIsHost) -> Option<&WhoIsServerValue> {
        self.map.values().find(|server| &server.host == host)
    }

    /// Pick the server a lookup starts from: the one given in the options, or the best match from the server list.
    fn get_server<'a>(
        &'a self,
        options: &'a WhoIsLookupOptions,
    ) -> Result<&'a WhoIsServerValue, WhoIsError> {
        if let Some(server) = &options.server {
            return Ok(server);
        }

        match &options.target.0 {
            Host::IPv4(_) | Host::IPv6(_) => Ok(&self.ip),
            Host::Domain(domain) => self
                .get_server_by_tld(domain.as_str())
                .ok_or(WhoIsError::MapError("No whois server is known for this kind of object.")),
        }
    }

    fn lookup_once(
        server: &WhoIsServerValue,
        text: &str,
        options: &WhoIsLookupOptions,
    ) -> Result<Vec<u8>, WhoIsError> {
        let addr = server.host.to_addr_string(DEFAULT_WHOIS_HOST_PORT);
        let request = build_request(server, text);

        match options.timeout {
            Some(timeout) => {
                let deadline = Deadline::new(timeout);

                let socket_addrs: Vec<SocketAddr> = addr.to_socket_addrs()?.collect();

                let mut client = connect(&socket_addrs, &deadline)?;

                client.set_write_timeout(Some(deadline.remaining()?))?;
                client.write_all(request.as_bytes())?;
                client.flush()?;

                Ok(read_response(&mut client, options.max_response_size, Some(&deadline))?)
            },
            None => {
                let mut client = TcpStream::connect(&addr)?;

                client.write_all(request.as_bytes())?;
                client.flush()?;

                Ok(read_response(&mut client, options.max_response_size, None)?)
            },
        }
    }

    fn lookup_inner(
        &self,
        server: &WhoIsServerValue,
        options: &WhoIsLookupOptions,
    ) -> Result<Vec<u8>, WhoIsError> {
        let host = &options.target.0;
        let mut follow = options.follow;
        let mut server = Cow::Borrowed(server);

        let text = query_text(&server, host);
        let mut query_result = Self::lookup_once(&server, text.as_ref(), options)?;

        while follow > 0 {
            let Some(referral) = extract_referral_host(&query_result)
                .and_then(|h| WhoIsServerValue::from_string(h).ok())
            else {
                break;
            };

            // The referral may carry a port, so compare the host alone to stop a server which refers to itself.
            if same_host(referral.host.host(), server.host.host()) {
                break;
            }

            server = match self.get_server_by_host(&referral.host) {
                Some(server) => Cow::Borrowed(server),
                None => Cow::Owned(referral),
            };

            let text = query_text(&server, host);

            query_result = Self::lookup_once(&server, text.as_ref(), options)?;

            follow -= 1;
        }

        Ok(query_result)
    }

    /// Lookup a domain or an IP, returning the raw bytes of the final WHOIS response without decoding.
    #[inline]
    pub fn lookup_raw(&self, options: WhoIsLookupOptions) -> Result<Vec<u8>, WhoIsError> {
        let server = self.get_server(&options)?;

        self.lookup_inner(server, &options)
    }

    /// Lookup a domain or an IP.
    pub fn lookup(&self, options: WhoIsLookupOptions) -> Result<String, WhoIsError> {
        let server = self.get_server(&options)?;

        let query_result = self.lookup_inner(server, &options)?;

        Ok(decode_response(query_result, tld_hint(&options.target.0).as_deref()))
    }
}

#[cfg(feature = "tokio")]
impl WhoIs {
    async fn lookup_once_async(
        server: &WhoIsServerValue,
        text: &str,
        options: &WhoIsLookupOptions,
    ) -> Result<Vec<u8>, WhoIsError> {
        let addr = server.host.to_addr_string(DEFAULT_WHOIS_HOST_PORT);
        let request = build_request(server, text);

        match options.timeout {
            Some(timeout) => {
                let deadline = Deadline::new(timeout);

                // Resolving has to go through tokio as well, because the blocking resolver would stall the whole runtime.
                let socket_addrs: Vec<SocketAddr> =
                    tokio::time::timeout(deadline.remaining()?, tokio::net::lookup_host(&addr))
                        .await??
                        .collect();

                let mut client = connect_async(&socket_addrs, &deadline).await?;

                tokio::time::timeout(deadline.remaining()?, client.write_all(request.as_bytes()))
                    .await??;
                tokio::time::timeout(deadline.remaining()?, client.flush()).await??;

                Ok(tokio::time::timeout(
                    deadline.remaining()?,
                    read_response_async(&mut client, options.max_response_size),
                )
                .await??)
            },
            None => {
                let mut client = tokio::net::TcpStream::connect(&addr).await?;

                client.write_all(request.as_bytes()).await?;
                client.flush().await?;

                Ok(read_response_async(&mut client, options.max_response_size).await?)
            },
        }
    }

    async fn lookup_inner_async(
        &self,
        server: &WhoIsServerValue,
        options: &WhoIsLookupOptions,
    ) -> Result<Vec<u8>, WhoIsError> {
        let host = &options.target.0;
        let mut follow = options.follow;
        let mut server = Cow::Borrowed(server);

        let text = query_text(&server, host);
        let mut query_result = Self::lookup_once_async(&server, text.as_ref(), options).await?;

        while follow > 0 {
            let Some(referral) = extract_referral_host(&query_result)
                .and_then(|h| WhoIsServerValue::from_string(h).ok())
            else {
                break;
            };

            // The referral may carry a port, so compare the host alone to stop a server which refers to itself.
            if same_host(referral.host.host(), server.host.host()) {
                break;
            }

            server = match self.get_server_by_host(&referral.host) {
                Some(server) => Cow::Borrowed(server),
                None => Cow::Owned(referral),
            };

            let text = query_text(&server, host);

            query_result = Self::lookup_once_async(&server, text.as_ref(), options).await?;

            follow -= 1;
        }

        Ok(query_result)
    }

    /// Lookup a domain or an IP, returning the raw bytes of the final WHOIS response without decoding.
    #[inline]
    pub async fn lookup_raw_async(
        &self,
        options: WhoIsLookupOptions,
    ) -> Result<Vec<u8>, WhoIsError> {
        let server = self.get_server(&options)?;

        self.lookup_inner_async(server, &options).await
    }

    /// Lookup a domain or an IP.
    pub async fn lookup_async(&self, options: WhoIsLookupOptions) -> Result<String, WhoIsError> {
        let server = self.get_server(&options)?;

        let query_result = self.lookup_inner_async(server, &options).await?;

        Ok(decode_response(query_result, tld_hint(&options.target.0).as_deref()))
    }
}

#[cfg(test)]
mod tests {
    use validators::models::Host;

    use super::{build_request, decode_response, extract_referral_host, tld_hint};
    use crate::WhoIsServerValue;

    #[test]
    fn extract_referral_host_trims_trailing_cr() {
        let body = b"Domain: example.com\r\nReferralServer: whois://whois.arin.net\r\n";

        assert_eq!(Some("whois.arin.net"), extract_referral_host(body));
    }

    #[test]
    fn extract_referral_host_ignores_non_utf8_body() {
        // The referral line is ASCII even when the rest of the response is in some other encoding.
        let body = b"\xB5n\xBFy: example.tw\r\nWhois Server: whois.twnic.net.tw\r\n";

        assert_eq!(Some("whois.twnic.net.tw"), extract_referral_host(body));
    }

    #[test]
    fn extract_referral_host_takes_the_first_token() {
        let body = b"   Registrar WHOIS Server: whois.example.com (see the note below)\r\n";

        assert_eq!(Some("whois.example.com"), extract_referral_host(body));
    }

    #[test]
    fn extract_referral_host_ignores_a_field_name_in_the_middle_of_a_line() {
        let body = b"Do not trust any Whois Server: which is not listed above.\r\n";

        assert_eq!(None, extract_referral_host(body));
    }

    #[test]
    fn tld_hint_takes_the_last_label() {
        assert_eq!(Some("tw"), tld_hint(&Host::Domain(String::from("magiclen.com.tw"))).as_deref());
        assert_eq!(Some("com"), tld_hint(&Host::Domain(String::from("magiclen.COM"))).as_deref());
        assert_eq!(None, tld_hint(&Host::IPv4("172.105.210.153".parse().unwrap())).as_deref());
    }

    #[test]
    fn build_request_ends_with_crlf() {
        let mut server = WhoIsServerValue::from_string("whois.example.com").unwrap();

        assert_eq!("magiclen.org\r\n", build_request(&server, "magiclen.org"));

        server.query = Some(String::from("domain $addr\r\n"));
        assert_eq!("domain magiclen.org\r\n", build_request(&server, "magiclen.org"));

        // A query which is terminated with LF alone, or not terminated at all, is fixed up.
        server.query = Some(String::from("domain $addr\n"));
        assert_eq!("domain magiclen.org\r\n", build_request(&server, "magiclen.org"));

        server.query = Some(String::from("domain $addr"));
        assert_eq!("domain magiclen.org\r\n", build_request(&server, "magiclen.org"));
    }

    #[test]
    fn decode_response_passes_through_utf8() {
        assert_eq!("café", decode_response("café".as_bytes().to_vec(), None));
    }

    // "café" with `é` as the single byte 0xE9 (Windows-1252 / ISO-8859-1).
    #[cfg(feature = "charset")]
    #[test]
    fn decode_response_detects_windows_1252() {
        assert_eq!("café", decode_response(vec![b'c', b'a', b'f', 0xE9], None));
    }

    #[cfg(not(feature = "charset"))]
    #[test]
    fn decode_response_is_lossy_without_charset() {
        assert_eq!("caf\u{FFFD}", decode_response(vec![b'c', b'a', b'f', 0xE9], None));
    }
}
