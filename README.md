WHOIS Rust
====================

[![CI](https://github.com/magiclen/whois-rust/actions/workflows/ci.yml/badge.svg)](https://github.com/magiclen/whois-rust/actions/workflows/ci.yml)

This is a WHOIS client library for Rust, inspired by <https://github.com/hjr265/node-whois>

## Usage

You can make a **servers.json** file or copy one from <https://github.com/hjr265/node-whois>

This is a simple example of **servers.json**.

```json
{
    "org": "whois.pir.org",
    "": "whois.ripe.net",
    "_": {
        "ip": {
            "host": "whois.arin.net",
            "query": "n + $addr\r\n"
        }
    }
}
```

Then, use the `from_path` (or `from_string` if your JSON data is in-memory) associated function to create a `WhoIs` instance.

```rust
use whois_rust::WhoIs;

let whois = WhoIs::from_path("/path/to/servers.json").unwrap();
```

Use the `lookup` method and input a `WhoIsLookupOptions` instance to lookup a domain or an IP.

```rust
use whois_rust::{WhoIs, WhoIsLookupOptions};

let whois = WhoIs::from_path("/path/to/servers.json").unwrap();

let result: String = whois.lookup(WhoIsLookupOptions::from_string("magiclen.org").unwrap()).unwrap();
```

The `lookup` method decodes the WHOIS response into a `String`. When the response is not valid UTF-8, it is decoded using the `charset` feature (enabled by default). If you need the exact bytes instead, use the `lookup_raw` method, which returns a `Vec<u8>`.

A lookup follows the referral of a response up to `follow` times (2 by default). Each connection has its own `timeout` budget (60 seconds by default), so a lookup can take up to `follow + 1` times that value, and it accepts up to `max_response_size` bytes (4 MiB by default) instead of letting a broken or malicious server exhaust the memory. All of them can be changed through `WhoIsLookupOptions`.

This crate implements the WHOIS protocol as specified in [RFC 3912](https://datatracker.ietf.org/doc/html/rfc3912): a request is a single line terminated with CRLF sent to TCP port 43, and the response is over when the server closes the connection. WHOIS has no authentication and no encryption, and no way to tell the character encoding of a response, which is why this crate has to guess it.

## Asynchronous APIs

You may want to use async APIs with your async runtime. This crate supports `tokio`, currently.

```toml
[dependencies.whois-rust]
version = "*"
features = ["tokio"]
```

After enabling the async feature, the `from_path_async` function and the `lookup_async` function are available.

## Finding a WHOIS Server via DNS

The `can_find_server_for_tld` method looks a WHOIS server up through the `_nicname._tcp` SRV records of a TLD. It needs a DNS client, so it is put behind the `srv` feature, which is disabled by default.

```toml
[dependencies.whois-rust]
version = "*"
features = ["srv"]
```

The `can_find_server_for_tld_async` function is available when the `tokio` feature is enabled as well. The blocking `can_find_server_for_tld` method runs its DNS query on a thread of its own, so it works from inside an async runtime too, but the async function is the one to use there.

## Testing

```bash
# git clone --recurse-submodules https://github.com/magiclen/whois-rust.git

git clone https://github.com/magiclen/whois-rust.git

cd whois-rust

git submodule init
git submodule update --recursive

cargo test
```

## Crates.io

https://crates.io/crates/whois-rust

## Documentation

https://docs.rs/whois-rust

## License

[MIT](LICENSE)