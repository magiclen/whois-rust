WHOIS Rust
====================

[![Build Status](https://travis-ci.org/magiclen/whois-rust.svg?branch=master)](https://travis-ci.org/magiclen/whois-rust)
[![Build status](https://ci.appveyor.com/api/projects/status/jrlc14e3dbbn8tv9/branch/master?svg=true)](https://ci.appveyor.com/project/magiclen/whois-rust/branch/master)

This is a WHOIS client library for Rust, inspired by https://github.com/hjr265/node-whois

## Usage

You can make a **servers.json** file or copy one from https://github.com/hjr265/node-whois

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
extern crate whois_rust;

use whois_rust::WhoIs;

let whois = WhoIs::from_path("/path/to/servers.json").unwrap();
```

Use the `lookup` method and input a `WhoIsLookupOptions` instance to lookup a domain or an IP.

```rust
extern crate whois_rust;

use whois_rust::{WhoIs, WhoIsLookupOptions};

let whois = WhoIs::from_path("/path/to/servers.json").unwrap();

let result: String = whois.lookup(WhoIsLookupOptions::from_string("magiclen.org").unwrap()).unwrap();
```

## Crates.io

https://crates.io/crates/whois-rust

## Documentation

https://docs.rs/whois-rust

## License

[MIT](LICENSE)