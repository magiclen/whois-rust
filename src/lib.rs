/*!
# WHOIS Rust

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

```rust,ignore
extern crate whois_rust;

use whois_rust::WhoIs;

let whois = WhoIs::from_path("/path/to/servers.json").unwrap();
```

Use the `lookup` method and input a `WhoIsLookupOptions` instance to lookup a domain or an IP.

```rust,ignore
extern crate whois_rust;

use whois_rust::{WhoIs, WhoIsLookupOptions};

let whois = WhoIs::from_path("/path/to/servers.json").unwrap();

let result: String = whois.lookup(WhoIsLookupOptions::from_string("magiclen.org").unwrap()).unwrap();
```

## Asynchronous APIs

You may want to use async APIs with your async runtime. This crate supports `tokio`, currently.

```toml
[dependencies.whois-rust]
version = "*"
features = ["tokio"]
```

After enabling the async feature, the `from_path_async` function and the `lookup_async` function are available.

## Testing

```bash
git clone --recurse-submodules git://github.com/magiclen/whois-rust.git

cd whois-rust

cargo test
```
*/

#[macro_use]
extern crate validators_derive;

extern crate validators;

extern crate serde_json;

#[cfg(feature = "tokio")]
pub extern crate tokio;

mod target;
mod who_is;
mod who_is_error;
mod who_is_host;
mod who_is_lookup_options;
mod who_is_server_value;

pub use target::*;
pub use who_is::*;
pub use who_is_error::*;
pub use who_is_host::*;
pub use who_is_lookup_options::*;
pub use who_is_server_value::*;
