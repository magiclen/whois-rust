extern crate whois_rust;

use whois_rust::*;

#[test]
fn test() {
    let who = WhoIs::from_path("tests/data/servers.json").unwrap();

    let result = who.lookup(WhoIsLookupOptions::from_string("magiclen.org").unwrap()).unwrap();

    println!("{}", result);
}