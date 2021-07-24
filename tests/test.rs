extern crate tokio;
extern crate whois_rust;

use whois_rust::*;

#[test]
fn test() {
    let who = WhoIs::from_path("node-whois/servers.json").unwrap();

    let result = who.lookup(WhoIsLookupOptions::from_string("magiclen.org").unwrap()).unwrap();
    println!("{}", result);

    let result = who.lookup(WhoIsLookupOptions::from_string("66.42.43.17").unwrap()).unwrap();
    println!("{}", result);

    let result =
        who.lookup(WhoIsLookupOptions::from_string("fe80::5400:1ff:feaf:b71").unwrap()).unwrap();
    println!("{}", result);
}

#[test]
fn test_srv() {
    let mut who = WhoIs::from_host("whois.arin.net").unwrap();
    who.can_find_server_for_tld(".lotteryusa.us");

    let result = who.lookup(WhoIsLookupOptions::from_string("lotteryusa.us").unwrap()).unwrap();
    println!("{}", result);

    let result = who.lookup(WhoIsLookupOptions::from_string("66.42.43.17").unwrap()).unwrap();
    println!("{}", result);

    let result =
        who.lookup(WhoIsLookupOptions::from_string("fe80::5400:1ff:feaf:b71").unwrap()).unwrap();
    println!("{}", result);
}

#[cfg(feature = "tokio")]
#[tokio::test]
async fn test_async() {
    let who = WhoIs::from_path_async("node-whois/servers.json").await.unwrap();

    let result =
        who.lookup_async(WhoIsLookupOptions::from_string("magiclen.org").unwrap()).await.unwrap();
    println!("{}", result);

    let result =
        who.lookup_async(WhoIsLookupOptions::from_string("66.42.43.17").unwrap()).await.unwrap();
    println!("{}", result);

    let result = who
        .lookup_async(WhoIsLookupOptions::from_string("fe80::5400:1ff:feaf:b71").unwrap())
        .await
        .unwrap();
    println!("{}", result);
}
