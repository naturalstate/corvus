// ©AngelaMos | 2026
// ja4_suite.rs

use tlsfp_core::ja4::{Transport, ja4s};
use tlsfp_core::ja4h::{ja4h, parse_http_request};
use tlsfp_core::parse::parse_server_hello;

/// Builds the ServerHello behind the FoxIO JA4S example: TLS 1.3 selected via the
/// supported versions extension, the cipher 0x1301, and two extensions in the
/// order key share then supported versions.
fn foxio_server_hello() -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&0x0303u16.to_be_bytes());
    body.extend_from_slice(&[0u8; 32]);
    body.push(0);
    body.extend_from_slice(&0x1301u16.to_be_bytes());
    body.push(0);

    let mut exts = Vec::new();
    exts.extend_from_slice(&0x0033u16.to_be_bytes());
    exts.extend_from_slice(&0u16.to_be_bytes());
    exts.extend_from_slice(&0x002bu16.to_be_bytes());
    exts.extend_from_slice(&2u16.to_be_bytes());
    exts.extend_from_slice(&0x0304u16.to_be_bytes());

    body.extend_from_slice(&u16::try_from(exts.len()).unwrap().to_be_bytes());
    body.extend_from_slice(&exts);
    body
}

#[test]
fn ja4s_reproduces_foxio_example() {
    let body = foxio_server_hello();
    let sh = parse_server_hello(&body).unwrap();
    let fp = ja4s(&sh, Transport::Tcp);
    assert_eq!(fp.hash, "t130200_1301_234ea6891581");
    assert_eq!(fp.raw, "t130200_1301_0033,002b");
}

/// The published JA4H example for a request with four uppercase headers, no
/// cookies, no referer, and no accept language. The header hash is the SHA256 of
/// the comma joined header names in wire order.
#[test]
fn ja4h_reproduces_published_example() {
    let raw = b"GET * HTTP/1.1\r\nHOST: a\r\nMAN: b\r\nMX: c\r\nST: d\r\n\r\n";
    let req = parse_http_request(raw).unwrap();
    let fp = ja4h(&req);
    assert_eq!(
        fp.hash,
        "ge11nn040000_a3c882e23515_000000000000_000000000000"
    );
}

/// Cookies and a referer must flip their flags and stop being counted as plain
/// headers, while the accept language must populate the language characters.
#[test]
fn ja4h_flags_cookies_referer_and_language() {
    let raw = b"GET / HTTP/1.1\r\nHost: x\r\nAccept-Language: en-US,en;q=0.9\r\nReferer: http://x\r\nCookie: a=1; b=2\r\n\r\n";
    let req = parse_http_request(raw).unwrap();
    let fp = ja4h(&req);
    let prefix = fp.hash.split('_').next().unwrap();
    assert_eq!(prefix, "ge11cr02enus");
    assert!(!fp.hash.contains("_000000000000_000000000000"));
}
