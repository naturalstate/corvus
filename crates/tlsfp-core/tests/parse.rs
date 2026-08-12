// ©AngelaMos | 2026
// parse.rs

mod common;

use common::ClientHelloBuilder;
use proptest::prelude::*;
use tlsfp_core::parse::{
    first_handshake_message, handshake_bytes, parse_client_hello, parse_server_hello,
};
use tlsfp_core::registry::handshake_type;

fn sample() -> ClientHelloBuilder {
    ClientHelloBuilder::new()
        .ciphers(&[0x0a0a, 0x1301, 0x1302, 0x1303, 0xc02b])
        .sni("example.com")
        .supported_groups(&[0x1a1a, 0x001d, 0x0017])
        .ec_point_formats(&[0x00])
        .signature_algorithms(&[0x0403, 0x0804, 0x0401])
        .alpn(&[b"h2", b"http/1.1"])
        .supported_versions(&[0x2a2a, 0x0304, 0x0303])
}

#[test]
fn parses_every_field_a_fingerprint_reads() {
    let body = sample().build_body();
    let ch = parse_client_hello(&body).unwrap();

    assert_eq!(ch.legacy_version, 0x0303);
    assert_eq!(
        ch.cipher_suites.as_slice(),
        &[0x0a0a, 0x1301, 0x1302, 0x1303, 0xc02b]
    );
    assert_eq!(ch.extensions.len(), 6);
    assert_eq!(ch.server_name(), Some("example.com"));
    assert_eq!(ch.supported_groups().as_slice(), &[0x1a1a, 0x001d, 0x0017]);
    assert_eq!(ch.ec_point_formats().as_slice(), &[0x00]);
    assert_eq!(
        ch.signature_algorithms().as_slice(),
        &[0x0403, 0x0804, 0x0401]
    );
    assert_eq!(ch.alpn_protocols().first().copied(), Some(b"h2".as_slice()));
    assert_eq!(
        ch.supported_versions().as_slice(),
        &[0x2a2a, 0x0304, 0x0303]
    );
    assert!(!ch.is_sslv2);
}

#[test]
fn reads_client_hello_through_the_record_layer() {
    let stream = sample().build_record();
    let hs = handshake_bytes(&stream).unwrap();
    let body = first_handshake_message(&hs, handshake_type::CLIENT_HELLO).unwrap();
    let ch = parse_client_hello(body).unwrap();
    assert_eq!(ch.cipher_suites.len(), 5);
}

#[test]
fn server_hello_parses_single_cipher() {
    let mut body = Vec::new();
    body.extend_from_slice(&0x0303u16.to_be_bytes());
    body.extend_from_slice(&[0u8; 32]);
    body.push(0);
    body.extend_from_slice(&0x1301u16.to_be_bytes());
    body.push(0);
    body.extend_from_slice(&0u16.to_be_bytes());

    let sh = parse_server_hello(&body).unwrap();
    assert_eq!(sh.cipher_suite, 0x1301);
    assert_eq!(sh.legacy_version, 0x0303);
}

#[test]
fn client_hello_without_extensions_parses() {
    let body = ClientHelloBuilder::new()
        .ciphers(&[0x002f, 0x0035])
        .build_body();
    let body = &body[..body.len() - 2];
    let ch = parse_client_hello(body).unwrap();
    assert_eq!(ch.cipher_suites.as_slice(), &[0x002f, 0x0035]);
    assert!(ch.extensions.is_empty());
}

proptest! {
    #[test]
    fn parser_never_panics_on_arbitrary_bytes(bytes in proptest::collection::vec(any::<u8>(), 0..2048)) {
        let _ = parse_client_hello(&bytes);
        let _ = parse_server_hello(&bytes);
        if let Ok(hs) = handshake_bytes(&bytes) {
            let _ = first_handshake_message(&hs, handshake_type::CLIENT_HELLO);
        }
    }

    #[test]
    fn well_formed_prefix_with_random_extension_tail_is_stable(
        tail in proptest::collection::vec(any::<u8>(), 0..256)
    ) {
        let mut ch = ClientHelloBuilder::new().ciphers(&[0x1301, 0x1302]);
        ch = ch.extension(0xabcd, tail);
        let body = ch.build_body();
        let parsed = parse_client_hello(&body).unwrap();
        prop_assert_eq!(parsed.cipher_suites.as_slice(), &[0x1301, 0x1302]);
    }
}
