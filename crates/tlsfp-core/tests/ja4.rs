// ©AngelaMos | 2026
// ja4.rs

mod common;

use common::ClientHelloBuilder;
use tlsfp_core::ja4::{Transport, ja4};
use tlsfp_core::parse::parse_client_hello;

const FOXIO_HASH: &str = "t13d1516h2_8daaf6152771_e5627efa2ab1";
const FOXIO_RAW: &str = "t13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01_0403,0804,0401,0503,0805,0501,0806,0601";

const CIPHERS_ORIGINAL_ORDER: [u16; 15] = [
    0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c,
    0x009d, 0x002f, 0x0035,
];

const OPAQUE_EXTENSIONS: [u16; 10] = [
    0x0005, 0x0012, 0x0015, 0x0017, 0x001b, 0x0023, 0x002d, 0x0033, 0x4469, 0xff01,
];

const SIG_ALGS: [u16; 8] = [
    0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
];

/// Assembles the handshake body for the canonical FoxIO example.
///
/// The cipher suites are supplied out of order with an injected GREASE value, to
/// prove that sorting and GREASE removal happen before hashing. When `reversed`
/// is set the opaque extensions are added in reverse, which must not change the
/// fingerprint because JA4 sorts the extension list.
fn foxio_body(reversed: bool) -> Vec<u8> {
    let mut ciphers = vec![0x0a0a];
    ciphers.extend_from_slice(&CIPHERS_ORIGINAL_ORDER);

    let mut builder = ClientHelloBuilder::new()
        .ciphers(&ciphers)
        .sni("example.com")
        .supported_groups(&[0x001d, 0x0017])
        .ec_point_formats(&[0x00])
        .signature_algorithms(&SIG_ALGS)
        .alpn(&[b"h2"])
        .supported_versions(&[0x2a2a, 0x0304, 0x0303]);

    if reversed {
        for ext in OPAQUE_EXTENSIONS.iter().rev() {
            builder = builder.extension(*ext, vec![]);
        }
    } else {
        for ext in OPAQUE_EXTENSIONS {
            builder = builder.extension(ext, vec![]);
        }
    }

    builder.build_body()
}

#[test]
fn reproduces_foxio_canonical_example() {
    let body = foxio_body(false);
    let ch = parse_client_hello(&body).unwrap();
    let fp = ja4(&ch, Transport::Tcp);
    assert_eq!(fp.raw, FOXIO_RAW);
    assert_eq!(fp.hash, FOXIO_HASH);
}

#[test]
fn extension_order_does_not_change_the_hash() {
    let normal = foxio_body(false);
    let reversed = foxio_body(true);
    let normal = parse_client_hello(&normal).unwrap();
    let reversed = parse_client_hello(&reversed).unwrap();
    assert_eq!(
        ja4(&normal, Transport::Tcp).hash,
        ja4(&reversed, Transport::Tcp).hash
    );
}

#[test]
fn transport_marker_switches_first_character() {
    let body = foxio_body(false);
    let ch = parse_client_hello(&body).unwrap();
    let tcp = ja4(&ch, Transport::Tcp);
    let quic = ja4(&ch, Transport::Quic);
    assert!(tcp.hash.starts_with('t'));
    assert!(quic.hash.starts_with('q'));
    assert_eq!(&tcp.hash[1..], &quic.hash[1..]);
}
