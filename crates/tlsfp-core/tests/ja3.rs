// ©AngelaMos | 2026
// ja3.rs

mod common;

use common::ClientHelloBuilder;
use tlsfp_core::ja3::{ja3, ja3_string};
use tlsfp_core::parse::parse_client_hello;

/// Rebuilds the exact ClientHello that produces the first published Salesforce
/// JA3 vector, then checks both the pre hash string and the digest end to end.
/// The SNI body content is arbitrary because JA3 records only that extension
/// type zero was present, not its value.
#[test]
fn end_to_end_matches_salesforce_vector_one() {
    let body = ClientHelloBuilder::new()
        .legacy_version(0x0301)
        .ciphers(&[47, 53, 5, 10, 49161, 49162, 49171, 49172, 50, 56, 19, 4])
        .extension(0x0000, vec![0x00, 0x00])
        .supported_groups(&[23, 24, 25])
        .ec_point_formats(&[0])
        .build_body();

    let ch = parse_client_hello(&body).unwrap();
    assert_eq!(
        ja3_string(&ch),
        "769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0"
    );
    assert_eq!(ja3(&ch).to_string(), "ada70206e40642a3e4461f35503241d5");
}

/// A ClientHello with GREASE in ciphers, extensions, and supported groups must
/// produce the same JA3 as the same hello without GREASE, because GREASE is
/// stripped from every list field before hashing.
#[test]
fn grease_does_not_change_the_fingerprint() {
    let clean = ClientHelloBuilder::new()
        .legacy_version(0x0303)
        .ciphers(&[0x1301, 0x1302])
        .supported_groups(&[0x001d, 0x0017])
        .ec_point_formats(&[0])
        .build_body();

    let greasy = ClientHelloBuilder::new()
        .legacy_version(0x0303)
        .ciphers(&[0x0a0a, 0x1301, 0x1302])
        .extension(0x1a1a, vec![])
        .supported_groups(&[0x2a2a, 0x001d, 0x0017])
        .ec_point_formats(&[0])
        .build_body();

    let clean = parse_client_hello(&clean).unwrap();
    let greasy = parse_client_hello(&greasy).unwrap();
    assert_eq!(ja3(&clean), ja3(&greasy));
}
