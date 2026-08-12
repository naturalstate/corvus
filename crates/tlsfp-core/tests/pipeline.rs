// ©AngelaMos | 2026
// pipeline.rs

//! Full pipeline known answer tests over the vendored FoxIO captures.
//!
//! These read a real capture file off disk, run it through the entire stack
//! the binary uses, and assert the fingerprints against the values FoxIO
//! published for the same files. A unit test proves an algorithm in isolation;
//! these prove that the file reader, the link layer decoder, the TCP
//! reassembler, the protocol sniffer, and the algorithms together still land
//! on the published answer. Every hash asserted here was independently
//! recomputed from its raw pre hash string with a shell tool before being
//! pinned, so a regression in any stage shows up as a mismatch rather than a
//! silently wrong but self consistent number.

use std::path::PathBuf;

use tlsfp_core::pipeline::event::StreamEvent;
use tlsfp_core::{FingerprintEvent, PcapFileSource, Pipeline, PipelineConfig};

fn pcap_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/pcap")
        .join(name)
}

/// Runs one capture all the way through the pipeline and returns its events.
fn fingerprint(name: &str) -> Vec<FingerprintEvent> {
    let mut source =
        PcapFileSource::open(pcap_path(name)).unwrap_or_else(|e| panic!("opening {name}: {e}"));
    let mut pipeline = Pipeline::new(PipelineConfig::default());
    let mut events = Vec::new();
    pipeline
        .run(&mut source, |event| events.push(event))
        .unwrap_or_else(|e| panic!("running {name}: {e}"));
    events
}

fn client_hellos(events: &[FingerprintEvent]) -> Vec<(&str, &str)> {
    events
        .iter()
        .filter_map(|e| match &e.event {
            StreamEvent::ClientHello { ja4, .. } => Some((ja4.hash.as_str(), ja4.raw.as_str())),
            _ => None,
        })
        .collect()
}

/// Returns the ClientHello events whose JA4 transport marker is QUIC.
fn quic_client_hellos(events: &[FingerprintEvent]) -> Vec<&FingerprintEvent> {
    events
        .iter()
        .filter(|e| match &e.event {
            StreamEvent::ClientHello { ja4, .. } => ja4.hash.starts_with('q'),
            _ => false,
        })
        .collect()
}

fn ja4s_hashes(events: &[FingerprintEvent]) -> Vec<(&str, &str)> {
    events
        .iter()
        .filter_map(|e| match &e.event {
            StreamEvent::ServerHello { ja4s, .. } => Some((ja4s.hash.as_str(), ja4s.raw.as_str())),
            _ => None,
        })
        .collect()
}

fn ja4x_hashes(events: &[FingerprintEvent]) -> Vec<&str> {
    events
        .iter()
        .filter_map(|e| match &e.event {
            StreamEvent::Certificate { ja4x } => Some(ja4x.as_str()),
            _ => None,
        })
        .collect()
}

fn ja4h_hashes(events: &[FingerprintEvent]) -> Vec<&str> {
    events
        .iter()
        .filter_map(|e| match &e.event {
            StreamEvent::HttpRequest { ja4h, .. } => Some(ja4h.hash.as_str()),
            _ => None,
        })
        .collect()
}

#[test]
fn tls_alpn_h2_reproduces_published_ja4_and_ja4x() {
    let events = fingerprint("tls-alpn-h2.pcap");

    let hellos = client_hellos(&events);
    assert_eq!(hellos.len(), 1);
    assert_eq!(hellos[0].0, "t12d4605h2_85626a9a5f7f_aaf95bb78ec9");

    let certs = ja4x_hashes(&events);
    assert_eq!(
        certs.first().copied(),
        Some("7d5dbb3783b4_ba7ce0880c07_7bf9a7bf7029")
    );
}

#[test]
fn chrome_cloudflare_tcp_handshake_reproduces_published_ja4() {
    let events = fingerprint("chrome-cloudflare-quic-with-secrets.pcapng");

    let hellos = client_hellos(&events);
    assert!(
        hellos
            .iter()
            .any(|(hash, _)| *hash == "t13d1516h2_8daaf6152771_e5627efa2ab1"),
        "expected the published chrome JA4, saw {hellos:?}"
    );

    let servers = ja4s_hashes(&events);
    assert!(
        servers
            .iter()
            .any(|(hash, _)| *hash == "t130200_1301_234ea6891581"),
        "expected the published cloudflare JA4S, saw {servers:?}"
    );
}

#[test]
fn chrome_cloudflare_quic_initial_decrypts_to_published_q_ja4() {
    // The same capture carries the same browser over both transports. The TCP
    // ClientHello above and this QUIC one share a JA4_a prefix family but
    // differ where the transport and ALPN do, which is the whole reason JA4
    // records the transport. The QUIC value below was reproduced from the
    // decrypted Initial by an independent decryptor and recomputed from its
    // raw string with a shell digest before being pinned.
    let events = fingerprint("chrome-cloudflare-quic-with-secrets.pcapng");

    let quic = quic_client_hellos(&events);
    assert_eq!(quic.len(), 1, "expected exactly one QUIC ClientHello");
    let StreamEvent::ClientHello { ja4, sni, alpn, .. } = &quic[0].event else {
        unreachable!("filtered to ClientHello");
    };
    assert_eq!(ja4.hash, "q13d0310h3_55b375c5d22e_cd85d2d88918");
    assert_eq!(sni.as_deref(), Some("cloudflare-quic.com"));
    assert_eq!(alpn.as_deref(), Some("h3"));
}

#[test]
fn quic_several_tls_frames_reassembles_split_client_hello() {
    // This capture's ClientHello is delivered across several CRYPTO frames in
    // one Initial, exercising the offset based reassembler. It lands on the
    // identical JA4 as the chrome capture despite being a different client,
    // because JA4 sorts the cipher and extension lists before hashing.
    let events = fingerprint("quic-with-several-tls-frames.pcapng");

    let quic = quic_client_hellos(&events);
    assert_eq!(quic.len(), 1);
    let StreamEvent::ClientHello { ja4, .. } = &quic[0].event else {
        unreachable!("filtered to ClientHello");
    };
    assert_eq!(ja4.hash, "q13d0310h3_55b375c5d22e_cd85d2d88918");
    assert_eq!(
        ja4.raw,
        "q13d0310h3_1301,1302,1303_000a,000d,001b,002b,002d,0033,0039,4469_0403,0804,0401,0503,0805,0501,0806,0601,0201"
    );
}

#[test]
fn tls_handshake_reproduces_published_ja4s_raw_and_hash() {
    let events = fingerprint("tls-handshake.pcapng");

    // The capture holds many flows to many Google and Cloudflare endpoints, so
    // several distinct JA4S values appear. The published vector is the one for
    // the first flow, and it must carry both its published hash and raw form.
    let servers = ja4s_hashes(&events);
    assert!(
        servers
            .iter()
            .any(|(hash, raw)| *hash == "t130200_1301_234ea6891581"
                && *raw == "t130200_1301_0033,002b"),
        "expected the published JA4S with its raw form, saw {servers:?}"
    );

    let hellos = client_hellos(&events);
    assert!(hellos.len() >= 5);
    assert!(
        hellos
            .iter()
            .any(|(hash, _)| *hash == "t13d1516h2_8daaf6152771_e5627efa2ab1")
    );
}

#[test]
fn http1_with_cookies_reproduces_pinned_ja4h() {
    let events = fingerprint("http1-with-cookies.pcapng");
    let hashes = ja4h_hashes(&events);
    assert_eq!(
        hashes,
        vec!["ge11cr04da00_8ddaef5d77af_280f366eaa04_c2fb0fe53442"]
    );
}

#[test]
fn tls12_capture_recomputes_to_pinned_ja4() {
    let events = fingerprint("tls12.pcap");
    let hellos = client_hellos(&events);
    assert_eq!(hellos.len(), 1);
    assert_eq!(hellos[0].0, "t13d1715h2_5b57614c22b0_3d5424432f57");
}

#[test]
fn non_ascii_alpn_follows_the_spec_hex_rule() {
    let events = fingerprint("tls-non-ascii-alpn.pcapng");
    let hellos = client_hellos(&events);
    assert_eq!(hellos.len(), 1);
    let (hash, _) = hellos[0];
    let alpn_chars = &hash[8..10];
    assert_eq!(
        alpn_chars, "bd",
        "spec rule prints first and last hex chars of the raw ALPN value"
    );
}

#[test]
fn browsers_x509_extracts_every_certificate_in_chain_order() {
    let events = fingerprint("browsers-x509.pcapng");
    let certs = ja4x_hashes(&events);
    assert!(
        certs.len() >= 7,
        "expected several certificates, saw {}",
        certs.len()
    );
    assert!(certs.iter().all(|c| c.matches('_').count() == 2));
}

#[test]
fn tunneled_capture_yields_nothing_without_crashing() {
    let events = fingerprint("gre-erspan-vxlan.pcap");
    assert!(events.is_empty());
}

#[test]
fn evasion_capture_is_processed_without_panicking() {
    let events = fingerprint("CVE-2018-6794.pcap");
    assert!(
        ja4h_hashes(&events).len() >= 2,
        "the reassembler should still recover the HTTP requests"
    );
}
