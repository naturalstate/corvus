// ©AngelaMos | 2026
// detect.rs

//! End to end tests for the detection engine.
//!
//! Each test drives a short sequence of hand built fingerprint events through a
//! store and checks that the right rule fires, and just as importantly that the
//! quiet cases stay quiet. The events are synthetic on purpose: the engine
//! consumes events, not packets, so building them directly is the honest seam
//! to test the rules at.

use tlsfp_core::fingerprint::{Ja3, Ja4Family};
use tlsfp_core::{FingerprintEvent, StreamEvent};
use tlsfp_intel::{AlertSeverity, DetectConfig, IntelStore, Rule};

const CURL_JA4: &str = "t13d1234h1_aaaaaaaaaaaa_bbbbbbbbbbbb";
const MALWARE_JA4: &str = "t10d070600_c50f5591e341_1a3805c3aa63";
const CHROME_JA4: &str = "t13d1516h2_8daaf6152771_e5627efa2ab1";
const BROWSER_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36";
const CURL_UA: &str = "curl/8.4.0";
const UNIX_JA4T: &str = "29200_2-4-8-1-3_1424_7";
const WINDOWS_JA4T: &str = "64240_2-1-3-1-1-4_1460_8";

const FEED: &str = r#"[
  {"application":"Chrome","os":"Windows","ja4_fingerprint":"t13d1516h2_8daaf6152771_e5627efa2ab1"},
  {"application":"curl","library":"OpenSSL","ja4_fingerprint":"t13d1234h1_aaaaaaaaaaaa_bbbbbbbbbbbb"},
  {"application":"Loader","notes":"known malware stealer","ja4_fingerprint":"t10d070600_c50f5591e341_1a3805c3aa63"}
]"#;

fn store() -> IntelStore {
    let mut store = IntelStore::open_in_memory().unwrap();
    store.import_ja4db(FEED).unwrap();
    store
}

fn cfg() -> DetectConfig {
    DetectConfig {
        window_secs: 86_400,
        rotation_threshold: 2,
        monoculture_threshold: 2,
    }
}

fn client_hello(ip: &str, ts: u64, ja4: &str) -> FingerprintEvent {
    FingerprintEvent {
        ts_nanos: ts,
        src: format!("{ip}:1000").parse().unwrap(),
        dst: "10.0.0.250:443".parse().unwrap(),
        event: StreamEvent::ClientHello {
            ja3: Ja3::from_digest([0u8; 16]),
            ja3_raw: "raw".into(),
            ja4: Ja4Family::new(ja4.into(), "raw".into()),
            sni: None,
            alpn: None,
        },
    }
}

fn http_request(ip: &str, ts: u64, ua: &str) -> FingerprintEvent {
    FingerprintEvent {
        ts_nanos: ts,
        src: format!("{ip}:1000").parse().unwrap(),
        dst: "10.0.0.250:80".parse().unwrap(),
        event: StreamEvent::HttpRequest {
            ja4h: Ja4Family::new(
                "ge20nn000000_000000000000_000000000000".into(),
                "raw".into(),
            ),
            method: "GET".into(),
            host: Some("example.com".into()),
            user_agent: Some(ua.into()),
        },
    }
}

fn tcp_syn(ip: &str, ts: u64, ja4t: &str) -> FingerprintEvent {
    FingerprintEvent {
        ts_nanos: ts,
        src: format!("{ip}:1000").parse().unwrap(),
        dst: "10.0.0.250:443".parse().unwrap(),
        event: StreamEvent::TcpSyn { ja4t: ja4t.into() },
    }
}

fn fires(alerts: &[tlsfp_intel::Alert], rule: Rule) -> bool {
    alerts.iter().any(|alert| alert.rule == rule)
}

#[test]
fn known_bad_fires_on_malicious_fingerprint() {
    let mut store = store();
    let alerts = store
        .detect_with(
            &client_hello("10.0.0.1", 1_000_000_000, MALWARE_JA4),
            &cfg(),
        )
        .unwrap();
    let known_bad = alerts
        .iter()
        .find(|alert| alert.rule == Rule::KnownBad)
        .expect("a malicious fingerprint should raise known_bad");
    assert_eq!(known_bad.severity, AlertSeverity::High);
    assert!(known_bad.detail.contains("Loader"));
    assert!(known_bad.detail.contains("prevalence"));
    assert_eq!(known_bad.score, Some(1.0));
}

#[test]
fn known_bad_does_not_refire_for_the_same_address_and_fingerprint() {
    let mut store = store();
    let config = cfg();
    let first = store
        .detect_with(
            &client_hello("10.0.0.1", 1_000_000_000, MALWARE_JA4),
            &config,
        )
        .unwrap();
    let second = store
        .detect_with(
            &client_hello("10.0.0.1", 2_000_000_000, MALWARE_JA4),
            &config,
        )
        .unwrap();
    let other = store
        .detect_with(
            &client_hello("10.0.0.99", 3_000_000_000, MALWARE_JA4),
            &config,
        )
        .unwrap();
    assert!(fires(&first, Rule::KnownBad));
    assert!(!fires(&second, Rule::KnownBad));
    assert!(fires(&other, Rule::KnownBad));
}

#[test]
fn ua_mismatch_browser_claim_over_tool_handshake() {
    let mut store = store();
    let config = cfg();
    store
        .detect_with(&client_hello("10.0.0.2", 1_000_000_000, CURL_JA4), &config)
        .unwrap();
    let alerts = store
        .detect_with(
            &http_request("10.0.0.2", 2_000_000_000, BROWSER_UA),
            &config,
        )
        .unwrap();
    let mismatch = alerts
        .iter()
        .find(|alert| alert.rule == Rule::UaMismatch)
        .expect("a browser User-Agent over a curl handshake is the headline mismatch");
    assert_eq!(mismatch.severity, AlertSeverity::High);
    assert!(mismatch.detail.to_lowercase().contains("curl"));
    assert!(mismatch.title.to_lowercase().contains("chrome"));
}

#[test]
fn ua_mismatch_fires_from_the_tls_side_too() {
    let mut store = store();
    let config = cfg();
    store
        .detect_with(
            &http_request("10.0.0.3", 1_000_000_000, BROWSER_UA),
            &config,
        )
        .unwrap();
    let alerts = store
        .detect_with(&client_hello("10.0.0.3", 2_000_000_000, CURL_JA4), &config)
        .unwrap();
    assert!(fires(&alerts, Rule::UaMismatch));
}

#[test]
fn an_honest_tool_user_agent_does_not_mismatch() {
    let mut store = store();
    let config = cfg();
    store
        .detect_with(&client_hello("10.0.0.4", 1_000_000_000, CURL_JA4), &config)
        .unwrap();
    let alerts = store
        .detect_with(&http_request("10.0.0.4", 2_000_000_000, CURL_UA), &config)
        .unwrap();
    assert!(!fires(&alerts, Rule::UaMismatch));
}

#[test]
fn a_real_browser_does_not_mismatch_its_own_handshake() {
    let mut store = store();
    let config = cfg();
    store
        .detect_with(
            &client_hello("10.0.0.5", 1_000_000_000, CHROME_JA4),
            &config,
        )
        .unwrap();
    let alerts = store
        .detect_with(
            &http_request("10.0.0.5", 2_000_000_000, BROWSER_UA),
            &config,
        )
        .unwrap();
    assert!(!fires(&alerts, Rule::UaMismatch));
}

#[test]
fn os_mismatch_windows_claim_over_unix_stack() {
    let mut store = store();
    let config = cfg();
    store
        .detect_with(&tcp_syn("10.0.0.6", 1_000_000_000, UNIX_JA4T), &config)
        .unwrap();
    let alerts = store
        .detect_with(
            &http_request("10.0.0.6", 2_000_000_000, BROWSER_UA),
            &config,
        )
        .unwrap();
    let mismatch = alerts
        .iter()
        .find(|alert| alert.rule == Rule::OsMismatch)
        .expect("a Windows User-Agent over a Unix SYN should raise os_mismatch");
    assert_eq!(mismatch.severity, AlertSeverity::Medium);
    assert!(mismatch.title.contains("windows"));
    assert!(mismatch.title.contains("unix"));
}

#[test]
fn os_mismatch_fires_from_the_syn_side_too() {
    let mut store = store();
    let config = cfg();
    store
        .detect_with(
            &http_request("10.0.0.7", 1_000_000_000, BROWSER_UA),
            &config,
        )
        .unwrap();
    let alerts = store
        .detect_with(&tcp_syn("10.0.0.7", 2_000_000_000, UNIX_JA4T), &config)
        .unwrap();
    assert!(fires(&alerts, Rule::OsMismatch));
}

#[test]
fn a_consistent_operating_system_does_not_mismatch() {
    let mut store = store();
    let config = cfg();
    store
        .detect_with(&tcp_syn("10.0.0.8", 1_000_000_000, WINDOWS_JA4T), &config)
        .unwrap();
    let alerts = store
        .detect_with(
            &http_request("10.0.0.8", 2_000_000_000, BROWSER_UA),
            &config,
        )
        .unwrap();
    assert!(!fires(&alerts, Rule::OsMismatch));
}

#[test]
fn first_seen_fires_once_per_fingerprint() {
    let mut store = store();
    let config = cfg();
    let first = store
        .detect_with(
            &client_hello("10.0.0.9", 1_000_000_000, CHROME_JA4),
            &config,
        )
        .unwrap();
    assert!(fires(&first, Rule::FirstSeen));
    let again = store
        .detect_with(
            &client_hello("10.0.0.10", 2_000_000_000, CHROME_JA4),
            &config,
        )
        .unwrap();
    assert!(!fires(&again, Rule::FirstSeen));
}

#[test]
fn rotation_fires_when_one_address_cycles_fingerprints() {
    let mut store = store();
    let config = cfg();
    let ip = "10.0.0.11";
    let first = store
        .detect_with(
            &client_hello(ip, 1_000_000_000, "t13d1516h2_111111111111_222222222222"),
            &config,
        )
        .unwrap();
    let second = store
        .detect_with(
            &client_hello(ip, 2_000_000_000, "t13d1516h2_333333333333_444444444444"),
            &config,
        )
        .unwrap();
    let third = store
        .detect_with(
            &client_hello(ip, 3_000_000_000, "t13d1516h2_555555555555_666666666666"),
            &config,
        )
        .unwrap();
    assert!(!fires(&first, Rule::FpRotation));
    assert!(!fires(&second, Rule::FpRotation));
    assert!(fires(&third, Rule::FpRotation));
}

#[test]
fn monoculture_fires_when_one_fingerprint_spans_addresses() {
    let mut store = store();
    let config = cfg();
    let ja4 = "t13d1516h2_777777777777_888888888888";
    let first = store
        .detect_with(&client_hello("10.1.0.1", 1_000_000_000, ja4), &config)
        .unwrap();
    let second = store
        .detect_with(&client_hello("10.1.0.2", 2_000_000_000, ja4), &config)
        .unwrap();
    let third = store
        .detect_with(&client_hello("10.1.0.3", 3_000_000_000, ja4), &config)
        .unwrap();
    assert!(!fires(&first, Rule::Monoculture));
    assert!(!fires(&second, Rule::Monoculture));
    assert!(fires(&third, Rule::Monoculture));
}

#[test]
fn alerts_persist_and_round_trip_through_the_store() {
    let mut store = store();
    store
        .detect_with(
            &client_hello("10.2.0.1", 1_000_000_000, MALWARE_JA4),
            &cfg(),
        )
        .unwrap();
    let recent = store.recent_alerts(10).unwrap();
    assert!(
        recent
            .iter()
            .any(|alert| alert.rule == Rule::KnownBad && alert.severity == AlertSeverity::High)
    );
    let counts = store.alert_counts().unwrap();
    assert!(
        counts
            .iter()
            .any(|(rule, count)| *rule == Rule::KnownBad && *count >= 1)
    );
}

#[test]
fn correlation_respects_the_time_window() {
    let mut store = store();
    let config = DetectConfig {
        window_secs: 1,
        rotation_threshold: 2,
        monoculture_threshold: 2,
    };
    store
        .detect_with(&client_hello("10.3.0.1", 0, CURL_JA4), &config)
        .unwrap();
    let alerts = store
        .detect_with(
            &http_request("10.3.0.1", 10_000_000_000, BROWSER_UA),
            &config,
        )
        .unwrap();
    assert!(!fires(&alerts, Rule::UaMismatch));
}
