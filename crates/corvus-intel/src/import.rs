// ©AngelaMos | 2026
// import.rs

//! Importing the ja4db.com enrichment feed.
//!
//! Unlike the three bundled feeds, ja4db is fetched at install time rather than
//! committed, because its licence is unspecified and the install script is the
//! honest place to pull it. Its records are also known to be dirty: the upstream
//! project tracks an issue where some fingerprint fields hold placeholders or
//! truncated values. So every fingerprint is validated for its kind before it
//! goes in, and the count of rejected rows is reported rather than hidden.
//!
//! The payload is read as untyped JSON rather than a fixed struct. ja4db is a
//! community database whose shape drifts, and a parser that demands an exact
//! schema would reject the whole file the day a field is renamed. Reading each
//! record as a map of optional fields keeps the importer working across those
//! changes and is itself the tolerance the dirty data calls for.
//!
//! ja4db identifies applications, so a record is treated as benign unless its
//! own classification fields name it as malicious. That makes ja4db the benign
//! baseline that the malicious feeds are weighed against, without silently
//! relabelling the handful of malware entries it does carry.

use anyhow::{Context, Result};
use rusqlite::Connection;
use serde_json::Value;

use super::model::{Category, FpKind};
use super::{NewFingerprint, get_or_create_source, insert_fingerprint, refresh_source_count};

const SOURCE_NAME: &str = "ja4db.com";
const SOURCE_URL: &str = "https://ja4db.com/api/read/";

/// The JSON field that carries each fingerprint kind in a ja4db record.
const FIELDS: &[(&str, FpKind)] = &[
    ("ja4_fingerprint", FpKind::Ja4),
    ("ja4s_fingerprint", FpKind::Ja4s),
    ("ja4h_fingerprint", FpKind::Ja4h),
    ("ja4x_fingerprint", FpKind::Ja4x),
    ("ja4t_fingerprint", FpKind::Ja4t),
    ("ja4ts_fingerprint", FpKind::Ja4ts),
];

/// What one import run did.
#[derive(Debug, Clone)]
pub struct ImportSummary {
    pub records: usize,
    pub imported: usize,
    pub skipped: usize,
}

/// Imports a ja4db `/api/read/` JSON array, validating every fingerprint.
pub fn import_ja4db(conn: &mut Connection, json: &str) -> Result<ImportSummary> {
    let payload: Value = serde_json::from_str(json).context("parsing ja4db JSON")?;
    let records = payload
        .as_array()
        .context("ja4db payload is not a JSON array")?;

    let tx = conn.transaction()?;
    let source_id = get_or_create_source(
        &tx,
        SOURCE_NAME,
        Some(SOURCE_URL),
        Some("unspecified"),
        "fetched",
    )?;

    let mut imported = 0;
    let mut skipped = 0;
    for record in records {
        let category = classify(record);
        let label = build_label(record);
        let reference = build_reference(record);
        for (field, kind) in FIELDS {
            let Some(raw) = record.get(field).and_then(Value::as_str) else {
                continue;
            };
            let value = raw.trim();
            if value.is_empty() {
                continue;
            }
            if !valid_fingerprint(*kind, value) {
                skipped += 1;
                continue;
            }
            if insert_fingerprint(
                &tx,
                source_id,
                &NewFingerprint {
                    kind: *kind,
                    value,
                    label: &label,
                    category,
                    reference: reference.as_deref(),
                    first_seen: None,
                },
            )? {
                imported += 1;
            }
        }
    }
    refresh_source_count(&tx, source_id)?;
    tx.commit()?;

    Ok(ImportSummary {
        records: records.len(),
        imported,
        skipped,
    })
}

/// Builds a display label from the application, library, or device, with the
/// operating system in parentheses when ja4db knows it.
fn build_label(record: &Value) -> String {
    let primary = ["application", "library", "device"]
        .into_iter()
        .filter_map(|key| record.get(key).and_then(Value::as_str))
        .map(str::trim)
        .find(|name| !name.is_empty());
    let os = record
        .get("os")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|name| !name.is_empty());
    match (primary, os) {
        (Some(name), Some(os)) => format!("{name} ({os})"),
        (Some(name), None) => name.to_string(),
        (None, Some(os)) => os.to_string(),
        (None, None) => "unknown".to_string(),
    }
}

/// Picks a human readable reference for a record, preferring the user agent
/// string and falling back to free form notes.
fn build_reference(record: &Value) -> Option<String> {
    for key in ["user_agent_string", "notes"] {
        if let Some(text) = record.get(key).and_then(Value::as_str) {
            let text = text.trim();
            if !text.is_empty() {
                return Some(text.to_string());
            }
        }
    }
    None
}

/// Classifies a record as benign unless one of its classification fields names
/// it as malicious. Identity fields like the application name are deliberately
/// not scanned, so an app that merely has an alarming name is not relabelled.
fn classify(record: &Value) -> Category {
    const MALICIOUS: &[&str] = &[
        "malware",
        "malicious",
        "trojan",
        "botnet",
        "ransomware",
        "stealer",
        "cobalt strike",
        "backdoor",
        "command and control",
    ];
    let mut text = String::new();
    for key in ["notes", "classification", "comment", "tags", "category"] {
        if let Some(value) = record.get(key).and_then(Value::as_str) {
            text.push_str(&value.to_ascii_lowercase());
            text.push(' ');
        }
    }
    if MALICIOUS.iter().any(|needle| text.contains(needle)) {
        Category::Malware
    } else {
        Category::Benign
    }
}

/// Whether a value has the right shape for its fingerprint kind. The checks are
/// loose enough to admit real data and strict enough to reject the placeholders
/// and truncations that the dirty ja4db rows are made of.
fn valid_fingerprint(kind: FpKind, value: &str) -> bool {
    match kind {
        FpKind::Ja3 | FpKind::Ja3s => is_hex(value, 32),
        FpKind::Ja4 => {
            let parts = value.split('_').collect::<Vec<_>>();
            parts.len() == 3
                && is_prefix(parts[0], 8, 12)
                && is_hex(parts[1], 12)
                && is_hex(parts[2], 12)
        }
        FpKind::Ja4s => {
            let parts = value.split('_').collect::<Vec<_>>();
            parts.len() == 3
                && is_prefix(parts[0], 5, 9)
                && is_hex_between(parts[1], 2, 8)
                && is_hex(parts[2], 12)
        }
        FpKind::Ja4x => {
            let parts = value.split('_').collect::<Vec<_>>();
            parts.len() == 3 && parts.iter().all(|part| is_hex(part, 12))
        }
        FpKind::Ja4t | FpKind::Ja4ts => {
            let parts = value.split('_').collect::<Vec<_>>();
            (2..=4).contains(&parts.len())
                && !parts[0].is_empty()
                && parts[0].bytes().all(|byte| byte.is_ascii_digit())
        }
        FpKind::Ja4h => {
            let parts = value.split('_').collect::<Vec<_>>();
            parts.len() >= 2
                && parts[0].len() >= 8
                && parts[0].bytes().all(|byte| byte.is_ascii_alphanumeric())
        }
    }
}

fn is_hex(value: &str, len: usize) -> bool {
    value.len() == len && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn is_hex_between(value: &str, min: usize, max: usize) -> bool {
    (min..=max).contains(&value.len()) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn is_prefix(value: &str, min: usize, max: usize) -> bool {
    (min..=max).contains(&value.len())
        && matches!(value.as_bytes().first(), Some(b't' | b'q' | b'd'))
        && value.bytes().all(|byte| byte.is_ascii_alphanumeric())
}

#[cfg(test)]
mod tests {
    use crate::IntelStore;
    use crate::model::{FpKind, Verdict};

    const SAMPLE: &str = r#"[
      {"application":"Chrome","os":"Windows","ja4_fingerprint":"t13d1516h2_8daaf6152771_e5627efa2ab1","user_agent_string":"Mozilla/5.0"},
      {"application":"curl","library":"OpenSSL","ja4_fingerprint":"t13d1234h1_aaaaaaaaaaaa_bbbbbbbbbbbb"},
      {"application":"Loader","notes":"known malware stealer","ja4_fingerprint":"t10d070600_c50f5591e341_1a3805c3aa63"},
      {"application":"Dirty","ja4_fingerprint":"GREASE"},
      {"application":"NoFp","ja4_fingerprint":null},
      {"application":"Server","ja4s_fingerprint":"t130200_1301_234ea6891581"}
    ]"#;

    #[test]
    fn imports_valid_rows_and_counts_dirty_ones() {
        let mut store = IntelStore::open_in_memory().unwrap();
        let summary = store.import_ja4db(SAMPLE).unwrap();
        assert_eq!(summary.records, 6);
        assert_eq!(summary.imported, 4);
        assert_eq!(summary.skipped, 1);
    }

    #[test]
    fn re_importing_adds_nothing_new() {
        let mut store = IntelStore::open_in_memory().unwrap();
        store.import_ja4db(SAMPLE).unwrap();
        let second = store.import_ja4db(SAMPLE).unwrap();
        assert_eq!(second.imported, 0);
        assert_eq!(second.skipped, 1);
    }

    #[test]
    fn classification_field_marks_malware() {
        let mut store = IntelStore::open_in_memory().unwrap();
        store.import_ja4db(SAMPLE).unwrap();
        let report = store
            .match_fingerprint(FpKind::Ja4, "t10d070600_c50f5591e341_1a3805c3aa63")
            .unwrap();
        assert_eq!(report.verdict, Verdict::Malicious);
    }

    #[test]
    fn identified_application_is_benign() {
        let mut store = IntelStore::open_in_memory().unwrap();
        store.import_ja4db(SAMPLE).unwrap();
        let report = store
            .match_fingerprint(FpKind::Ja4, "t13d1516h2_8daaf6152771_e5627efa2ab1")
            .unwrap();
        assert_eq!(report.verdict, Verdict::Benign);
        assert!(
            report
                .hits
                .iter()
                .any(|hit| hit.label == "Chrome (Windows)")
        );
    }

    #[test]
    fn a_non_array_payload_is_an_error() {
        let mut store = IntelStore::open_in_memory().unwrap();
        assert!(store.import_ja4db("{}").is_err());
        assert!(store.import_ja4db("not json").is_err());
    }

    #[test]
    fn an_empty_array_imports_nothing() {
        let mut store = IntelStore::open_in_memory().unwrap();
        let summary = store.import_ja4db("[]").unwrap();
        assert_eq!(summary.records, 0);
        assert_eq!(summary.imported, 0);
    }

    #[test]
    fn validators_reject_placeholders() {
        use super::valid_fingerprint;
        assert!(valid_fingerprint(
            FpKind::Ja4,
            "t13d1516h2_8daaf6152771_e5627efa2ab1"
        ));
        assert!(!valid_fingerprint(FpKind::Ja4, "GREASE"));
        assert!(!valid_fingerprint(
            FpKind::Ja4,
            "t13d1516h2_short_e5627efa2ab1"
        ));
        assert!(!valid_fingerprint(FpKind::Ja4, ""));
        assert!(valid_fingerprint(
            FpKind::Ja3,
            "1aa7bf8b97e540ca5edd75f7b8384bfa"
        ));
        assert!(!valid_fingerprint(FpKind::Ja3, "N/A"));
    }
}
