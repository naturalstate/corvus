// ©AngelaMos | 2026
// matcher.rs

//! Looking a fingerprint up against the store.
//!
//! Every kind supports an exact match. The JA4 client fingerprint also supports
//! two partial tiers, because its value is three fields joined by underscores:
//! a capability prefix, a hash of the cipher list, and a hash of the extension
//! list. A tool that copies a browser's cipher order but not its full set of
//! extensions produces a different whole fingerprint but the same cipher hash,
//! so matching on the cipher hash alone catches the impersonation that an exact
//! match misses. The three tiers query disjoint rows, so a hit is counted once
//! at its true strength with no later de duplication.

use rusqlite::{Connection, Params, Row, params};
use tlsfp_core::{FingerprintEvent, StreamEvent};

use super::ja4_parts;
use super::model::{CatalogEntry, Category, FpKind, IntelHit, MatchReport, MatchStrength};

const SELECT: &str = "SELECT f.fp_kind, f.value, f.label, f.category, s.name, f.reference
     FROM intel_fingerprint f
     JOIN intel_source s ON s.id = f.source_id";

/// Looks one fingerprint up and scores every hit into a verdict.
pub fn match_one(conn: &Connection, kind: FpKind, value: &str) -> anyhow::Result<MatchReport> {
    let value = value.trim().to_ascii_lowercase();
    let mut hits = collect(
        conn,
        &format!("{SELECT} WHERE f.fp_kind = ?1 AND f.value = ?2"),
        params![kind.as_str(), value],
        MatchStrength::Exact,
    )?;

    if kind.supports_partial() {
        if let Some((prefix, cipher)) = ja4_parts(&value) {
            hits.extend(collect(
                conn,
                &format!(
                    "{SELECT} WHERE f.fp_kind = 'ja4' AND f.part_a = ?1 AND f.part_b = ?2 AND f.value != ?3"
                ),
                params![prefix, cipher, value],
                MatchStrength::CipherAndPrefix,
            )?);
            hits.extend(collect(
                conn,
                &format!("{SELECT} WHERE f.fp_kind = 'ja4' AND f.part_b = ?1 AND f.part_a != ?2"),
                params![cipher, prefix],
                MatchStrength::CipherOnly,
            )?);
        }
    }

    Ok(MatchReport::from_hits(kind, value, hits))
}

/// The fingerprints carried by one capture event, paired with their kind.
pub fn event_fingerprints(event: &FingerprintEvent) -> Vec<(FpKind, String)> {
    match &event.event {
        StreamEvent::ClientHello { ja3, ja4, .. } => {
            vec![
                (FpKind::Ja3, ja3.to_string()),
                (FpKind::Ja4, ja4.hash.clone()),
            ]
        }
        StreamEvent::ServerHello { ja3s, ja4s, .. } => {
            vec![
                (FpKind::Ja3s, ja3s.to_string()),
                (FpKind::Ja4s, ja4s.hash.clone()),
            ]
        }
        StreamEvent::Certificate { ja4x } => vec![(FpKind::Ja4x, ja4x.clone())],
        StreamEvent::HttpRequest { ja4h, .. } => vec![(FpKind::Ja4h, ja4h.hash.clone())],
        StreamEvent::TcpSyn { ja4t } => vec![(FpKind::Ja4t, ja4t.clone())],
        StreamEvent::TcpSynAck { ja4ts } => vec![(FpKind::Ja4ts, ja4ts.clone())],
    }
}

/// Searches the stored catalogue by a free text substring against fingerprint
/// values and labels, optionally narrowed to one kind. This is the browse path
/// the dashboard search box and the CLI use, distinct from matching an observed
/// value: it returns rows that contain the query, not hits scored against it.
/// LIKE metacharacters in the query are escaped so a literal percent or
/// underscore searches for itself rather than acting as a wildcard.
pub fn search_catalog(
    conn: &Connection,
    query: &str,
    kind: Option<FpKind>,
    limit: i64,
) -> anyhow::Result<Vec<CatalogEntry>> {
    let needle = format!("%{}%", escape_like(query.trim()));
    let select = "SELECT f.fp_kind, f.value, f.label, f.category, s.name, f.reference
         FROM intel_fingerprint f
         JOIN intel_source s ON s.id = f.source_id
         WHERE (f.value LIKE ?1 ESCAPE '\\' OR f.label LIKE ?1 ESCAPE '\\')";
    let entries = if let Some(kind) = kind {
        let sql = format!("{select} AND f.fp_kind = ?2 ORDER BY f.label, f.value LIMIT ?3");
        let mut statement = conn.prepare(&sql)?;
        statement
            .query_map(params![needle, kind.as_str(), limit], map_catalog_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?
    } else {
        let sql = format!("{select} ORDER BY f.label, f.value LIMIT ?2");
        let mut statement = conn.prepare(&sql)?;
        statement
            .query_map(params![needle, limit], map_catalog_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?
    };
    Ok(entries)
}

fn map_catalog_row(row: &Row) -> rusqlite::Result<CatalogEntry> {
    let kind: String = row.get(0)?;
    let category: String = row.get(3)?;
    Ok(CatalogEntry {
        kind: FpKind::from_token(&kind).unwrap_or(FpKind::Ja3),
        value: row.get(1)?,
        label: row.get(2)?,
        category: Category::from_token(&category),
        source: row.get(4)?,
        reference: row.get(5)?,
    })
}

/// Escapes the LIKE metacharacters in user supplied search text so they match
/// as literal characters. Pairs with the `ESCAPE '\'` clause in the query.
fn escape_like(input: &str) -> String {
    let mut escaped = String::with_capacity(input.len());
    for ch in input.chars() {
        if matches!(ch, '\\' | '%' | '_') {
            escaped.push('\\');
        }
        escaped.push(ch);
    }
    escaped
}

fn collect(
    conn: &Connection,
    sql: &str,
    params: impl Params,
    strength: MatchStrength,
) -> rusqlite::Result<Vec<IntelHit>> {
    let mut statement = conn.prepare(sql)?;
    let hits = statement
        .query_map(params, |row| map_row(row, strength))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(hits)
}

fn map_row(row: &Row, strength: MatchStrength) -> rusqlite::Result<IntelHit> {
    let kind: String = row.get(0)?;
    let category: String = row.get(3)?;
    Ok(IntelHit {
        kind: FpKind::from_token(&kind).unwrap_or(FpKind::Ja3),
        value: row.get(1)?,
        label: row.get(2)?,
        category: Category::from_token(&category),
        source: row.get(4)?,
        reference: row.get(5)?,
        strength,
    })
}

#[cfg(test)]
mod tests {
    use super::{event_fingerprints, match_one};
    use crate::IntelStore;
    use crate::model::{FpKind, MatchStrength, Verdict};
    use tlsfp_core::fingerprint::{Ja3, Ja4Family};
    use tlsfp_core::{FingerprintEvent, StreamEvent};

    fn seeded() -> IntelStore {
        let mut store = IntelStore::open_in_memory().unwrap();
        store.seed_bundled().unwrap();
        store
    }

    #[test]
    fn known_malicious_ja3_is_malicious() {
        let store = seeded();
        let report = store
            .match_fingerprint(FpKind::Ja3, "1aa7bf8b97e540ca5edd75f7b8384bfa")
            .unwrap();
        assert_eq!(report.verdict, Verdict::Malicious);
        assert!(report.hits.iter().any(|hit| hit.label == "TrickBot"));
    }

    #[test]
    fn known_benign_ja3_is_benign() {
        let store = seeded();
        let report = store
            .match_fingerprint(FpKind::Ja3, "c36fb08942cf19508c08d96af22d4ffc")
            .unwrap();
        assert_eq!(report.verdict, Verdict::Benign);
        assert!(report.hits.iter().any(|hit| hit.label == "Safari"));
    }

    #[test]
    fn cross_feed_collision_is_suspicious() {
        let store = seeded();
        let report = store
            .match_fingerprint(FpKind::Ja3, "51a7ad14509fd614c7bb3a50c4982b8c")
            .unwrap();
        assert_eq!(report.verdict, Verdict::Suspicious);
        assert!(report.hits.len() >= 2);
        assert!((report.threat_score - 0.5).abs() < 1e-9);
    }

    #[test]
    fn unknown_fingerprint_returns_no_hits() {
        let store = seeded();
        let report = store
            .match_fingerprint(FpKind::Ja3, "00000000000000000000000000000000")
            .unwrap();
        assert_eq!(report.verdict, Verdict::Unknown);
        assert!(!report.has_hits());
    }

    #[test]
    fn case_is_normalised_before_lookup() {
        let store = seeded();
        let report = store
            .match_fingerprint(FpKind::Ja3, "1AA7BF8B97E540CA5EDD75F7B8384BFA")
            .unwrap();
        assert_eq!(report.verdict, Verdict::Malicious);
    }

    #[test]
    fn exact_ja4_lookup_hits() {
        let store = seeded();
        let report = store
            .match_fingerprint(FpKind::Ja4, "t10d070600_c50f5591e341_1a3805c3aa63")
            .unwrap();
        assert_eq!(report.verdict, Verdict::Malicious);
        assert_eq!(report.hits[0].strength, MatchStrength::Exact);
        assert!(report.hits.iter().any(|hit| hit.label == "RedLine Stealer"));
    }

    #[test]
    fn ja4_same_ciphers_different_extensions_is_a_partial_hit() {
        let store = seeded();
        let report = match_one(
            &store.conn,
            FpKind::Ja4,
            "t13d1516h2_8daaf6152771_ffffffffffff",
        )
        .unwrap();
        assert!(report.has_hits());
        assert_eq!(report.hits[0].strength, MatchStrength::CipherAndPrefix);
        assert!(report.hits.iter().any(|hit| hit.label == "Google Chrome"));
    }

    #[test]
    fn ja4_same_cipher_list_under_a_different_profile_is_cipher_only() {
        let store = seeded();
        let report = match_one(
            &store.conn,
            FpKind::Ja4,
            "t13d0000h0_8daaf6152771_000000000000",
        )
        .unwrap();
        assert!(report.has_hits());
        assert_eq!(report.hits[0].strength, MatchStrength::CipherOnly);
    }

    #[test]
    fn ja3_does_not_do_partial_matching() {
        let store = seeded();
        let report = store
            .match_fingerprint(FpKind::Ja3, "1aa7bf8b97e540ca5edd75f7b8384bf0")
            .unwrap();
        assert!(!report.has_hits());
    }

    #[test]
    fn event_fingerprints_pulls_both_client_fingerprints() {
        let event = FingerprintEvent {
            ts_nanos: 0,
            src: "10.0.0.1:1000".parse().unwrap(),
            dst: "10.0.0.2:443".parse().unwrap(),
            event: StreamEvent::ClientHello {
                ja3: Ja3::from_digest([0x1a; 16]),
                ja3_raw: "raw".into(),
                ja4: Ja4Family::new("t13d1516h2_8daaf6152771_e5627efa2ab1".into(), "raw".into()),
                sni: None,
                alpn: None,
            },
        };
        let fingerprints = event_fingerprints(&event);
        assert_eq!(fingerprints.len(), 2);
        assert_eq!(fingerprints[0].0, FpKind::Ja3);
        assert_eq!(fingerprints[1].0, FpKind::Ja4);
        assert_eq!(fingerprints[1].1, "t13d1516h2_8daaf6152771_e5627efa2ab1");
    }

    #[test]
    fn match_event_only_reports_kinds_with_intel() {
        let store = seeded();
        let event = FingerprintEvent {
            ts_nanos: 0,
            src: "10.0.0.1:1000".parse().unwrap(),
            dst: "10.0.0.2:443".parse().unwrap(),
            event: StreamEvent::ClientHello {
                ja3: Ja3::from_digest([0x00; 16]),
                ja3_raw: "raw".into(),
                ja4: Ja4Family::new("t13d1516h2_8daaf6152771_e5627efa2ab1".into(), "raw".into()),
                sni: None,
                alpn: None,
            },
        };
        let reports = store.match_event(&event).unwrap();
        assert_eq!(reports.len(), 1);
        assert_eq!(reports[0].kind, FpKind::Ja4);
        assert_eq!(reports[0].verdict, Verdict::Benign);
    }

    #[test]
    fn search_finds_a_label_substring_case_insensitively() {
        let store = seeded();
        let hits = store.search("trick", None, 20).unwrap();
        assert!(hits.iter().any(|entry| entry.label == "TrickBot"));
    }

    #[test]
    fn search_can_narrow_to_one_kind() {
        let store = seeded();
        let all = store.search("", None, 10_000).unwrap();
        let ja3_only = store.search("", Some(FpKind::Ja3), 10_000).unwrap();
        assert!(!ja3_only.is_empty());
        assert!(ja3_only.iter().all(|entry| entry.kind == FpKind::Ja3));
        assert!(ja3_only.len() < all.len());
    }

    #[test]
    fn search_escapes_like_wildcards() {
        let store = seeded();
        let literal_percent = store.search("%", None, 10).unwrap();
        assert!(literal_percent.is_empty());
    }
}
