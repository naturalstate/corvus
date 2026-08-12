// ©AngelaMos | 2026
// seed.rs

//! Loading the three vendored feeds into the database.
//!
//! The feeds are compiled into the binary, so seeding needs no network. Each
//! feed has its own column layout, so each gets its own small parser, but they
//! share one insert path that computes the JA4 partial match columns and skips
//! rows already present. Parsing uses a real CSV reader rather than splitting on
//! commas, because the salesforce application names are quoted and can contain
//! commas, and its licence header is a quoted field that spans several lines.
//!
//! Every malicious feed row is classified by the feed it came from: abuse.ch
//! SSLBL is a blocklist, so its rows are malware, and the salesforce list is a
//! benign application catalogue, so its rows are benign. The curated file
//! carries an explicit category per row. The point of loading both a malicious
//! and a benign feed is that some hashes appear in both, and the matcher needs
//! to see that disagreement to score it.

use anyhow::Result;
use rusqlite::Connection;

use super::model::{Category, FpKind};
use super::{NewFingerprint, get_or_create_source, insert_fingerprint, refresh_source_count};

const SSLBL: &str = include_str!("../seeds/sslbl-ja3.csv");
const SALESFORCE: &str = include_str!("../seeds/salesforce-osx-nix-ja3.csv");
const CURATED: &str = include_str!("../seeds/curated-c2-intel.csv");

const SSLBL_NAME: &str = "abuse.ch SSLBL";
const SSLBL_URL: &str = "https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv";
const SALESFORCE_NAME: &str = "salesforce/ja3 osx-nix";
const SALESFORCE_URL: &str = "https://github.com/salesforce/ja3";
const CURATED_NAME: &str = "tlsfp curated";

/// How many rows one feed contributed on a seed run.
#[derive(Debug, Clone)]
pub struct FeedLoad {
    pub name: String,
    pub inserted: usize,
    pub parsed: usize,
}

/// The result of a full seed run across every feed.
#[derive(Debug, Clone)]
pub struct SeedSummary {
    pub feeds: Vec<FeedLoad>,
}

impl SeedSummary {
    /// Rows newly inserted across all feeds, zero on a repeat seed.
    pub fn inserted(&self) -> usize {
        self.feeds.iter().map(|feed| feed.inserted).sum()
    }

    /// Valid rows parsed across all feeds, the same on every seed.
    pub fn parsed(&self) -> usize {
        self.feeds.iter().map(|feed| feed.parsed).sum()
    }
}

/// Loads all three vendored feeds inside a single transaction.
pub fn load_bundled(conn: &mut Connection) -> Result<SeedSummary> {
    let tx = conn.transaction()?;
    let mut feeds = Vec::new();

    let sslbl_id =
        get_or_create_source(&tx, SSLBL_NAME, Some(SSLBL_URL), Some("CC0-1.0"), "bundled")?;
    let (inserted, parsed) = load_sslbl(&tx, sslbl_id)?;
    refresh_source_count(&tx, sslbl_id)?;
    feeds.push(FeedLoad {
        name: SSLBL_NAME.to_string(),
        inserted,
        parsed,
    });

    let sf_id = get_or_create_source(
        &tx,
        SALESFORCE_NAME,
        Some(SALESFORCE_URL),
        Some("BSD-3-Clause"),
        "bundled",
    )?;
    let (inserted, parsed) = load_salesforce(&tx, sf_id)?;
    refresh_source_count(&tx, sf_id)?;
    feeds.push(FeedLoad {
        name: SALESFORCE_NAME.to_string(),
        inserted,
        parsed,
    });

    let curated_id = get_or_create_source(&tx, CURATED_NAME, None, Some("project"), "bundled")?;
    let (inserted, parsed) = load_curated(&tx, curated_id)?;
    refresh_source_count(&tx, curated_id)?;
    feeds.push(FeedLoad {
        name: CURATED_NAME.to_string(),
        inserted,
        parsed,
    });

    tx.commit()?;
    Ok(SeedSummary { feeds })
}

/// abuse.ch SSLBL: `ja3_md5, Firstseen, Lastseen, Listingreason`, every row a
/// known malicious JA3.
fn load_sslbl(conn: &Connection, source_id: i64) -> Result<(usize, usize)> {
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(false)
        .flexible(true)
        .comment(Some(b'#'))
        .from_reader(SSLBL.as_bytes());

    let mut inserted = 0;
    let mut parsed = 0;
    for record in reader.records() {
        let record = record?;
        let value = record.get(0).unwrap_or_default().trim();
        if !is_hex_md5(value) {
            continue;
        }
        let first_seen = record.get(1).map(str::trim).filter(|seen| !seen.is_empty());
        let label = record
            .get(3)
            .map(str::trim)
            .filter(|reason| !reason.is_empty())
            .unwrap_or("unknown");
        parsed += 1;
        if insert_fingerprint(
            conn,
            source_id,
            &NewFingerprint {
                kind: FpKind::Ja3,
                value,
                label,
                category: Category::Malware,
                reference: None,
                first_seen,
            },
        )? {
            inserted += 1;
        }
    }
    Ok((inserted, parsed))
}

/// salesforce osx-nix: `ja3_md5, "application name(s)"`, every row a benign app.
/// The quoted multi line licence header is the first record and is dropped by
/// the hex check, since its first field is prose rather than a hash.
fn load_salesforce(conn: &Connection, source_id: i64) -> Result<(usize, usize)> {
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(false)
        .flexible(true)
        .from_reader(SALESFORCE.as_bytes());

    let mut inserted = 0;
    let mut parsed = 0;
    for record in reader.records() {
        let record = record?;
        let value = record.get(0).unwrap_or_default().trim();
        if !is_hex_md5(value) {
            continue;
        }
        let label = record
            .get(1)
            .map(str::trim)
            .filter(|app| !app.is_empty())
            .unwrap_or("unknown");
        parsed += 1;
        if insert_fingerprint(
            conn,
            source_id,
            &NewFingerprint {
                kind: FpKind::Ja3,
                value,
                label,
                category: Category::Benign,
                reference: None,
                first_seen: None,
            },
        )? {
            inserted += 1;
        }
    }
    Ok((inserted, parsed))
}

/// The curated file: `fp_kind, value, label, category, reference`, each row a
/// hand classified entry from a named source.
fn load_curated(conn: &Connection, source_id: i64) -> Result<(usize, usize)> {
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(true)
        .flexible(true)
        .comment(Some(b'#'))
        .from_reader(CURATED.as_bytes());

    let mut inserted = 0;
    let mut parsed = 0;
    for record in reader.records() {
        let record = record?;
        let Some(kind) = record.get(0).map(str::trim).and_then(FpKind::from_token) else {
            continue;
        };
        let value = record.get(1).unwrap_or_default().trim();
        if value.is_empty() {
            continue;
        }
        let label = record
            .get(2)
            .map(str::trim)
            .filter(|label| !label.is_empty())
            .unwrap_or("unknown");
        let category = record
            .get(3)
            .map_or(Category::Unknown, Category::from_token);
        let reference = record.get(4).map(str::trim).filter(|note| !note.is_empty());
        parsed += 1;
        if insert_fingerprint(
            conn,
            source_id,
            &NewFingerprint {
                kind,
                value,
                label,
                category,
                reference,
                first_seen: None,
            },
        )? {
            inserted += 1;
        }
    }
    Ok((inserted, parsed))
}

/// Whether a string is a lowercase or uppercase 32 character hex digest, the
/// shape of every JA3 value and the test that skips comment and header rows.
fn is_hex_md5(value: &str) -> bool {
    value.len() == 32 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::{CURATED_NAME, SALESFORCE_NAME, SSLBL_NAME, load_bundled};
    use crate::IntelStore;
    use crate::model::{Category, FpKind};

    fn category_of(store: &IntelStore, value: &str, source: &str) -> Option<String> {
        store
            .conn
            .query_row(
                "SELECT category FROM intel_fingerprint f
                 JOIN intel_source s ON s.id = f.source_id
                 WHERE f.value = ?1 AND s.name = ?2",
                rusqlite::params![value, source],
                |row| row.get(0),
            )
            .ok()
    }

    #[test]
    fn seeds_every_vendored_row() {
        let mut store = IntelStore::open_in_memory().unwrap();
        let summary = store.seed_bundled().unwrap();
        assert_eq!(summary.parsed(), 97 + 157 + 17);
        assert_eq!(summary.inserted(), summary.parsed());
    }

    #[test]
    fn seeding_twice_inserts_nothing_new() {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        super::super::schema::apply_migrations(&mut conn).unwrap();
        let first = load_bundled(&mut conn).unwrap();
        let second = load_bundled(&mut conn).unwrap();
        assert!(first.inserted() > 0);
        assert_eq!(second.inserted(), 0);
        assert_eq!(second.parsed(), first.parsed());
    }

    #[test]
    fn sslbl_rows_are_malware_salesforce_rows_are_benign() {
        let mut store = IntelStore::open_in_memory().unwrap();
        store.seed_bundled().unwrap();
        assert_eq!(
            category_of(&store, "1aa7bf8b97e540ca5edd75f7b8384bfa", SSLBL_NAME).as_deref(),
            Some("malware"),
        );
        assert_eq!(
            category_of(&store, "c36fb08942cf19508c08d96af22d4ffc", SALESFORCE_NAME).as_deref(),
            Some("benign"),
        );
    }

    #[test]
    fn curated_carries_its_own_categories() {
        let mut store = IntelStore::open_in_memory().unwrap();
        store.seed_bundled().unwrap();
        assert_eq!(
            category_of(&store, "72a589da586844d7f0818ce684948eea", CURATED_NAME).as_deref(),
            Some("c2"),
        );
        assert_eq!(
            category_of(&store, "8916410db85077a5460817142dcbc8de", CURATED_NAME).as_deref(),
            Some("tool"),
        );
    }

    #[test]
    fn the_same_hash_can_be_both_malicious_and_benign() {
        let mut store = IntelStore::open_in_memory().unwrap();
        store.seed_bundled().unwrap();
        let collision = "51a7ad14509fd614c7bb3a50c4982b8c";
        assert_eq!(
            category_of(&store, collision, SSLBL_NAME).as_deref(),
            Some("malware"),
        );
        assert_eq!(
            category_of(&store, collision, SALESFORCE_NAME).as_deref(),
            Some("benign"),
        );
    }

    #[test]
    fn ja4_rows_get_partial_match_columns() {
        let mut store = IntelStore::open_in_memory().unwrap();
        store.seed_bundled().unwrap();
        let parts: (Option<String>, Option<String>) = store
            .conn
            .query_row(
                "SELECT part_a, part_b FROM intel_fingerprint WHERE fp_kind = 'ja4' AND value = ?1",
                rusqlite::params!["t13d1516h2_8daaf6152771_e5627efa2ab1"],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(parts.0.as_deref(), Some("t13d1516h2"));
        assert_eq!(parts.1.as_deref(), Some("8daaf6152771"));
        let ja3_parts: (Option<String>, Option<String>) = store
            .conn
            .query_row(
                "SELECT part_a, part_b FROM intel_fingerprint WHERE fp_kind = 'ja3' LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(ja3_parts, (None, None));
    }

    #[test]
    fn category_tokens_parse() {
        assert_eq!(Category::from_token("malware"), Category::Malware);
        assert_eq!(Category::from_token(" C2 "), Category::C2);
        assert_eq!(Category::from_token("garbage"), Category::Unknown);
    }

    #[test]
    fn fp_kind_tokens_parse() {
        assert_eq!(FpKind::from_token("ja4"), Some(FpKind::Ja4));
        assert_eq!(FpKind::from_token("zz"), None);
    }
}
