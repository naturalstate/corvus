// ©AngelaMos | 2026
// lib.rs

//! The local threat intelligence store.
//!
//! This is the half of the tool that turns a fingerprint into a judgement. It
//! owns a bundled SQLite database, seeds it from three vendored feeds, can pull
//! a fourth feed at install time, and answers the one question the rest of the
//! tool cares about: is this fingerprint known, and is it known to be bad.
//!
//! The store is deliberately synchronous. The capture pipeline that feeds it is
//! a plain loop, and a lookup is a single indexed query, so wrapping it in an
//! async runtime would buy nothing here. The web server, when it arrives, is
//! the place that needs concurrent access, and that is where an async wrapper
//! belongs.

mod detect;
mod import;
mod matcher;
mod model;
mod schema;
mod seed;
mod signal;

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use rusqlite::{Connection, params};
use serde::Serialize;
use tlsfp_core::FingerprintEvent;

pub use detect::{Alert, AlertSeverity, DetectConfig, Rule};
pub use import::ImportSummary;
pub use model::{CatalogEntry, Category, FpKind, IntelHit, MatchReport, MatchStrength, Verdict};
pub use seed::{FeedLoad, SeedSummary};

/// A handle to the open intelligence database.
pub struct IntelStore {
    conn: Connection,
}

impl IntelStore {
    /// Opens or creates the database at `path`, creating any missing parent
    /// directories and bringing the schema up to date.
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("creating database directory {}", parent.display()))?;
            }
        }
        let conn = Connection::open(path)
            .with_context(|| format!("opening database {}", path.display()))?;
        conn.execute_batch("PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL;")?;
        // The dashboard runs a read connection alongside a capture writer on this
        // same file, so wait on a contended lock rather than failing the query.
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        Self::migrate(conn)
    }

    /// Opens a private in memory database, used by tests and by commands that
    /// only need a scratch store.
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch("PRAGMA foreign_keys = ON;")?;
        Self::migrate(conn)
    }

    fn migrate(mut conn: Connection) -> Result<Self> {
        schema::apply_migrations(&mut conn).context("applying schema migrations")?;
        Ok(Self { conn })
    }

    /// Loads the three vendored feeds, skipping rows already present so a second
    /// call changes nothing.
    pub fn seed_bundled(&mut self) -> Result<SeedSummary> {
        seed::load_bundled(&mut self.conn)
    }

    /// Imports a ja4db.com `/api/read/` JSON payload, validating each
    /// fingerprint and reporting how many rows were kept and skipped.
    pub fn import_ja4db(&mut self, json: &str) -> Result<ImportSummary> {
        import::import_ja4db(&mut self.conn, json)
    }

    /// Looks up one fingerprint and scores the hits into a verdict.
    pub fn match_fingerprint(&self, kind: FpKind, value: &str) -> Result<MatchReport> {
        matcher::match_one(&self.conn, kind, value)
    }

    /// Looks up every fingerprint carried by one capture event, returning a
    /// report for each kind that found intelligence.
    pub fn match_event(&self, event: &FingerprintEvent) -> Result<Vec<MatchReport>> {
        let mut reports = Vec::new();
        for (kind, value) in matcher::event_fingerprints(event) {
            let report = self.match_fingerprint(kind, &value)?;
            if report.has_hits() {
                reports.push(report);
            }
        }
        Ok(reports)
    }

    /// Records one capture event and returns every alert its detection rules
    /// raised, using the default thresholds.
    pub fn detect(&mut self, event: &FingerprintEvent) -> Result<Vec<Alert>> {
        self.detect_with(event, &DetectConfig::default())
    }

    /// Records one capture event under explicit thresholds. The observation and
    /// any alerts it raises commit together inside one transaction.
    pub fn detect_with(
        &mut self,
        event: &FingerprintEvent,
        config: &DetectConfig,
    ) -> Result<Vec<Alert>> {
        let tx = self.conn.transaction()?;
        let alerts = detect::run(&tx, event, config)?;
        tx.commit()?;
        Ok(alerts)
    }

    /// The most recent alerts, newest first, for the CLI feed and the dashboard.
    pub fn recent_alerts(&self, limit: i64) -> Result<Vec<Alert>> {
        detect::recent(&self.conn, limit)
    }

    /// A count of recorded alerts per rule, for the stats summary.
    pub fn alert_counts(&self) -> Result<Vec<(Rule, i64)>> {
        detect::counts_by_rule(&self.conn)
    }

    /// Searches the stored catalogue by a free text substring, optionally
    /// narrowed to one fingerprint kind, for the dashboard search box and CLI.
    pub fn search(
        &self,
        query: &str,
        kind: Option<FpKind>,
        limit: i64,
    ) -> Result<Vec<CatalogEntry>> {
        matcher::search_catalog(&self.conn, query, kind, limit)
    }

    /// The alerts recorded after `after_id`, oldest first, for a reader tailing
    /// the store as new detections land.
    pub fn alerts_since(&self, after_id: i64, limit: i64) -> Result<Vec<(i64, Alert)>> {
        detect::since(&self.conn, after_id, limit)
    }

    /// The highest alert id currently stored, the starting point for a tailing
    /// reader that wants only alerts raised after it connected.
    pub fn latest_alert_id(&self) -> Result<i64> {
        detect::max_id(&self.conn)
    }

    /// Summarises what the store holds, by feed and by category.
    pub fn stats(&self) -> Result<Stats> {
        let sources = self
            .conn
            .prepare("SELECT name, kind, license, record_count FROM intel_source ORDER BY name")?
            .query_map([], |row| {
                Ok(SourceStat {
                    name: row.get(0)?,
                    kind: row.get(1)?,
                    license: row.get(2)?,
                    records: row.get(3)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        let by_category = self
            .conn
            .prepare(
                "SELECT category, count(*) FROM intel_fingerprint GROUP BY category ORDER BY category",
            )?
            .query_map([], |row| {
                Ok(CategoryStat {
                    category: row.get(0)?,
                    records: row.get(1)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        let total: i64 =
            self.conn
                .query_row("SELECT count(*) FROM intel_fingerprint", [], |row| {
                    row.get(0)
                })?;

        Ok(Stats {
            sources,
            by_category,
            total,
        })
    }
}

/// A per feed row of the stats summary.
#[derive(Debug, Clone, Serialize)]
pub struct SourceStat {
    pub name: String,
    pub kind: String,
    pub license: Option<String>,
    pub records: i64,
}

/// A per category row of the stats summary.
#[derive(Debug, Clone, Serialize)]
pub struct CategoryStat {
    pub category: String,
    pub records: i64,
}

/// What the store currently holds.
#[derive(Debug, Clone, Serialize)]
pub struct Stats {
    pub sources: Vec<SourceStat>,
    pub by_category: Vec<CategoryStat>,
    pub total: i64,
}

/// The default on disk location of the database, under the XDG data directory
/// when one is set and the home directory otherwise.
pub fn default_db_path() -> PathBuf {
    let base = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .or_else(|| {
            std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".local").join("share"))
        })
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("tlsfp").join("intel.db")
}

/// Splits a JA4 client fingerprint into its capability prefix and cipher hash,
/// the two parts the partial matcher indexes on. Returns `None` for a value
/// that is not the expected three underscore separated fields.
pub(crate) fn ja4_parts(value: &str) -> Option<(String, String)> {
    let mut fields = value.split('_');
    let prefix = fields.next()?;
    let cipher = fields.next()?;
    let extensions = fields.next()?;
    if fields.next().is_some() || prefix.is_empty() || cipher.is_empty() || extensions.is_empty() {
        return None;
    }
    Some((prefix.to_string(), cipher.to_string()))
}

/// Inserts a feed by name or updates it if already present, returning its row
/// id. The id is kept stable across re imports so the fingerprints that point
/// at it are never orphaned.
pub(crate) fn get_or_create_source(
    conn: &Connection,
    name: &str,
    url: Option<&str>,
    license: Option<&str>,
    kind: &str,
) -> rusqlite::Result<i64> {
    conn.execute(
        "INSERT INTO intel_source (name, url, license, kind, imported_at)
         VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(name) DO UPDATE SET
             url = excluded.url,
             license = excluded.license,
             kind = excluded.kind,
             imported_at = excluded.imported_at",
        params![name, url, license, kind, unix_now()],
    )?;
    conn.query_row(
        "SELECT id FROM intel_source WHERE name = ?1",
        params![name],
        |row| row.get(0),
    )
}

/// One fingerprint about to be written, shared by the seed loader and the
/// ja4db importer so both compute the JA4 partial match columns identically.
pub(crate) struct NewFingerprint<'a> {
    pub kind: FpKind,
    pub value: &'a str,
    pub label: &'a str,
    pub category: Category,
    pub reference: Option<&'a str>,
    pub first_seen: Option<&'a str>,
}

/// Inserts one fingerprint, lowercasing the value, filling the JA4 partial
/// match columns where they apply, and leaving any existing row untouched.
/// Returns whether a new row was written.
pub(crate) fn insert_fingerprint(
    conn: &Connection,
    source_id: i64,
    fingerprint: &NewFingerprint,
) -> rusqlite::Result<bool> {
    let value = fingerprint.value.trim().to_ascii_lowercase();
    let (part_a, part_b) = if fingerprint.kind.supports_partial() {
        match ja4_parts(&value) {
            Some((prefix, cipher)) => (Some(prefix), Some(cipher)),
            None => (None, None),
        }
    } else {
        (None, None)
    };
    let affected = conn.execute(
        "INSERT OR IGNORE INTO intel_fingerprint
             (fp_kind, value, part_a, part_b, label, category, reference, first_seen, source_id)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            fingerprint.kind.as_str(),
            value,
            part_a,
            part_b,
            fingerprint.label,
            fingerprint.category.as_str(),
            fingerprint.reference,
            fingerprint.first_seen,
            source_id,
        ],
    )?;
    Ok(affected == 1)
}

/// Recomputes and stores a feed's record count after its rows are inserted.
pub(crate) fn refresh_source_count(conn: &Connection, source_id: i64) -> rusqlite::Result<()> {
    conn.execute(
        "UPDATE intel_source
         SET record_count = (SELECT count(*) FROM intel_fingerprint WHERE source_id = ?1)
         WHERE id = ?1",
        params![source_id],
    )?;
    Ok(())
}

/// The current wall clock time in whole seconds since the Unix epoch, clamped to
/// zero if the clock is set before 1970.
pub(crate) fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_secs()).ok())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::ja4_parts;

    #[test]
    fn ja4_parts_splits_three_fields() {
        let parts = ja4_parts("t13d1516h2_8daaf6152771_e5627efa2ab1");
        assert_eq!(
            parts,
            Some(("t13d1516h2".to_string(), "8daaf6152771".to_string()))
        );
    }

    #[test]
    fn ja4_parts_rejects_wrong_shape() {
        assert_eq!(ja4_parts("nounderscores"), None);
        assert_eq!(ja4_parts("only_two"), None);
        assert_eq!(ja4_parts("a_b_c_d"), None);
        assert_eq!(ja4_parts("a__c"), None);
    }
}
