// ©AngelaMos | 2026
// schema.rs

//! The database schema and its migration runner.
//!
//! Versions are tracked in SQLite's own `user_version` header field rather than
//! a side table, so an empty database and a fully migrated one are told apart
//! with a single pragma and no bootstrapping. Each migration is the whole SQL
//! to move from one version to the next, applied inside a transaction so a
//! half applied schema can never be left behind. Running the migrations on an
//! already current database is a no op, which is what lets every command open
//! the store and migrate without checking first.
//!
//! Migration one is the intelligence half: feeds and the fingerprints they
//! carry. Migration two is the detection half: the observations the engine
//! records as it watches traffic and the alerts it raises when a rule fires.
//! Both tables stand on their own, so a detection run needs intelligence loaded
//! only for the rules that consult it.

use rusqlite::Connection;

/// The ordered list of migrations. Index zero moves a fresh database to version
/// one, index one to version two, and so on. Append, never edit in place, or an
/// existing database will silently disagree with a new one.
const MIGRATIONS: &[&str] = &[
    r"
CREATE TABLE intel_source (
    id           INTEGER PRIMARY KEY,
    name         TEXT NOT NULL UNIQUE,
    url          TEXT,
    license      TEXT,
    kind         TEXT NOT NULL,
    imported_at  INTEGER NOT NULL,
    record_count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE intel_fingerprint (
    id         INTEGER PRIMARY KEY,
    fp_kind    TEXT NOT NULL,
    value      TEXT NOT NULL,
    part_a     TEXT,
    part_b     TEXT,
    label      TEXT NOT NULL,
    category   TEXT NOT NULL,
    reference  TEXT,
    first_seen TEXT,
    source_id  INTEGER NOT NULL REFERENCES intel_source(id) ON DELETE CASCADE,
    UNIQUE(fp_kind, value, source_id)
);

CREATE INDEX idx_fp_kind_value  ON intel_fingerprint(fp_kind, value);
CREATE INDEX idx_fp_kind_part_b ON intel_fingerprint(fp_kind, part_b);
CREATE INDEX idx_fp_kind_part_a ON intel_fingerprint(fp_kind, part_a);
",
    r"
CREATE TABLE observation (
    id         INTEGER PRIMARY KEY,
    ts         INTEGER NOT NULL,
    ip         TEXT NOT NULL,
    fp_kind    TEXT NOT NULL,
    fp_value   TEXT NOT NULL,
    verdict    TEXT,
    label      TEXT,
    category   TEXT,
    sni        TEXT,
    host       TEXT,
    user_agent TEXT,
    os_claim   TEXT
);

CREATE INDEX idx_obs_ip       ON observation(ip);
CREATE INDEX idx_obs_ip_kind  ON observation(ip, fp_kind);
CREATE INDEX idx_obs_fp       ON observation(fp_kind, fp_value);
CREATE INDEX idx_obs_ts       ON observation(ts);

CREATE TABLE alert (
    id             INTEGER PRIMARY KEY,
    ts             INTEGER NOT NULL,
    rule           TEXT NOT NULL,
    severity       TEXT NOT NULL,
    ip             TEXT,
    fp_kind        TEXT,
    fp_value       TEXT,
    title          TEXT NOT NULL,
    detail         TEXT NOT NULL,
    score          REAL,
    observation_id INTEGER REFERENCES observation(id) ON DELETE SET NULL
);

CREATE INDEX idx_alert_ts   ON alert(ts);
CREATE INDEX idx_alert_rule ON alert(rule);
CREATE INDEX idx_alert_ip   ON alert(ip);
",
];

/// Brings a connection's schema up to the latest version, applying only the
/// migrations it is missing. Safe to call on every open.
pub fn apply_migrations(conn: &mut Connection) -> rusqlite::Result<()> {
    let mut version: i64 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
    while usize::try_from(version).unwrap_or(usize::MAX) < MIGRATIONS.len() {
        let index = usize::try_from(version).unwrap_or(usize::MAX);
        let tx = conn.transaction()?;
        tx.execute_batch(MIGRATIONS[index])?;
        tx.pragma_update(None, "user_version", version + 1)?;
        tx.commit()?;
        version += 1;
    }
    Ok(())
}

/// The schema version a fully migrated database reports, used by the tests to
/// assert the runner reaches the head of the migration list.
#[cfg(test)]
fn latest_version() -> i64 {
    i64::try_from(MIGRATIONS.len()).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::{MIGRATIONS, apply_migrations, latest_version};
    use rusqlite::Connection;

    fn user_version(conn: &Connection) -> i64 {
        conn.pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap()
    }

    #[test]
    fn migrates_a_fresh_database_to_latest() {
        let mut conn = Connection::open_in_memory().unwrap();
        assert_eq!(user_version(&conn), 0);
        apply_migrations(&mut conn).unwrap();
        assert_eq!(user_version(&conn), latest_version());
    }

    #[test]
    fn migrating_twice_is_a_no_op() {
        let mut conn = Connection::open_in_memory().unwrap();
        apply_migrations(&mut conn).unwrap();
        apply_migrations(&mut conn).unwrap();
        assert_eq!(user_version(&conn), latest_version());
    }

    #[test]
    fn expected_tables_exist() {
        let mut conn = Connection::open_in_memory().unwrap();
        apply_migrations(&mut conn).unwrap();
        let count: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE type='table' AND name IN ('intel_source','intel_fingerprint','observation','alert')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 4);
    }

    #[test]
    fn migration_two_is_appended_not_edited() {
        assert!(
            MIGRATIONS.len() >= 2,
            "detection tables live in migration two"
        );
        assert!(MIGRATIONS[0].contains("intel_fingerprint"));
        assert!(MIGRATIONS[1].contains("observation") && MIGRATIONS[1].contains("alert"));
    }
}
