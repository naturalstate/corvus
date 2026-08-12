// ©AngelaMos | 2026
// detect.rs

//! The detection engine: what turns a stream of fingerprints into alerts.
//!
//! Every fingerprint the capture pipeline produces is recorded as an
//! observation, and then six rules read the history around it. The history is
//! the database itself, not an in memory accumulator, so a rule behaves the
//! same whether it is fed a packet capture all at once or a live link one frame
//! at a time, and a long running sensor keeps its memory across restarts.
//!
//! The rules, in the order they are evaluated:
//!
//! - known bad: the fingerprint matches malicious or suspicious intelligence,
//!   raised the first time an address presents it so a repeating beacon from one
//!   host is one alert rather than one per flow.
//! - User-Agent mismatch: a request calls itself a browser while the same
//!   client's TLS fingerprint is a script or a tool. This is the headline, the
//!   lie that a fingerprint catches and a User-Agent string cannot tell.
//! - operating-system mismatch: the operating system a User-Agent claims
//!   disagrees with the one the client's TCP SYN reveals.
//! - first seen: this exact fingerprint has never been recorded before.
//! - rotation: one address has presented an unusual number of distinct
//!   fingerprints, the tell of a client cycling its identity to evade matching.
//! - monoculture: one fingerprint has appeared from an unusual number of
//!   distinct addresses, the tell of a botnet built from one toolkit.
//!
//! The two correlation rules look only backwards, at observations already
//! recorded for the same address, so a pair of flows raises one alert when the
//! second of the pair completes the picture, not two.

use anyhow::Result;
use rusqlite::{Connection, params};
use serde::Serialize;
use tlsfp_core::{FingerprintEvent, StreamEvent};

use crate::matcher::{event_fingerprints, match_one};
use crate::model::{Category, FpKind, MatchReport, Severity, Verdict};
use crate::signal::{
    OsClass, ja4t_os_class, label_is_browser, label_is_non_browser, ua_family, ua_os_class,
};

/// How far back the correlation and diversity rules look, in seconds.
const DEFAULT_WINDOW_SECS: i64 = 3600;

/// How many distinct fingerprints from one address, inside the window, count as
/// rotation rather than ordinary repeat visits.
const DEFAULT_ROTATION_THRESHOLD: i64 = 5;

/// How many distinct addresses presenting one fingerprint, inside the window,
/// count as a monoculture rather than a popular client.
const DEFAULT_MONOCULTURE_THRESHOLD: i64 = 10;

const NANOS_PER_SEC: i64 = 1_000_000_000;

/// The thresholds and window the engine runs with. The defaults suit a quiet
/// link; a busy sensor would raise them, and the tests lower them to trip a
/// rule with a handful of events.
#[derive(Debug, Clone, Copy)]
pub struct DetectConfig {
    pub window_secs: i64,
    pub rotation_threshold: i64,
    pub monoculture_threshold: i64,
}

impl Default for DetectConfig {
    fn default() -> Self {
        Self {
            window_secs: DEFAULT_WINDOW_SECS,
            rotation_threshold: DEFAULT_ROTATION_THRESHOLD,
            monoculture_threshold: DEFAULT_MONOCULTURE_THRESHOLD,
        }
    }
}

/// Which rule raised an alert, the first half of its provenance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Rule {
    KnownBad,
    UaMismatch,
    OsMismatch,
    FirstSeen,
    FpRotation,
    Monoculture,
}

impl Rule {
    /// The token stored in the database and printed on the CLI.
    pub const fn as_str(self) -> &'static str {
        match self {
            Rule::KnownBad => "known_bad",
            Rule::UaMismatch => "ua_mismatch",
            Rule::OsMismatch => "os_mismatch",
            Rule::FirstSeen => "first_seen",
            Rule::FpRotation => "fp_rotation",
            Rule::Monoculture => "monoculture",
        }
    }

    /// Parses a stored rule token, falling back to first seen for an
    /// unrecognised value so reading the feed never fails on a stray row.
    pub fn from_token(token: &str) -> Self {
        match token {
            "known_bad" => Rule::KnownBad,
            "ua_mismatch" => Rule::UaMismatch,
            "os_mismatch" => Rule::OsMismatch,
            "fp_rotation" => Rule::FpRotation,
            "monoculture" => Rule::Monoculture,
            _ => Rule::FirstSeen,
        }
    }
}

/// How much a human should care, the urgency carried alongside the rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl AlertSeverity {
    /// The token stored in the database and printed on the CLI.
    pub const fn as_str(self) -> &'static str {
        match self {
            AlertSeverity::Info => "info",
            AlertSeverity::Low => "low",
            AlertSeverity::Medium => "medium",
            AlertSeverity::High => "high",
            AlertSeverity::Critical => "critical",
        }
    }

    /// Parses a stored severity token, falling back to info for anything
    /// unrecognised so reading the feed never fails on a stray row.
    pub fn from_token(token: &str) -> Self {
        match token {
            "low" => AlertSeverity::Low,
            "medium" => AlertSeverity::Medium,
            "high" => AlertSeverity::High,
            "critical" => AlertSeverity::Critical,
            _ => AlertSeverity::Info,
        }
    }
}

/// One alert: a rule that fired, where, and the evidence that tripped it. The
/// `detail` field is the second half of the provenance, the human readable
/// reason this rule decided what it did.
#[derive(Debug, Clone, Serialize)]
pub struct Alert {
    pub ts_nanos: i64,
    pub rule: Rule,
    pub severity: AlertSeverity,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fp_kind: Option<FpKind>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fp_value: Option<String>,
    pub title: String,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub score: Option<f64>,
}

/// The fingerprint kind and value an event is recorded under, the JA4 family
/// member that names the event.
fn primary_fingerprint(event: &StreamEvent) -> (FpKind, String) {
    match event {
        StreamEvent::ClientHello { ja4, .. } => (FpKind::Ja4, ja4.hash.clone()),
        StreamEvent::ServerHello { ja4s, .. } => (FpKind::Ja4s, ja4s.hash.clone()),
        StreamEvent::Certificate { ja4x } => (FpKind::Ja4x, ja4x.clone()),
        StreamEvent::HttpRequest { ja4h, .. } => (FpKind::Ja4h, ja4h.hash.clone()),
        StreamEvent::TcpSyn { ja4t } => (FpKind::Ja4t, ja4t.clone()),
        StreamEvent::TcpSynAck { ja4ts } => (FpKind::Ja4ts, ja4ts.clone()),
    }
}

/// The context fields an event carries beyond its fingerprint: the server name
/// a TLS client asked for, and the host, User-Agent, and claimed operating
/// system an HTTP request declared.
struct Context {
    sni: Option<String>,
    host: Option<String>,
    user_agent: Option<String>,
    os_claim: Option<String>,
}

fn context_of(event: &StreamEvent) -> Context {
    match event {
        StreamEvent::ClientHello { sni, .. } => Context {
            sni: sni.clone(),
            host: None,
            user_agent: None,
            os_claim: None,
        },
        StreamEvent::HttpRequest {
            host, user_agent, ..
        } => {
            let os_claim = user_agent
                .as_deref()
                .and_then(ua_os_class)
                .map(|class| class.as_str().to_string());
            Context {
                sni: None,
                host: host.clone(),
                user_agent: user_agent.clone(),
                os_claim,
            }
        }
        _ => Context {
            sni: None,
            host: None,
            user_agent: None,
            os_claim: None,
        },
    }
}

/// Records one event and returns every alert it raised, all inside the caller's
/// transaction so the observation and its alerts commit together or not at all.
pub(crate) fn run(
    conn: &Connection,
    event: &FingerprintEvent,
    config: &DetectConfig,
) -> Result<Vec<Alert>> {
    let ts = i64::try_from(event.ts_nanos).unwrap_or(i64::MAX);
    let ip_text = event.src.ip().to_string();
    let (kind, value) = primary_fingerprint(&event.event);
    let context = context_of(&event.event);
    let since = ts.saturating_sub(config.window_secs.saturating_mul(NANOS_PER_SEC));

    let reports = lookups(conn, event)?;
    let summary = Summary::from_reports(&reports);

    let mut alerts = Vec::new();

    let fp_known = fp_seen_anywhere(conn, kind, &value)?;
    let ip_fp_known = ip_fp_seen(conn, &ip_text, kind, &value)?;

    correlate_ua_http(conn, &ip_text, since, &context, &mut alerts)?;
    correlate_ua_tls(
        conn,
        &ip_text,
        since,
        kind,
        &value,
        summary.label.as_deref(),
        summary.category,
        &mut alerts,
    )?;
    correlate_os(conn, &ip_text, since, &context, kind, &value, &mut alerts)?;

    let observation_id = insert_observation(conn, ts, &ip_text, kind, &value, &summary, &context)?;

    if !ip_fp_known {
        if let Some(alert) = known_bad(conn, ts, &ip_text, &reports, kind, &value)? {
            alerts.push(alert);
        }
    }

    if !fp_known {
        alerts.push(first_seen(ts, &ip_text, kind, &value, &summary));
    }

    if !ip_fp_known {
        let distinct = distinct_fp_for_ip(conn, &ip_text, kind, since)?;
        if distinct > config.rotation_threshold {
            alerts.push(rotation(ts, &ip_text, kind, distinct, config.window_secs));
        }
        let addresses = distinct_ip_for_fp(conn, kind, &value, since)?;
        if addresses > config.monoculture_threshold {
            alerts.push(monoculture(ts, kind, &value, addresses, config.window_secs));
        }
    }

    for alert in &mut alerts {
        alert.ts_nanos = ts;
    }
    for alert in &alerts {
        persist(conn, alert, observation_id)?;
    }

    Ok(alerts)
}

/// The intelligence reports for every fingerprint the event carries, keeping
/// only the ones that matched something, so the JA3 the public feeds index on
/// is checked alongside the JA4 the event is recorded under.
fn lookups(conn: &Connection, event: &FingerprintEvent) -> Result<Vec<MatchReport>> {
    let mut reports = Vec::new();
    for (kind, value) in event_fingerprints(event) {
        let report = match_one(conn, kind, &value)?;
        if report.has_hits() {
            reports.push(report);
        }
    }
    Ok(reports)
}

/// The most telling thing intelligence said about an event, distilled to one
/// verdict, label, and category for the observation row.
struct Summary {
    verdict: Option<Verdict>,
    label: Option<String>,
    category: Option<Category>,
}

impl Summary {
    /// Picks the worst hit across every report: the highest severity, breaking
    /// ties on match strength, so a malware label wins over a benign collision
    /// and an exact hit wins over a partial one.
    fn from_reports(reports: &[MatchReport]) -> Self {
        let mut best: Option<(u8, f64, Verdict, &str, Category)> = None;
        for report in reports {
            for hit in &report.hits {
                let rank = severity_rank(hit.category.severity());
                let weight = hit.strength.weight();
                let better = match best {
                    Some((best_rank, best_weight, ..)) => (rank, weight) > (best_rank, best_weight),
                    None => true,
                };
                if better {
                    best = Some((
                        rank,
                        weight,
                        report.verdict,
                        hit.label.as_str(),
                        hit.category,
                    ));
                }
            }
        }
        match best {
            Some((_, _, verdict, label, category)) => Self {
                verdict: Some(verdict),
                label: Some(label.to_string()),
                category: Some(category),
            },
            None => Self {
                verdict: None,
                label: None,
                category: None,
            },
        }
    }
}

fn severity_rank(severity: Severity) -> u8 {
    match severity {
        Severity::Malicious => 3,
        Severity::Suspicious => 2,
        Severity::Benign => 1,
    }
}

/// The known bad rule: if any fingerprint matched malicious or suspicious
/// intelligence, raise one alert citing the strongest report and how rare the
/// fingerprint is in what we have seen.
fn known_bad(
    conn: &Connection,
    ts: i64,
    ip: &str,
    reports: &[MatchReport],
    kind: FpKind,
    value: &str,
) -> Result<Option<Alert>> {
    let Some(report) = worst_report(reports) else {
        return Ok(None);
    };
    let severity = match report.verdict {
        Verdict::Malicious => AlertSeverity::High,
        _ => AlertSeverity::Medium,
    };
    let labels = report
        .hits
        .iter()
        .map(|hit| format!("{} ({})", hit.label, hit.source))
        .collect::<Vec<_>>()
        .join(", ");
    let (seen, total) = fp_prevalence(conn, kind, value)?;
    let detail = format!(
        "{} {} matched {}; threat {:.2} confidence {:.2}; {}",
        report.kind.as_str(),
        report.observed,
        labels,
        report.threat_score,
        report.confidence,
        prevalence_phrase(seen, total),
    );
    Ok(Some(Alert {
        ts_nanos: ts,
        rule: Rule::KnownBad,
        severity,
        ip: Some(ip.to_string()),
        fp_kind: Some(kind),
        fp_value: Some(value.to_string()),
        title: format!("fingerprint matches known {} intelligence", report.verdict),
        detail,
        score: Some(report.threat_score),
    }))
}

/// The most severe report worth alerting on, malicious before suspicious and
/// higher threat first, or nothing if every match was benign.
fn worst_report(reports: &[MatchReport]) -> Option<&MatchReport> {
    reports
        .iter()
        .filter(|report| matches!(report.verdict, Verdict::Malicious | Verdict::Suspicious))
        .max_by(|a, b| {
            verdict_rank(a.verdict)
                .cmp(&verdict_rank(b.verdict))
                .then(a.threat_score.total_cmp(&b.threat_score))
        })
}

fn verdict_rank(verdict: Verdict) -> u8 {
    match verdict {
        Verdict::Malicious => 3,
        Verdict::Suspicious => 2,
        Verdict::Benign => 1,
        Verdict::Unknown => 0,
    }
}

/// The User-Agent mismatch rule, evaluated from whichever side of the pair
/// completes it: an HTTP request claiming a browser checked against the
/// address's earlier TLS tool fingerprints, and a TLS tool fingerprint checked
/// against the address's earlier browser claims.
fn correlate_ua_http(
    conn: &Connection,
    ip: &str,
    since: i64,
    context: &Context,
    alerts: &mut Vec<Alert>,
) -> Result<()> {
    let Some(user_agent) = &context.user_agent else {
        return Ok(());
    };
    let Some(claimed) = ua_family(user_agent) else {
        return Ok(());
    };
    if !claimed.is_browser() {
        return Ok(());
    }
    for (fp_kind, fp_value, label, category) in prior_tls_labels(conn, ip, since)? {
        if label_is_non_browser(&label, category) && !label_is_browser(&label) {
            alerts.push(ua_mismatch_alert(
                ip,
                claimed.as_str(),
                user_agent,
                &fp_kind,
                &fp_value,
                &label,
                category,
            ));
            break;
        }
    }
    Ok(())
}

/// The TLS side of the User-Agent mismatch rule: when the event being recorded
/// is itself a non-browser TLS fingerprint, look back for a browser claim from
/// the same address.
#[allow(clippy::too_many_arguments)]
fn correlate_ua_tls(
    conn: &Connection,
    ip: &str,
    since: i64,
    kind: FpKind,
    value: &str,
    label: Option<&str>,
    category: Option<Category>,
    alerts: &mut Vec<Alert>,
) -> Result<()> {
    if !matches!(kind, FpKind::Ja3 | FpKind::Ja4) {
        return Ok(());
    }
    let (Some(label), Some(category)) = (label, category) else {
        return Ok(());
    };
    if !label_is_non_browser(label, category) || label_is_browser(label) {
        return Ok(());
    }
    for user_agent in prior_browser_uas(conn, ip, since)? {
        if let Some(claimed) = ua_family(&user_agent) {
            if claimed.is_browser() {
                alerts.push(ua_mismatch_alert(
                    ip,
                    claimed.as_str(),
                    &user_agent,
                    kind.as_str(),
                    value,
                    label,
                    category,
                ));
                break;
            }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn ua_mismatch_alert(
    ip: &str,
    claimed: &str,
    user_agent: &str,
    fp_kind: &str,
    fp_value: &str,
    label: &str,
    category: Category,
) -> Alert {
    Alert {
        ts_nanos: 0,
        rule: Rule::UaMismatch,
        severity: AlertSeverity::High,
        ip: Some(ip.to_string()),
        fp_kind: FpKind::from_token(fp_kind),
        fp_value: Some(fp_value.to_string()),
        title: format!("User-Agent claims {claimed} but the TLS fingerprint is not a browser"),
        detail: format!(
            "address {ip} sent User-Agent '{user_agent}' yet presented {fp_kind} {fp_value}, known as {label} ({}); a real {claimed} does not produce a {label} handshake",
            category.as_str(),
        ),
        score: None,
    }
}

/// The operating-system mismatch rule, evaluated from whichever side completes
/// it: an HTTP claim checked against the address's earlier SYN, and a SYN
/// checked against the address's earlier HTTP claim.
fn correlate_os(
    conn: &Connection,
    ip: &str,
    since: i64,
    context: &Context,
    kind: FpKind,
    value: &str,
    alerts: &mut Vec<Alert>,
) -> Result<()> {
    if let Some(user_agent) = &context.user_agent {
        let Some(claimed) = ua_os_class(user_agent) else {
            return Ok(());
        };
        for ja4t in prior_ja4t(conn, ip, since)? {
            if let Some(observed) = ja4t_os_class(&ja4t) {
                if observed != claimed {
                    alerts.push(os_mismatch_alert(
                        ip,
                        claimed.as_str(),
                        observed.as_str(),
                        &ja4t,
                        user_agent,
                    ));
                    break;
                }
            }
        }
        return Ok(());
    }

    if matches!(kind, FpKind::Ja4t) {
        if let Some(observed) = ja4t_os_class(value) {
            for (user_agent, os_claim) in prior_os_claims(conn, ip, since)? {
                if let Some(claimed) = OsClass::from_token(&os_claim) {
                    if claimed != observed {
                        alerts.push(os_mismatch_alert(
                            ip,
                            claimed.as_str(),
                            observed.as_str(),
                            value,
                            &user_agent,
                        ));
                        break;
                    }
                }
            }
        }
    }
    Ok(())
}

fn os_mismatch_alert(
    ip: &str,
    claimed: &str,
    observed: &str,
    ja4t: &str,
    user_agent: &str,
) -> Alert {
    Alert {
        ts_nanos: 0,
        rule: Rule::OsMismatch,
        severity: AlertSeverity::Medium,
        ip: Some(ip.to_string()),
        fp_kind: Some(FpKind::Ja4t),
        fp_value: Some(ja4t.to_string()),
        title: format!("User-Agent claims {claimed} but the TCP stack looks like {observed}"),
        detail: format!(
            "address {ip} sent User-Agent '{user_agent}' claiming {claimed}, but its SYN fingerprint {ja4t} matches a {observed} TCP stack",
        ),
        score: None,
    }
}

fn first_seen(ts: i64, ip: &str, kind: FpKind, value: &str, summary: &Summary) -> Alert {
    let known = match &summary.label {
        Some(label) => format!(", known as {label}"),
        None => String::new(),
    };
    Alert {
        ts_nanos: ts,
        rule: Rule::FirstSeen,
        severity: AlertSeverity::Info,
        ip: Some(ip.to_string()),
        fp_kind: Some(kind),
        fp_value: Some(value.to_string()),
        title: format!(
            "first time this {} fingerprint has been seen",
            kind.as_str()
        ),
        detail: format!(
            "{} {value} recorded for the first time{known}",
            kind.as_str()
        ),
        score: None,
    }
}

fn rotation(ts: i64, ip: &str, kind: FpKind, distinct: i64, window_secs: i64) -> Alert {
    Alert {
        ts_nanos: ts,
        rule: Rule::FpRotation,
        severity: AlertSeverity::Medium,
        ip: Some(ip.to_string()),
        fp_kind: Some(kind),
        fp_value: None,
        title: format!("address is rotating {} fingerprints", kind.as_str()),
        detail: format!(
            "address {ip} presented {distinct} distinct {} fingerprints within {window_secs}s, more than a single client explains",
            kind.as_str(),
        ),
        score: None,
    }
}

fn monoculture(ts: i64, kind: FpKind, value: &str, addresses: i64, window_secs: i64) -> Alert {
    Alert {
        ts_nanos: ts,
        rule: Rule::Monoculture,
        severity: AlertSeverity::Medium,
        ip: None,
        fp_kind: Some(kind),
        fp_value: Some(value.to_string()),
        title: format!("one {} fingerprint spans many addresses", kind.as_str()),
        detail: format!(
            "{} {value} appeared from {addresses} distinct addresses within {window_secs}s, the shape of a single toolkit run widely",
            kind.as_str(),
        ),
        score: None,
    }
}

fn prevalence_phrase(seen: i64, total: i64) -> String {
    if total <= 0 {
        return "prevalence unknown".to_string();
    }
    let pct = 100.0 * f64_of(seen) / f64_of(total);
    format!("prevalence {pct:.1}% ({seen}/{total} observations)")
}

/// Converts an observation count to a float for the prevalence percentage. A
/// non negative integer is exact in an f64 up to two to the fifty third, far
/// more rows than any observation table holds, so the precision the lint warns
/// about is never actually lost here.
#[allow(clippy::cast_precision_loss)]
fn f64_of(n: i64) -> f64 {
    n.max(0) as f64
}

fn fp_seen_anywhere(conn: &Connection, kind: FpKind, value: &str) -> Result<bool> {
    let exists: i64 = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM observation WHERE fp_kind = ?1 AND fp_value = ?2)",
        params![kind.as_str(), value],
        |row| row.get(0),
    )?;
    Ok(exists == 1)
}

fn ip_fp_seen(conn: &Connection, ip: &str, kind: FpKind, value: &str) -> Result<bool> {
    let exists: i64 = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM observation WHERE ip = ?1 AND fp_kind = ?2 AND fp_value = ?3)",
        params![ip, kind.as_str(), value],
        |row| row.get(0),
    )?;
    Ok(exists == 1)
}

fn distinct_fp_for_ip(conn: &Connection, ip: &str, kind: FpKind, since: i64) -> Result<i64> {
    let count: i64 = conn.query_row(
        "SELECT count(DISTINCT fp_value) FROM observation
         WHERE ip = ?1 AND fp_kind = ?2 AND ts >= ?3",
        params![ip, kind.as_str(), since],
        |row| row.get(0),
    )?;
    Ok(count)
}

fn distinct_ip_for_fp(conn: &Connection, kind: FpKind, value: &str, since: i64) -> Result<i64> {
    let count: i64 = conn.query_row(
        "SELECT count(DISTINCT ip) FROM observation
         WHERE fp_kind = ?1 AND fp_value = ?2 AND ts >= ?3",
        params![kind.as_str(), value, since],
        |row| row.get(0),
    )?;
    Ok(count)
}

fn fp_prevalence(conn: &Connection, kind: FpKind, value: &str) -> Result<(i64, i64)> {
    let seen: i64 = conn.query_row(
        "SELECT count(*) FROM observation WHERE fp_kind = ?1 AND fp_value = ?2",
        params![kind.as_str(), value],
        |row| row.get(0),
    )?;
    let total: i64 = conn.query_row("SELECT count(*) FROM observation", [], |row| row.get(0))?;
    Ok((seen, total))
}

fn prior_tls_labels(
    conn: &Connection,
    ip: &str,
    since: i64,
) -> Result<Vec<(String, String, String, Category)>> {
    let mut statement = conn.prepare(
        "SELECT fp_kind, fp_value, label, category FROM observation
         WHERE ip = ?1 AND fp_kind IN ('ja3', 'ja4') AND label IS NOT NULL AND ts >= ?2
         ORDER BY ts DESC",
    )?;
    let rows = statement
        .query_map(params![ip, since], |row| {
            let kind: String = row.get(0)?;
            let value: String = row.get(1)?;
            let label: String = row.get(2)?;
            let category: String = row.get(3)?;
            Ok((kind, value, label, category))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows
        .into_iter()
        .map(|(kind, value, label, category)| (kind, value, label, Category::from_token(&category)))
        .collect())
}

fn prior_browser_uas(conn: &Connection, ip: &str, since: i64) -> Result<Vec<String>> {
    let mut statement = conn.prepare(
        "SELECT user_agent FROM observation
         WHERE ip = ?1 AND fp_kind = 'ja4h' AND user_agent IS NOT NULL AND ts >= ?2
         ORDER BY ts DESC",
    )?;
    let rows = statement
        .query_map(params![ip, since], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

fn prior_ja4t(conn: &Connection, ip: &str, since: i64) -> Result<Vec<String>> {
    let mut statement = conn.prepare(
        "SELECT fp_value FROM observation
         WHERE ip = ?1 AND fp_kind = 'ja4t' AND ts >= ?2
         ORDER BY ts DESC",
    )?;
    let rows = statement
        .query_map(params![ip, since], |row| row.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

fn prior_os_claims(conn: &Connection, ip: &str, since: i64) -> Result<Vec<(String, String)>> {
    let mut statement = conn.prepare(
        "SELECT user_agent, os_claim FROM observation
         WHERE ip = ?1 AND fp_kind = 'ja4h' AND os_claim IS NOT NULL AND ts >= ?2
         ORDER BY ts DESC",
    )?;
    let rows = statement
        .query_map(params![ip, since], |row| {
            let user_agent: Option<String> = row.get(0)?;
            let os_claim: String = row.get(1)?;
            Ok((user_agent.unwrap_or_default(), os_claim))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

#[allow(clippy::too_many_arguments)]
fn insert_observation(
    conn: &Connection,
    ts: i64,
    ip: &str,
    kind: FpKind,
    value: &str,
    summary: &Summary,
    context: &Context,
) -> Result<i64> {
    conn.execute(
        "INSERT INTO observation
            (ts, ip, fp_kind, fp_value, verdict, label, category, sni, host, user_agent, os_claim)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            ts,
            ip,
            kind.as_str(),
            value,
            summary.verdict.map(Verdict::as_str),
            summary.label,
            summary.category.map(Category::as_str),
            context.sni,
            context.host,
            context.user_agent,
            context.os_claim,
        ],
    )?;
    Ok(conn.last_insert_rowid())
}

fn persist(conn: &Connection, alert: &Alert, observation_id: i64) -> Result<()> {
    let observation_id = match alert.rule {
        Rule::Monoculture => None,
        _ => Some(observation_id),
    };
    conn.execute(
        "INSERT INTO alert
            (ts, rule, severity, ip, fp_kind, fp_value, title, detail, score, observation_id)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            alert.ts_nanos,
            alert.rule.as_str(),
            alert.severity.as_str(),
            alert.ip,
            alert.fp_kind.map(FpKind::as_str),
            alert.fp_value,
            alert.title,
            alert.detail,
            alert.score,
            observation_id,
        ],
    )?;
    Ok(())
}

/// The most recent alerts, newest first, for the CLI feed and the dashboard.
pub(crate) fn recent(conn: &Connection, limit: i64) -> Result<Vec<Alert>> {
    let mut statement = conn.prepare(
        "SELECT ts, rule, severity, ip, fp_kind, fp_value, title, detail, score
         FROM alert ORDER BY ts DESC, id DESC LIMIT ?1",
    )?;
    let rows = statement
        .query_map(params![limit], |row| {
            let rule: String = row.get(1)?;
            let severity: String = row.get(2)?;
            let fp_kind: Option<String> = row.get(4)?;
            Ok(Alert {
                ts_nanos: row.get(0)?,
                rule: Rule::from_token(&rule),
                severity: AlertSeverity::from_token(&severity),
                ip: row.get(3)?,
                fp_kind: fp_kind.and_then(|token| FpKind::from_token(&token)),
                fp_value: row.get(5)?,
                title: row.get(6)?,
                detail: row.get(7)?,
                score: row.get(8)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

/// A small count of alerts per rule, for the stats summary.
pub(crate) fn counts_by_rule(conn: &Connection) -> Result<Vec<(Rule, i64)>> {
    let mut statement =
        conn.prepare("SELECT rule, count(*) FROM alert GROUP BY rule ORDER BY count(*) DESC")?;
    let rows = statement
        .query_map([], |row| {
            let rule: String = row.get(0)?;
            let count: i64 = row.get(1)?;
            Ok((Rule::from_token(&rule), count))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

/// Alerts recorded after a given row id, oldest first, for a reader tailing the
/// store as new detections land. Alert ids are assigned in insertion order, so
/// a poller that remembers the highest id it has emitted never replays one.
pub(crate) fn since(conn: &Connection, after_id: i64, limit: i64) -> Result<Vec<(i64, Alert)>> {
    let mut statement = conn.prepare(
        "SELECT id, ts, rule, severity, ip, fp_kind, fp_value, title, detail, score
         FROM alert WHERE id > ?1 ORDER BY id ASC LIMIT ?2",
    )?;
    let rows = statement
        .query_map(params![after_id, limit], |row| {
            let id: i64 = row.get(0)?;
            let rule: String = row.get(2)?;
            let severity: String = row.get(3)?;
            let fp_kind: Option<String> = row.get(5)?;
            Ok((
                id,
                Alert {
                    ts_nanos: row.get(1)?,
                    rule: Rule::from_token(&rule),
                    severity: AlertSeverity::from_token(&severity),
                    ip: row.get(4)?,
                    fp_kind: fp_kind.and_then(|token| FpKind::from_token(&token)),
                    fp_value: row.get(6)?,
                    title: row.get(7)?,
                    detail: row.get(8)?,
                    score: row.get(9)?,
                },
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

/// The highest alert id currently stored, or zero when the table is empty. A
/// tailing reader starts here so it streams only alerts raised after it began
/// watching, not the whole history.
pub(crate) fn max_id(conn: &Connection) -> Result<i64> {
    let id: i64 = conn.query_row("SELECT COALESCE(MAX(id), 0) FROM alert", [], |row| {
        row.get(0)
    })?;
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::{
        AlertSeverity, Rule, Summary, prevalence_phrase, severity_rank, verdict_rank, worst_report,
    };
    use crate::model::{Category, FpKind, IntelHit, MatchReport, MatchStrength, Severity, Verdict};

    fn hit(category: Category, strength: MatchStrength, label: &str) -> IntelHit {
        IntelHit {
            kind: FpKind::Ja4,
            value: "v".into(),
            label: label.into(),
            category,
            source: "feed".into(),
            reference: None,
            strength,
        }
    }

    #[test]
    fn summary_keeps_the_worst_hit() {
        let report = MatchReport::from_hits(
            FpKind::Ja4,
            "x".into(),
            vec![
                hit(Category::Benign, MatchStrength::Exact, "java"),
                hit(Category::Malware, MatchStrength::Exact, "TrickBot"),
            ],
        );
        let summary = Summary::from_reports(&[report]);
        assert_eq!(summary.category, Some(Category::Malware));
        assert_eq!(summary.label.as_deref(), Some("TrickBot"));
    }

    #[test]
    fn summary_of_nothing_is_empty() {
        let summary = Summary::from_reports(&[]);
        assert!(summary.verdict.is_none());
        assert!(summary.label.is_none());
        assert!(summary.category.is_none());
    }

    #[test]
    fn worst_report_ignores_benign_and_prefers_malicious() {
        let benign = MatchReport::from_hits(
            FpKind::Ja4,
            "x".into(),
            vec![hit(Category::Benign, MatchStrength::Exact, "Chrome")],
        );
        assert!(worst_report(std::slice::from_ref(&benign)).is_none());

        let malicious = MatchReport::from_hits(
            FpKind::Ja3,
            "y".into(),
            vec![hit(Category::Malware, MatchStrength::Exact, "Bad")],
        );
        let suspicious = MatchReport::from_hits(
            FpKind::Ja4,
            "z".into(),
            vec![hit(Category::Tool, MatchStrength::Exact, "Tool")],
        );
        let reports = [benign, suspicious, malicious];
        let chosen = worst_report(&reports).unwrap();
        assert_eq!(chosen.verdict, Verdict::Malicious);
    }

    #[test]
    fn prevalence_phrase_handles_empty_and_normal() {
        assert_eq!(prevalence_phrase(0, 0), "prevalence unknown");
        assert_eq!(
            prevalence_phrase(1, 4),
            "prevalence 25.0% (1/4 observations)"
        );
    }

    #[test]
    fn rank_helpers_order_correctly() {
        assert!(severity_rank(Severity::Malicious) > severity_rank(Severity::Suspicious));
        assert!(severity_rank(Severity::Suspicious) > severity_rank(Severity::Benign));
        assert!(verdict_rank(Verdict::Malicious) > verdict_rank(Verdict::Benign));
        assert!(verdict_rank(Verdict::Benign) > verdict_rank(Verdict::Unknown));
    }

    #[test]
    fn alert_severity_is_ordered() {
        assert!(AlertSeverity::Critical > AlertSeverity::High);
        assert!(AlertSeverity::High > AlertSeverity::Medium);
        assert!(AlertSeverity::Medium > AlertSeverity::Low);
        assert!(AlertSeverity::Low > AlertSeverity::Info);
    }

    #[test]
    fn rule_tokens_round_trip() {
        for rule in [
            Rule::KnownBad,
            Rule::UaMismatch,
            Rule::OsMismatch,
            Rule::FirstSeen,
            Rule::FpRotation,
            Rule::Monoculture,
        ] {
            assert_eq!(Rule::from_token(rule.as_str()), rule);
        }
        assert_eq!(Rule::from_token("garbage"), Rule::FirstSeen);
    }

    #[test]
    fn severity_tokens_round_trip() {
        for severity in [
            AlertSeverity::Info,
            AlertSeverity::Low,
            AlertSeverity::Medium,
            AlertSeverity::High,
            AlertSeverity::Critical,
        ] {
            assert_eq!(AlertSeverity::from_token(severity.as_str()), severity);
        }
        assert_eq!(AlertSeverity::from_token("garbage"), AlertSeverity::Info);
    }
}
