// state.rs
//
// Everything the dashboard draws is derived from this. The producer thread
// sends `Observation`s; the render thread folds them in here and never touches
// the pipeline or the database itself.

use std::collections::{HashSet, VecDeque};
use std::time::{Duration, Instant};

use corvus_core::{FingerprintEvent, StreamEvent};
use corvus_intel::{Alert, MatchReport, MatchStrength, Verdict};

/// One fingerprint, already enriched and scored on the producer thread.
pub struct Observation {
    pub event: FingerprintEvent,
    pub reports: Vec<MatchReport>,
    pub alerts: Vec<Alert>,
}

/// How many stream rows are retained for scrollback.
const MAX_ROWS: usize = 1_000;
/// How many alerts are retained.
const MAX_ALERTS: usize = 200;
/// How many one-second buckets of throughput history are kept. The sparkline
/// slices the most recent screenful out of this, so it needs to be wider than
/// any terminal rather than a fixed display length.
const RATE_BUCKETS: usize = 600;
/// How many divergence samples the JA3/JA4 chart shows.
const MAX_DIVERGENCE: usize = 240;
/// How long a constellation point takes to fade out.
const STAR_TTL: Duration = Duration::from_secs(12);

/// The severity a row is painted with, collapsed from the intel verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tone {
    Benign,
    Unknown,
    Suspicious,
    Malicious,
}

impl Tone {
    fn from_reports(reports: &[MatchReport]) -> Self {
        reports
            .iter()
            .map(|r| match r.verdict {
                Verdict::Malicious => Self::Malicious,
                Verdict::Suspicious => Self::Suspicious,
                Verdict::Benign => Self::Benign,
                Verdict::Unknown => Self::Unknown,
            })
            .max_by_key(|t| match t {
                Self::Malicious => 3,
                Self::Suspicious => 2,
                Self::Unknown => 1,
                Self::Benign => 0,
            })
            .unwrap_or(Self::Unknown)
    }
}

/// A single line in the live stream pane.
pub struct Row {
    pub ts_nanos: u64,
    pub src: String,
    pub dst: String,
    /// `client_hello`, `server_hello`, and so on, shortened for the column.
    pub kind: &'static str,
    /// The headline fingerprint for this event kind.
    pub fingerprint: String,
    /// The JA3 hash, where the event has one.
    pub ja3: Option<String>,
    /// The pre-hash JA4 field list, which the inspector decodes.
    pub raw: Option<String>,
    pub sni: Option<String>,
    pub alpn: Option<String>,
    pub user_agent: Option<String>,
    /// The best intel label, if the fingerprint matched anything.
    pub label: Option<String>,
    /// True when the intel hit was fuzzy rather than exact.
    pub fuzzy: bool,
    pub tone: Tone,
}

/// A point on the constellation, with the instant it arrived so it can decay.
pub struct Star {
    pub ciphers: f64,
    pub extensions: f64,
    pub tone: Tone,
    pub born: Instant,
}

impl Star {
    /// 1.0 when it just arrived, falling to 0.0 at [`STAR_TTL`].
    pub fn intensity(&self, now: Instant) -> f64 {
        let age = now.duration_since(self.born).as_secs_f64();
        (1.0 - age / STAR_TTL.as_secs_f64()).clamp(0.0, 1.0)
    }
}

/// Which pane has the keyboard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Focus {
    Stream,
    Inspector,
}

pub struct AppState {
    pub rows: VecDeque<Row>,
    pub alerts: VecDeque<Alert>,
    pub stars: Vec<Star>,
    /// One sample per second: distinct JA3 hashes and distinct JA4 hashes seen.
    pub divergence: VecDeque<(f64, f64)>,
    /// Handshakes per second, most recent last.
    pub rate: VecDeque<u64>,

    ja3_seen: HashSet<String>,
    ja4_seen: HashSet<String>,

    pub selected: usize,
    pub focus: Focus,
    pub paused: bool,

    pub total: u64,
    pub started: Instant,
    bucket_started: Instant,
    bucket_count: u64,
    /// Set when the producer thread has finished and will send nothing more.
    pub source_done: bool,
}

impl AppState {
    pub fn new() -> Self {
        let now = Instant::now();
        Self {
            rows: VecDeque::with_capacity(MAX_ROWS),
            alerts: VecDeque::with_capacity(MAX_ALERTS),
            stars: Vec::new(),
            divergence: VecDeque::with_capacity(MAX_DIVERGENCE),
            rate: VecDeque::from(vec![0; RATE_BUCKETS]),
            ja3_seen: HashSet::new(),
            ja4_seen: HashSet::new(),
            selected: 0,
            focus: Focus::Stream,
            paused: false,
            total: 0,
            started: now,
            bucket_started: now,
            bucket_count: 0,
            source_done: false,
        }
    }

    /// Seconds since the dashboard started.
    pub fn uptime(&self) -> Duration {
        self.started.elapsed()
    }

    /// The row under the cursor, if the stream is not empty.
    pub fn current(&self) -> Option<&Row> {
        self.rows.get(self.selected)
    }

    pub fn fold(&mut self, observation: Observation) {
        self.total += 1;
        self.bucket_count += 1;

        let Observation {
            event,
            reports,
            alerts,
        } = observation;
        let tone = Tone::from_reports(&reports);
        let (label, fuzzy) = best_label(&reports);

        let mut ja3 = None;
        let mut raw = None;
        let mut sni = None;
        let mut alpn = None;
        let mut user_agent = None;

        let (kind, fingerprint) = match &event.event {
            StreamEvent::ClientHello {
                ja3: hash,
                ja4,
                sni: server_name,
                alpn: proto,
                ..
            } => {
                ja3 = Some(hash.to_string());
                raw = Some(ja4.raw.clone());
                sni.clone_from(server_name);
                alpn.clone_from(proto);
                self.ja3_seen.insert(hash.to_string());
                self.ja4_seen.insert(ja4.hash.clone());
                if let Some((ciphers, extensions)) = ja4_counts(&ja4.hash) {
                    self.stars.push(Star {
                        ciphers: f64::from(ciphers),
                        extensions: f64::from(extensions),
                        tone,
                        born: Instant::now(),
                    });
                }
                ("client_hello", ja4.hash.clone())
            }
            StreamEvent::ServerHello { ja3s, ja4s, .. } => {
                ja3 = Some(ja3s.to_string());
                raw = Some(ja4s.raw.clone());
                ("server_hello", ja4s.hash.clone())
            }
            StreamEvent::Certificate { ja4x } => ("certificate", ja4x.clone()),
            StreamEvent::HttpRequest {
                ja4h,
                host,
                user_agent: ua,
                ..
            } => {
                raw = Some(ja4h.raw.clone());
                sni.clone_from(host);
                user_agent.clone_from(ua);
                ("http", ja4h.hash.clone())
            }
            StreamEvent::TcpSyn { ja4t } => ("syn", ja4t.clone()),
            StreamEvent::TcpSynAck { ja4ts } => ("syn_ack", ja4ts.clone()),
        };

        self.rows.push_front(Row {
            ts_nanos: event.ts_nanos,
            src: event.src.to_string(),
            dst: event.dst.to_string(),
            kind,
            fingerprint,
            ja3,
            raw,
            sni,
            alpn,
            user_agent,
            label,
            fuzzy,
            tone,
        });
        while self.rows.len() > MAX_ROWS {
            self.rows.pop_back();
        }

        // Keep the cursor on whatever the user was looking at as rows arrive
        // above it, rather than letting the selection drift.
        if self.selected > 0 {
            self.selected = (self.selected + 1).min(self.rows.len().saturating_sub(1));
        }

        for alert in alerts {
            self.alerts.push_front(alert);
        }
        while self.alerts.len() > MAX_ALERTS {
            self.alerts.pop_back();
        }
    }

    /// Advance the one-second aggregates and expire faded constellation points.
    pub fn tick(&mut self) {
        let now = Instant::now();
        if now.duration_since(self.bucket_started) >= Duration::from_secs(1) {
            self.rate.push_back(self.bucket_count);
            while self.rate.len() > RATE_BUCKETS {
                self.rate.pop_front();
            }
            #[allow(clippy::cast_precision_loss)]
            self.divergence
                .push_back((self.ja3_seen.len() as f64, self.ja4_seen.len() as f64));
            while self.divergence.len() > MAX_DIVERGENCE {
                self.divergence.pop_front();
            }
            self.bucket_count = 0;
            self.bucket_started = now;
        }
        self.stars.retain(|s| s.intensity(now) > 0.0);
    }

    pub fn distinct_ja3(&self) -> usize {
        self.ja3_seen.len()
    }

    pub fn distinct_ja4(&self) -> usize {
        self.ja4_seen.len()
    }

    /// How many times more identities JA3 reports than JA4 for the same
    /// population. With an extension-shuffling browser on the wire this climbs
    /// without bound, which is the whole reason JA4 sorts before hashing.
    pub fn inflation(&self) -> f64 {
        let ja4 = self.ja4_seen.len();
        if ja4 == 0 {
            return 1.0;
        }
        #[allow(clippy::cast_precision_loss)]
        {
            self.ja3_seen.len() as f64 / ja4 as f64
        }
    }

    pub fn scroll(&mut self, delta: isize) {
        if self.rows.is_empty() {
            return;
        }
        let last = self.rows.len() - 1;
        self.selected = if delta.is_negative() {
            self.selected.saturating_sub(delta.unsigned_abs())
        } else {
            self.selected.saturating_add(delta.unsigned_abs()).min(last)
        };
    }
}

/// The strongest intel label across a set of reports, and whether the match
/// that produced it was fuzzy.
fn best_label(reports: &[MatchReport]) -> (Option<String>, bool) {
    // MatchStrength is deliberately not Ord upstream, so rank it here rather
    // than assuming an ordering the enum does not promise.
    const fn rank(strength: MatchStrength) -> u8 {
        match strength {
            MatchStrength::Exact => 2,
            MatchStrength::CipherAndPrefix => 1,
            MatchStrength::CipherOnly => 0,
        }
    }
    let hit = reports
        .iter()
        .flat_map(|r| r.hits.iter())
        .max_by_key(|hit| rank(hit.strength));
    match hit {
        Some(hit) => (
            Some(hit.label.clone()),
            hit.strength != MatchStrength::Exact,
        ),
        None => (None, false),
    }
}

/// Pull the cipher and extension counts out of a JA4 hash's readable prefix.
///
/// `t13d1516h2_…` is transport `t`, TLS 1.3, SNI present, **15** ciphers,
/// **16** extensions, ALPN `h2`. Those two counts are the constellation's
/// coordinates, which is why JA4's partly readable prefix is worth having.
pub fn ja4_counts(hash: &str) -> Option<(u16, u16)> {
    let prefix = hash.split('_').next()?;
    let ciphers = prefix.get(4..6)?.parse().ok()?;
    let extensions = prefix.get(6..8)?.parse().ok()?;
    Some((ciphers, extensions))
}

/// The comma-separated extension list from a JA4 raw string, for the barcode.
pub fn extensions_of(raw: &str) -> Vec<&str> {
    raw.split('_')
        .nth(2)
        .map(|s| s.split(',').filter(|s| !s.is_empty()).collect())
        .unwrap_or_default()
}

/// The comma-separated cipher list from a JA4 raw string.
pub fn ciphers_of(raw: &str) -> Vec<&str> {
    raw.split('_')
        .nth(1)
        .map(|s| s.split(',').filter(|s| !s.is_empty()).collect())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ja4_prefix_yields_the_constellation_coordinates() {
        assert_eq!(
            ja4_counts("t13d1516h2_8daaf6152771_e5627efa2ab1"),
            Some((15, 16))
        );
        assert_eq!(
            ja4_counts("q13d0310h3_55b375c5d22e_cd85d2d88918"),
            Some((3, 10))
        );
    }

    #[test]
    fn a_malformed_prefix_is_not_plotted() {
        assert_eq!(ja4_counts("short"), None);
        assert_eq!(ja4_counts("t13dxxxxh2_a_b"), None);
    }

    #[test]
    fn raw_splits_into_ciphers_and_extensions() {
        let raw = "t13d1516h2_002f,0035_0005,000a,000b_0403";
        assert_eq!(ciphers_of(raw), vec!["002f", "0035"]);
        assert_eq!(extensions_of(raw), vec!["0005", "000a", "000b"]);
    }
}
