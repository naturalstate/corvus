// ©AngelaMos | 2026
// model.rs

//! Domain types for the intelligence store.
//!
//! These describe what the store holds (a fingerprint, its kind, and how its
//! label is classified) and what a lookup returns (a set of hits and the
//! verdict they add up to). The scoring lives here too, kept apart from the SQL
//! so it can be unit tested on plain values with no database in the picture.

use std::fmt;

use serde::Serialize;

/// The threat score at or above which a fingerprint is judged malicious.
const MALICIOUS_THRESHOLD: f64 = 0.8;

/// The threat score at or below which a fingerprint is judged benign; between
/// the two thresholds it is suspicious.
const BENIGN_THRESHOLD: f64 = 0.2;

/// How much a suspicious, dual use hit counts toward the threat score, half a
/// malicious vote.
const SUSPICIOUS_VOTE: f64 = 0.5;

/// The share of confidence the best match earns before corroboration, so a lone
/// exact hit is already fairly trusted and agreeing hits raise it the rest of
/// the way without ever exceeding the best match weight.
const CONFIDENCE_FLOOR: f64 = 0.6;

/// The remaining share of confidence that corroborating, aligned hits supply.
const CONFIDENCE_CORROBORATION: f64 = 0.4;

/// Which fingerprint algorithm a stored value belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FpKind {
    Ja3,
    Ja3s,
    Ja4,
    Ja4s,
    Ja4h,
    Ja4x,
    Ja4t,
    Ja4ts,
}

impl FpKind {
    /// The lowercase token used for this kind in the database and on the CLI.
    pub const fn as_str(self) -> &'static str {
        match self {
            FpKind::Ja3 => "ja3",
            FpKind::Ja3s => "ja3s",
            FpKind::Ja4 => "ja4",
            FpKind::Ja4s => "ja4s",
            FpKind::Ja4h => "ja4h",
            FpKind::Ja4x => "ja4x",
            FpKind::Ja4t => "ja4t",
            FpKind::Ja4ts => "ja4ts",
        }
    }

    /// Parses a kind token, returning `None` for anything unrecognised.
    pub fn from_token(token: &str) -> Option<Self> {
        Some(match token {
            "ja3" => FpKind::Ja3,
            "ja3s" => FpKind::Ja3s,
            "ja4" => FpKind::Ja4,
            "ja4s" => FpKind::Ja4s,
            "ja4h" => FpKind::Ja4h,
            "ja4x" => FpKind::Ja4x,
            "ja4t" => FpKind::Ja4t,
            "ja4ts" => FpKind::Ja4ts,
            _ => return None,
        })
    }

    /// Whether partial, structure aware matching applies to this kind.
    ///
    /// Only the JA4 client fingerprint carries a cipher list hash and a
    /// capability prefix that mean something on their own, so it is the only
    /// kind that supports the cipher and prefix match tiers. Everything else is
    /// either an opaque digest (JA3) or a single server side value where a
    /// partial match would not be informative.
    pub const fn supports_partial(self) -> bool {
        matches!(self, FpKind::Ja4)
    }
}

impl fmt::Display for FpKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The classification carried by a stored label, as read from a seed feed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    Malware,
    C2,
    Tool,
    Benign,
    Os,
    Unknown,
}

impl Category {
    /// The token used for this category in the database and seed files.
    pub const fn as_str(self) -> &'static str {
        match self {
            Category::Malware => "malware",
            Category::C2 => "c2",
            Category::Tool => "tool",
            Category::Benign => "benign",
            Category::Os => "os",
            Category::Unknown => "unknown",
        }
    }

    /// Parses a category token, falling back to `Unknown` for anything else so
    /// that a dirty feed value never aborts an import.
    pub fn from_token(token: &str) -> Self {
        match token.trim().to_ascii_lowercase().as_str() {
            "malware" => Category::Malware,
            "c2" => Category::C2,
            "tool" => Category::Tool,
            "benign" => Category::Benign,
            "os" => Category::Os,
            _ => Category::Unknown,
        }
    }

    /// How a hit in this category weighs on the final verdict.
    ///
    /// Command and control and malware are malicious. Dual use tooling, such as
    /// Metasploit or a Tor client, is suspicious rather than malicious because
    /// its presence is noteworthy but not proof of compromise. Benign and
    /// operating system baselines are benign. An unlabelled entry is treated as
    /// suspicious, since it was put in the store for some reason.
    pub const fn severity(self) -> Severity {
        match self {
            Category::Malware | Category::C2 => Severity::Malicious,
            Category::Tool | Category::Unknown => Severity::Suspicious,
            Category::Benign | Category::Os => Severity::Benign,
        }
    }
}

/// The coarse direction a single hit pushes the verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Malicious,
    Suspicious,
    Benign,
}

/// How closely a stored fingerprint matched the observed one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchStrength {
    /// Every byte of the fingerprint is identical.
    Exact,
    /// JA4 only: the capability prefix and the cipher hash both match but the
    /// extension hash differs, so the same client stack presented a different
    /// extension set, often just a different server name.
    CipherAndPrefix,
    /// JA4 only: the cipher hash matches but the capability prefix differs, so a
    /// different protocol or version profile is carrying the same cipher list.
    /// This is the tell of a tool that copies a browser cipher order.
    CipherOnly,
}

impl MatchStrength {
    /// The token used for this strength on the CLI and in JSON.
    pub const fn as_str(self) -> &'static str {
        match self {
            MatchStrength::Exact => "exact",
            MatchStrength::CipherAndPrefix => "cipher_and_prefix",
            MatchStrength::CipherOnly => "cipher_only",
        }
    }

    /// A weight in the range zero to one expressing how much trust a match of
    /// this strength earns when scoring.
    pub const fn weight(self) -> f64 {
        match self {
            MatchStrength::Exact => 1.0,
            MatchStrength::CipherAndPrefix => 0.8,
            MatchStrength::CipherOnly => 0.55,
        }
    }
}

/// One stored fingerprint that matched the observed one, with its provenance.
#[derive(Debug, Clone, Serialize)]
pub struct IntelHit {
    pub kind: FpKind,
    pub value: String,
    pub label: String,
    pub category: Category,
    pub source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
    pub strength: MatchStrength,
}

/// One stored fingerprint as returned by a catalogue search.
///
/// This is the browse view of the database, a row of intelligence found by a
/// free text query, rather than a hit scored against an observed value. It
/// carries no match strength because nothing was matched against it.
#[derive(Debug, Clone, Serialize)]
pub struct CatalogEntry {
    pub kind: FpKind,
    pub value: String,
    pub label: String,
    pub category: Category,
    pub source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
}

/// The judgement for an observed fingerprint after weighing every hit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Malicious,
    Suspicious,
    Benign,
    Unknown,
}

impl Verdict {
    pub const fn as_str(self) -> &'static str {
        match self {
            Verdict::Malicious => "malicious",
            Verdict::Suspicious => "suspicious",
            Verdict::Benign => "benign",
            Verdict::Unknown => "unknown",
        }
    }
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The full result of looking up one observed fingerprint.
#[derive(Debug, Clone, Serialize)]
pub struct MatchReport {
    pub kind: FpKind,
    pub observed: String,
    pub verdict: Verdict,
    pub threat_score: f64,
    pub confidence: f64,
    pub hits: Vec<IntelHit>,
}

impl MatchReport {
    /// Whether the lookup found any intelligence at all.
    pub fn has_hits(&self) -> bool {
        !self.hits.is_empty()
    }

    /// Scores a set of hits into a verdict.
    ///
    /// The threat score follows the prevalence idea from public sandboxes: a
    /// fingerprint seen mostly in malicious sources scores high, one seen mostly
    /// in benign sources scores low, and one claimed by both lands in the
    /// middle. Each hit contributes its match strength as weight, so an exact
    /// hash hit counts for more than a partial cipher hit. Suspicious, dual use
    /// hits count as half a malicious vote.
    ///
    /// Confidence is separate from the score: it says how sure the verdict is,
    /// rising with the strength of the best match and with the number of
    /// corroborating hits that agree with the verdict.
    pub fn from_hits(kind: FpKind, observed: String, hits: Vec<IntelHit>) -> Self {
        if hits.is_empty() {
            return Self {
                kind,
                observed,
                verdict: Verdict::Unknown,
                threat_score: 0.0,
                confidence: 0.0,
                hits,
            };
        }

        let mut malicious = 0.0;
        let mut suspicious = 0.0;
        let mut benign = 0.0;
        let mut best = 0.0_f64;
        for hit in &hits {
            let weight = hit.strength.weight();
            best = best.max(weight);
            match hit.category.severity() {
                Severity::Malicious => malicious += weight,
                Severity::Suspicious => suspicious += weight,
                Severity::Benign => benign += weight,
            }
        }
        let total = malicious + suspicious + benign;
        let threat_score = (malicious + SUSPICIOUS_VOTE * suspicious) / total;

        let verdict = if threat_score >= MALICIOUS_THRESHOLD {
            Verdict::Malicious
        } else if threat_score <= BENIGN_THRESHOLD {
            Verdict::Benign
        } else {
            Verdict::Suspicious
        };

        let aligned = hits
            .iter()
            .filter(|hit| verdict_aligns(verdict, hit.category.severity()))
            .count();
        let corroboration = 1.0 - 1.0 / (1.0 + count_to_f64(aligned));
        let confidence = best * (CONFIDENCE_FLOOR + CONFIDENCE_CORROBORATION * corroboration);

        Self {
            kind,
            observed,
            verdict,
            threat_score,
            confidence,
            hits,
        }
    }
}

/// Whether a hit of a given severity supports the chosen verdict, used to count
/// how many hits corroborate the result when scoring confidence.
fn verdict_aligns(verdict: Verdict, severity: Severity) -> bool {
    match verdict {
        Verdict::Malicious => severity == Severity::Malicious,
        Verdict::Benign => severity == Severity::Benign,
        Verdict::Suspicious => true,
        Verdict::Unknown => false,
    }
}

/// Converts a small count to a float without tripping the precision loss lint.
/// Intel hit counts are tiny, so saturating at `u32::MAX` is unreachable.
fn count_to_f64(n: usize) -> f64 {
    f64::from(u32::try_from(n).unwrap_or(u32::MAX))
}

#[cfg(test)]
mod tests {
    use super::{Category, FpKind, IntelHit, MatchReport, MatchStrength, Severity, Verdict};

    fn hit(category: Category, strength: MatchStrength) -> IntelHit {
        IntelHit {
            kind: FpKind::Ja3,
            value: "x".into(),
            label: "x".into(),
            category,
            source: "s".into(),
            reference: None,
            strength,
        }
    }

    #[test]
    fn kind_tokens_round_trip() {
        for kind in [
            FpKind::Ja3,
            FpKind::Ja3s,
            FpKind::Ja4,
            FpKind::Ja4s,
            FpKind::Ja4h,
            FpKind::Ja4x,
            FpKind::Ja4t,
            FpKind::Ja4ts,
        ] {
            assert_eq!(FpKind::from_token(kind.as_str()), Some(kind));
        }
        assert_eq!(FpKind::from_token("nope"), None);
    }

    #[test]
    fn only_ja4_supports_partial() {
        assert!(FpKind::Ja4.supports_partial());
        assert!(!FpKind::Ja3.supports_partial());
        assert!(!FpKind::Ja4s.supports_partial());
    }

    #[test]
    fn category_severity_mapping() {
        assert_eq!(Category::Malware.severity(), Severity::Malicious);
        assert_eq!(Category::C2.severity(), Severity::Malicious);
        assert_eq!(Category::Tool.severity(), Severity::Suspicious);
        assert_eq!(Category::Unknown.severity(), Severity::Suspicious);
        assert_eq!(Category::Benign.severity(), Severity::Benign);
        assert_eq!(Category::Os.severity(), Severity::Benign);
    }

    #[test]
    fn no_hits_is_unknown() {
        let report = MatchReport::from_hits(FpKind::Ja3, "x".into(), vec![]);
        assert_eq!(report.verdict, Verdict::Unknown);
        assert!(report.threat_score.abs() < 1e-9);
        assert!(report.confidence.abs() < 1e-9);
        assert!(!report.has_hits());
    }

    #[test]
    fn single_exact_malware_is_malicious() {
        let report = MatchReport::from_hits(
            FpKind::Ja3,
            "x".into(),
            vec![hit(Category::Malware, MatchStrength::Exact)],
        );
        assert_eq!(report.verdict, Verdict::Malicious);
        assert!((report.threat_score - 1.0).abs() < 1e-9);
        assert!((report.confidence - 0.8).abs() < 1e-9);
    }

    #[test]
    fn single_benign_is_benign() {
        let report = MatchReport::from_hits(
            FpKind::Ja3,
            "x".into(),
            vec![hit(Category::Benign, MatchStrength::Exact)],
        );
        assert_eq!(report.verdict, Verdict::Benign);
        assert!((report.threat_score - 0.0).abs() < 1e-9);
        assert!((report.confidence - 0.8).abs() < 1e-9);
    }

    #[test]
    fn malicious_and_benign_collision_is_suspicious() {
        let report = MatchReport::from_hits(
            FpKind::Ja3,
            "x".into(),
            vec![
                hit(Category::Malware, MatchStrength::Exact),
                hit(Category::Benign, MatchStrength::Exact),
            ],
        );
        assert_eq!(report.verdict, Verdict::Suspicious);
        assert!((report.threat_score - 0.5).abs() < 1e-9);
        let expected = 1.0 * (0.6 + 0.4 * (1.0 - 1.0 / 3.0));
        assert!((report.confidence - expected).abs() < 1e-9);
    }

    #[test]
    fn dual_use_tool_alone_is_suspicious() {
        let report = MatchReport::from_hits(
            FpKind::Ja3,
            "x".into(),
            vec![hit(Category::Tool, MatchStrength::Exact)],
        );
        assert_eq!(report.verdict, Verdict::Suspicious);
        assert!((report.threat_score - 0.5).abs() < 1e-9);
    }

    #[test]
    fn partial_cipher_hit_lowers_confidence() {
        let exact = MatchReport::from_hits(
            FpKind::Ja4,
            "x".into(),
            vec![hit(Category::Malware, MatchStrength::Exact)],
        );
        let partial = MatchReport::from_hits(
            FpKind::Ja4,
            "x".into(),
            vec![hit(Category::Malware, MatchStrength::CipherOnly)],
        );
        assert!(partial.confidence < exact.confidence);
        assert_eq!(partial.verdict, Verdict::Malicious);
    }

    #[test]
    fn corroboration_raises_confidence() {
        let one = MatchReport::from_hits(
            FpKind::Ja3,
            "x".into(),
            vec![hit(Category::Malware, MatchStrength::Exact)],
        );
        let three = MatchReport::from_hits(
            FpKind::Ja3,
            "x".into(),
            vec![
                hit(Category::Malware, MatchStrength::Exact),
                hit(Category::C2, MatchStrength::Exact),
                hit(Category::Malware, MatchStrength::Exact),
            ],
        );
        assert!(three.confidence > one.confidence);
        assert_eq!(three.verdict, Verdict::Malicious);
    }
}
