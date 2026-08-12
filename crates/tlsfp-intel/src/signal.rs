// ©AngelaMos | 2026
// signal.rs

//! The classifiers the detection rules read fingerprints and headers through.
//!
//! These are deliberately pure: a string in, a small verdict out, no database
//! and no state. That keeps the judgement calls, which are the part most likely
//! to be wrong, testable against named example values.
//!
//! Two families of classifier live here. The first maps a fingerprint or a
//! User-Agent to a client family, so a request that calls itself a browser can
//! be checked against what its fingerprint actually is. The second maps a JA4T
//! or a User-Agent to a coarse operating-system class, so the operating system
//! a connection claims can be checked against the one its TCP stack reveals.
//!
//! The operating-system heuristic is intentionally coarse: Windows against
//! everything Unix-like. It rests on one signature that is stable across stack
//! versions and well documented: Microsoft Windows does not send the TCP
//! timestamp option (kind 8) on a SYN, while Unix-like stacks do, and within a
//! stack that sends no timestamp, Windows orders the window-scale option before
//! the SACK-permitted option where Linux without timestamps does the reverse.
//! Anything that does not match a known signature is left unclassified rather
//! than guessed, so the mismatch rule never fires on an ambiguous stack.
//!
//! Sources: the JA4T specification and the FoxIO JA4T write-up
//! (blog.foxio.io/ja4t-tcp-fingerprinting), and the p0f v3 SYN signature
//! database it builds on for the per-operating-system option layouts.

use crate::model::Category;

/// Whether `needle` appears in `haystack` as a whole word, bounded by characters
/// that are not ASCII alphanumeric. Short, ambiguous tokens like "tor" and
/// "java" are matched this way so a label such as "Factory" is not read as Tor
/// and a User-Agent mentioning "javascript" is not read as Java.
fn contains_word(haystack: &str, needle: &str) -> bool {
    haystack
        .split(|c: char| !c.is_ascii_alphanumeric())
        .any(|word| word == needle)
}

/// A coarse operating-system class, the resolution the SYN signature can carry
/// without guessing. Finer naming from one packet is not reliable, so the
/// mismatch rule works at this granularity on purpose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OsClass {
    Windows,
    Unix,
}

impl OsClass {
    /// A short token for the class, used when describing an alert.
    pub const fn as_str(self) -> &'static str {
        match self {
            OsClass::Windows => "windows",
            OsClass::Unix => "unix",
        }
    }

    /// Parses a class token back into a class, the inverse of `as_str`. This
    /// reads the operating system an observation already resolved and stored,
    /// which is not a User-Agent and must not be run back through the loose
    /// User-Agent classifier.
    pub fn from_token(token: &str) -> Option<OsClass> {
        match token {
            "windows" => Some(OsClass::Windows),
            "unix" => Some(OsClass::Unix),
            _ => None,
        }
    }
}

/// The operating system a User-Agent string claims, read from the platform
/// token every mainstream browser places near the front of the string.
///
/// Returns `None` when no platform token is recognised, so an unusual or absent
/// User-Agent never produces a false claim to compare against.
#[must_use]
pub fn ua_os_class(user_agent: &str) -> Option<OsClass> {
    const UNIX_TOKENS: &[&str] = &[
        "android",
        "linux",
        "mac os x",
        "macintosh",
        "iphone",
        "ipad",
        "ipod",
        " cros ",
        "x11",
        "freebsd",
        "openbsd",
        "netbsd",
    ];
    let ua = user_agent.to_ascii_lowercase();
    if ua.contains("windows") {
        return Some(OsClass::Windows);
    }
    if UNIX_TOKENS.iter().any(|token| ua.contains(token)) {
        return Some(OsClass::Unix);
    }
    None
}

/// The operating-system class a JA4T implies from its TCP option layout.
///
/// The JA4T value is `window_options_mss_windowscale`; only the options field,
/// a dash separated list of TCP option kind numbers, is read here. A timestamp
/// option marks a Unix-like stack. Its absence, combined with the window-scale
/// option preceding the SACK-permitted option, marks Windows. Every other
/// layout, including a Unix stack with timestamps disabled, is left
/// unclassified.
#[must_use]
pub fn ja4t_os_class(ja4t: &str) -> Option<OsClass> {
    let options = ja4t.split('_').nth(1)?;
    if options.is_empty() || options == "0" {
        return None;
    }
    let kinds: Vec<&str> = options.split('-').collect();
    if kinds.contains(&"8") {
        return Some(OsClass::Unix);
    }
    let window_scale = kinds.iter().position(|kind| *kind == "3");
    let sack = kinds.iter().position(|kind| *kind == "4");
    if let (Some(window_scale), Some(sack)) = (window_scale, sack) {
        if window_scale < sack {
            return Some(OsClass::Windows);
        }
    }
    None
}

/// A client software family, coarse enough that a fingerprint label and a
/// User-Agent can be compared even when they word the same software
/// differently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    Chrome,
    Firefox,
    Safari,
    Edge,
    Opera,
    Brave,
    Curl,
    Wget,
    Python,
    Go,
    OkHttp,
    Java,
    Tor,
}

impl Family {
    /// A short token for the family, used when describing an alert.
    pub const fn as_str(self) -> &'static str {
        match self {
            Family::Chrome => "chrome",
            Family::Firefox => "firefox",
            Family::Safari => "safari",
            Family::Edge => "edge",
            Family::Opera => "opera",
            Family::Brave => "brave",
            Family::Curl => "curl",
            Family::Wget => "wget",
            Family::Python => "python",
            Family::Go => "go-http",
            Family::OkHttp => "okhttp",
            Family::Java => "java",
            Family::Tor => "tor",
        }
    }

    /// Whether this family is a human-driven web browser rather than a script,
    /// library, or command line client. The mismatch rule turns on this line:
    /// a request that claims a browser but fingerprints as one of the others is
    /// the impersonation worth flagging.
    pub const fn is_browser(self) -> bool {
        matches!(
            self,
            Family::Chrome
                | Family::Firefox
                | Family::Safari
                | Family::Edge
                | Family::Opera
                | Family::Brave
        )
    }
}

/// The family a User-Agent string claims to be.
///
/// Browsers are checked before the engines they embed, because a Chromium
/// derivative carries the Chrome and Safari tokens too, and a script that sets
/// a real browser string would otherwise be read as that browser.
#[must_use]
pub fn ua_family(user_agent: &str) -> Option<Family> {
    let ua = user_agent.to_ascii_lowercase();
    if ua.contains("edg/") || ua.contains("edga/") || ua.contains("edgios/") {
        return Some(Family::Edge);
    }
    if ua.contains("opr/") || ua.contains("opera") {
        return Some(Family::Opera);
    }
    if ua.contains("brave") {
        return Some(Family::Brave);
    }
    if ua.contains("firefox") || ua.contains("fxios") {
        return Some(Family::Firefox);
    }
    if ua.contains("chrome") || ua.contains("chromium") || ua.contains("crios") {
        return Some(Family::Chrome);
    }
    if ua.contains("safari") {
        return Some(Family::Safari);
    }
    if ua.contains("curl") {
        return Some(Family::Curl);
    }
    if ua.contains("wget") {
        return Some(Family::Wget);
    }
    if ua.contains("python") || ua.contains("urllib") || ua.contains("aiohttp") {
        return Some(Family::Python);
    }
    if ua.contains("go-http-client") {
        return Some(Family::Go);
    }
    if ua.contains("okhttp") {
        return Some(Family::OkHttp);
    }
    if contains_word(&ua, "java") {
        return Some(Family::Java);
    }
    None
}

/// The family an intelligence label names, by keyword.
///
/// This reads the human label a feed attached to a fingerprint, so it
/// recognises the same software the User-Agent classifier does and nothing it
/// cannot name with confidence.
#[must_use]
pub fn label_family(label: &str) -> Option<Family> {
    let label = label.to_ascii_lowercase();
    if label.contains("edge") {
        return Some(Family::Edge);
    }
    if label.contains("opera") {
        return Some(Family::Opera);
    }
    if label.contains("brave") {
        return Some(Family::Brave);
    }
    if label.contains("firefox") {
        return Some(Family::Firefox);
    }
    if label.contains("chrome") || label.contains("chromium") {
        return Some(Family::Chrome);
    }
    if label.contains("safari") {
        return Some(Family::Safari);
    }
    if label.contains("curl") {
        return Some(Family::Curl);
    }
    if label.contains("wget") {
        return Some(Family::Wget);
    }
    if label.contains("python") || label.contains("requests") || label.contains("urllib") {
        return Some(Family::Python);
    }
    if label.contains("go-http") || label.contains("golang") {
        return Some(Family::Go);
    }
    if label.contains("okhttp") {
        return Some(Family::OkHttp);
    }
    if contains_word(&label, "java") {
        return Some(Family::Java);
    }
    if contains_word(&label, "tor") {
        return Some(Family::Tor);
    }
    None
}

/// Whether an observed fingerprint should be read as a non-browser client.
///
/// A label that names a script or tool says so directly. A category of tool,
/// malware, or command and control says it too, even when the label is just a
/// family name like TrickBot, because none of those are a browser. A benign or
/// unknown category with an unrecognised label is left alone, so the mismatch
/// rule needs a real reason to call something not a browser.
#[must_use]
pub fn label_is_non_browser(label: &str, category: Category) -> bool {
    if label_family(label).is_some_and(|family| !family.is_browser()) {
        return true;
    }
    matches!(category, Category::Tool | Category::Malware | Category::C2)
}

/// Whether an observed fingerprint should be read as a browser, used to suppress
/// the mismatch rule when both sides agree the client is a browser.
#[must_use]
pub fn label_is_browser(label: &str) -> bool {
    label_family(label).is_some_and(Family::is_browser)
}

#[cfg(test)]
mod tests {
    use super::{
        Family, OsClass, ja4t_os_class, label_family, label_is_browser, label_is_non_browser,
        ua_family, ua_os_class,
    };
    use crate::model::Category;

    #[test]
    fn windows_user_agent_is_windows() {
        let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0";
        assert_eq!(ua_os_class(ua), Some(OsClass::Windows));
    }

    #[test]
    fn unix_user_agents_are_unix() {
        for ua in [
            "Mozilla/5.0 (X11; Linux x86_64) Firefox/121.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)",
            "Mozilla/5.0 (Linux; Android 14) Chrome/120.0",
        ] {
            assert_eq!(ua_os_class(ua), Some(OsClass::Unix), "{ua}");
        }
    }

    #[test]
    fn unknown_platform_is_unclassified() {
        assert_eq!(ua_os_class("curl/8.4.0"), None);
        assert_eq!(ua_os_class(""), None);
    }

    #[test]
    fn ja4t_with_timestamp_is_unix() {
        assert_eq!(ja4t_os_class("29200_2-4-8-1-3_1424_7"), Some(OsClass::Unix));
        assert_eq!(ja4t_os_class("65535_2-4-8-1-3_1460_6"), Some(OsClass::Unix));
    }

    #[test]
    fn ja4t_windows_layout_is_windows() {
        assert_eq!(
            ja4t_os_class("64240_2-1-3-1-1-4_1460_8"),
            Some(OsClass::Windows)
        );
    }

    #[test]
    fn ja4t_ambiguous_layout_is_unclassified() {
        assert_eq!(ja4t_os_class("64240_2-4-1-3_1460_7"), None);
        assert_eq!(ja4t_os_class("64240_0_0_0"), None);
        assert_eq!(ja4t_os_class("nonsense"), None);
    }

    #[test]
    fn windows_scale_byte_is_not_read_as_a_timestamp_option() {
        let windows = ja4t_os_class("64240_2-1-3-1-1-4_1460_8");
        assert_eq!(windows, Some(OsClass::Windows));
    }

    #[test]
    fn os_class_tokens_round_trip() {
        assert_eq!(
            OsClass::from_token(OsClass::Windows.as_str()),
            Some(OsClass::Windows)
        );
        assert_eq!(
            OsClass::from_token(OsClass::Unix.as_str()),
            Some(OsClass::Unix)
        );
        assert_eq!(OsClass::from_token("plan9"), None);
    }

    #[test]
    fn browser_user_agents_classify() {
        assert_eq!(
            ua_family("Mozilla/5.0 (Windows NT 10.0) Gecko Firefox/121.0"),
            Some(Family::Firefox)
        );
        assert_eq!(
            ua_family(
                "Mozilla/5.0 (Macintosh) AppleWebKit/537.36 (KHTML) Chrome/120.0 Safari/537.36"
            ),
            Some(Family::Chrome)
        );
        assert_eq!(
            ua_family("Mozilla/5.0 (Macintosh) AppleWebKit/605.1 Version/17.0 Safari/605.1"),
            Some(Family::Safari)
        );
    }

    #[test]
    fn edge_and_opera_are_not_read_as_chrome() {
        assert_eq!(
            ua_family("Mozilla/5.0 (Windows NT 10.0) Chrome/120.0 Safari/537.36 Edg/120.0"),
            Some(Family::Edge)
        );
        assert_eq!(
            ua_family("Mozilla/5.0 (Windows NT 10.0) Chrome/120.0 Safari/537.36 OPR/106.0"),
            Some(Family::Opera)
        );
    }

    #[test]
    fn tool_user_agents_classify() {
        assert_eq!(ua_family("curl/8.4.0"), Some(Family::Curl));
        assert_eq!(ua_family("python-requests/2.31.0"), Some(Family::Python));
        assert_eq!(ua_family("Go-http-client/2.0"), Some(Family::Go));
    }

    #[test]
    fn labels_classify_and_categories_decide_non_browser() {
        assert_eq!(label_family("Google Chrome"), Some(Family::Chrome));
        assert_eq!(label_family("curl"), Some(Family::Curl));
        assert!(label_is_browser("Google Chrome"));
        assert!(!label_is_browser("curl"));
        assert!(label_is_non_browser("curl", Category::Benign));
        assert!(label_is_non_browser("TrickBot", Category::Malware));
        assert!(!label_is_non_browser("Google Chrome", Category::Benign));
        assert!(!label_is_non_browser("unrecognised", Category::Benign));
    }

    #[test]
    fn ambiguous_substrings_do_not_misclassify() {
        assert_eq!(label_family("Factory C2"), None);
        assert_eq!(label_family("Tor Browser"), Some(Family::Tor));
        assert_eq!(label_family("JavaScript Runtime"), None);
        assert_eq!(label_family("Java"), Some(Family::Java));
        assert_eq!(ua_family("Mozilla/5.0 javascript engine"), None);
    }
}
