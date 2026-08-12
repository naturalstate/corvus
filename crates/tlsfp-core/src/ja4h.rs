// ©AngelaMos | 2026
// ja4h.rs

use crate::fingerprint::Ja4Family;
use crate::hash::sha256_hex12;

/// A parsed HTTP request, holding what JA4H reads.
///
/// JA4H fingerprints an HTTP client from one request: its method, version,
/// whether it carries cookies and a referer, the names of its other headers in
/// the order they were sent, its accept language, and its cookie names and
/// values. A request that omits an accept language and sends no cookies is far
/// more likely to be a script than a person, and JA4H makes that visible in the
/// first few characters.
///
/// This applies to cleartext HTTP only. Over HTTPS the request is encrypted and
/// invisible to a passive observer, and HTTP/2 carries its headers in HPACK,
/// which a passive tool cannot decode without following the whole connection.
#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: String,
    pub version: String,
    pub headers: Vec<(String, String)>,
}

/// Parses an HTTP/1.x request from the start of a reassembled byte stream.
///
/// Returns `None` when the bytes are not a well formed request line followed by
/// headers. Header values keep their original bytes; header names keep their
/// original case because JA4H hashes them as sent.
#[must_use]
pub fn parse_http_request(bytes: &[u8]) -> Option<HttpRequest> {
    let text = std::str::from_utf8(bytes).ok()?;
    let mut lines = text.split("\r\n");

    let request_line = lines.next()?;
    let mut parts = request_line.split(' ');
    let method = parts.next()?.to_string();
    let _target = parts.next()?;
    let http_token = parts.next()?;
    if !http_token.starts_with("HTTP/") {
        return None;
    }
    let version = http_token.trim_start_matches("HTTP/").replace('.', "");

    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        let (name, value) = line.split_once(':')?;
        headers.push((name.to_string(), value.trim_start().to_string()));
    }

    Some(HttpRequest {
        method,
        version,
        headers,
    })
}

/// Computes the JA4H fingerprint for a parsed HTTP request.
#[must_use]
pub fn ja4h(req: &HttpRequest) -> Ja4Family {
    let method = method_code(&req.method);
    let version = version_code(&req.version);
    let cookie_flag = if has_header(req, "cookie") { 'c' } else { 'n' };
    let referer_flag = if has_named_header(req, "referer") {
        'r'
    } else {
        'n'
    };

    let counted: Vec<&str> = req
        .headers
        .iter()
        .map(|(name, _)| name.as_str())
        .filter(|name| is_counted_header(name))
        .collect();
    let header_len = counted.len().min(99);
    let lang = accept_language(req);

    let prefix = format!("{method}{version}{cookie_flag}{referer_flag}{header_len:02}{lang}");
    let header_hash = sha12(&counted.join(","));

    let cookies = cookie_pairs(req);
    let (cookie_hash, value_hash, raw_cookie_tail) = if let Some(mut pairs) = cookies {
        pairs.sort_by(|a, b| a.0.cmp(&b.0));
        let names: Vec<&str> = pairs.iter().map(|p| p.0.as_str()).collect();
        let entries: Vec<&str> = pairs.iter().map(|p| p.1.as_str()).collect();
        let tail = format!("{}_{}", names.join(","), entries.join(","));
        (sha12(&names.join(",")), sha12(&entries.join(",")), tail)
    } else {
        (ZERO_HASH.to_string(), ZERO_HASH.to_string(), String::new())
    };

    let hash = format!("{prefix}_{header_hash}_{cookie_hash}_{value_hash}");
    let raw = format!("{prefix}_{}_{raw_cookie_tail}", counted.join(","));
    Ja4Family::new(hash, raw)
}

const ZERO_HASH: &str = "000000000000";

fn method_code(method: &str) -> String {
    method.to_lowercase().chars().take(2).collect()
}

fn version_code(version: &str) -> String {
    match version {
        "2" | "20" => "20".to_string(),
        "3" | "30" => "30".to_string(),
        "10" => "10".to_string(),
        _ => "11".to_string(),
    }
}

fn has_header(req: &HttpRequest, prefix_lower: &str) -> bool {
    req.headers
        .iter()
        .any(|(name, _)| name.to_lowercase().starts_with(prefix_lower))
}

fn has_named_header(req: &HttpRequest, name_lower: &str) -> bool {
    req.headers
        .iter()
        .any(|(name, _)| name.to_lowercase() == name_lower)
}

fn is_counted_header(name: &str) -> bool {
    let lower = name.to_lowercase();
    !name.starts_with(':') && !lower.starts_with("cookie") && lower != "referer" && !name.is_empty()
}

fn accept_language(req: &HttpRequest) -> String {
    let Some((_, value)) = req
        .headers
        .iter()
        .find(|(name, _)| name.to_lowercase() == "accept-language")
    else {
        return "0000".to_string();
    };
    let normalized = value.replace('-', "").replace(';', ",").to_lowercase();
    let first = normalized.split(',').next().unwrap_or("");
    let mut code: String = first.chars().take(4).collect();
    while code.len() < 4 {
        code.push('0');
    }
    code
}

fn cookie_pairs(req: &HttpRequest) -> Option<Vec<(String, String)>> {
    let (_, value) = req
        .headers
        .iter()
        .find(|(name, _)| name.to_lowercase() == "cookie")?;
    let pairs = value
        .split(';')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(|p| {
            let name = p.split('=').next().unwrap_or(p).trim().to_string();
            (name, p.to_string())
        })
        .collect();
    Some(pairs)
}

fn sha12(joined: &str) -> String {
    sha256_hex12(joined.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::{parse_http_request, version_code};

    #[test]
    fn parses_request_line_and_headers() {
        let raw = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n";
        let req = parse_http_request(raw).unwrap();
        assert_eq!(req.method, "GET");
        assert_eq!(req.version, "11");
        assert_eq!(req.headers.len(), 2);
        assert_eq!(
            req.headers[0],
            ("Host".to_string(), "example.com".to_string())
        );
    }

    #[test]
    fn version_codes() {
        assert_eq!(version_code("11"), "11");
        assert_eq!(version_code("10"), "10");
        assert_eq!(version_code("2"), "20");
    }
}
