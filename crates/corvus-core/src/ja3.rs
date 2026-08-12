// ©AngelaMos | 2026
// ja3.rs

use std::fmt::Write as _;

use md5::{Digest, Md5};
use smallvec::SmallVec;

use crate::fingerprint::Ja3;
use crate::grease::is_grease;
use crate::parse::{ClientHello, ServerHello};

/// Computes the JA3 string and digest for a ClientHello.
///
/// JA3 concatenates five fields, in order: the legacy version, the cipher
/// suites, the extension types, the supported groups, and the elliptic curve
/// point formats. Within a field the values are decimal and joined with
/// hyphens; the fields themselves are joined with commas. GREASE values are
/// removed from every list field so that the deliberate noise a client inserts
/// does not change its fingerprint. The MD5 of that string is the JA3 hash.
///
/// JA3 is kept here despite being effectively dead for modern browser traffic,
/// because malware fingerprints in public feeds are still expressed as JA3 and
/// because watching JA3 collapse next to JA4 is the clearest way to understand
/// why JA4 exists.
#[must_use]
pub fn ja3_string(ch: &ClientHello) -> String {
    let ext_types: SmallVec<[u16; 16]> = ch.extensions.iter().map(|e| e.ext_type).collect();
    let groups = ch.supported_groups();
    let formats = ch.ec_point_formats();

    let mut s = String::new();
    let _ = write!(s, "{}", ch.legacy_version);
    s.push(',');
    append_u16_hyphenated(&mut s, &ch.cipher_suites);
    s.push(',');
    append_u16_hyphenated(&mut s, &ext_types);
    s.push(',');
    append_u16_hyphenated(&mut s, &groups);
    s.push(',');
    append_u8_hyphenated(&mut s, &formats);
    s
}

/// Computes the JA3 digest for a ClientHello.
#[must_use]
pub fn ja3(ch: &ClientHello) -> Ja3 {
    digest(&ja3_string(ch))
}

/// Computes the JA3S string for a ServerHello.
///
/// JA3S mirrors JA3 on the server side with three fields: the version, the
/// single chosen cipher suite, and the extension types. A server and the exact
/// ClientHello it answered together identify a deployment more tightly than
/// either side alone.
#[must_use]
pub fn ja3s_string(sh: &ServerHello) -> String {
    let ext_types: SmallVec<[u16; 16]> = sh.extensions.iter().map(|e| e.ext_type).collect();
    let mut s = String::new();
    let _ = write!(s, "{},{},", sh.legacy_version, sh.cipher_suite);
    append_u16_hyphenated(&mut s, &ext_types);
    s
}

/// Computes the JA3S digest for a ServerHello.
#[must_use]
pub fn ja3s(sh: &ServerHello) -> Ja3 {
    digest(&ja3s_string(sh))
}

fn digest(pre_hash: &str) -> Ja3 {
    let out = Md5::digest(pre_hash.as_bytes());
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&out);
    Ja3::from_digest(bytes)
}

fn append_u16_hyphenated(out: &mut String, values: &[u16]) {
    let mut first = true;
    for &v in values {
        if is_grease(v) {
            continue;
        }
        if !first {
            out.push('-');
        }
        first = false;
        let _ = write!(out, "{v}");
    }
}

fn append_u8_hyphenated(out: &mut String, values: &[u8]) {
    let mut first = true;
    for &v in values {
        if !first {
            out.push('-');
        }
        first = false;
        let _ = write!(out, "{v}");
    }
}

#[cfg(test)]
mod tests {
    use super::digest;

    #[test]
    fn salesforce_client_vector_one() {
        let pre = "769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0";
        assert_eq!(digest(pre).to_string(), "ada70206e40642a3e4461f35503241d5");
    }

    #[test]
    fn salesforce_client_vector_two_empty_fields() {
        let pre = "769,4-5-10-9-100-98-3-6-19-18-99,,,";
        assert_eq!(digest(pre).to_string(), "de350869b8c85de67a350c8d186f11e6");
    }

    #[test]
    fn server_vector_round_trips_through_md5() {
        let pre = "769,47,65281-0-11-35-5-16";
        assert_eq!(digest(pre).to_string(), "836ce314215654b5b1f85f97c73e506f");
    }
}
