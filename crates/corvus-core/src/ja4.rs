// ©AngelaMos | 2026
// ja4.rs

use std::fmt::Write as _;

use smallvec::SmallVec;

use crate::fingerprint::Ja4Family;
use crate::grease::is_grease;
use crate::hash::sha256_hex12;
use crate::parse::{ClientHello, ServerHello};
use crate::registry::{extension, ja4_version_code};

/// The transport that carried the handshake.
///
/// JA4 records the transport in its first character because the same TLS stack
/// produces a recognizably different ClientHello over QUIC than over TCP, and an
/// analyst wants to see that difference at a glance rather than infer it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Tcp,
    Quic,
    Dtls,
}

impl Transport {
    const fn marker(self) -> char {
        match self {
            Transport::Tcp => 't',
            Transport::Quic => 'q',
            Transport::Dtls => 'd',
        }
    }
}

const EMPTY_HASH: &str = "000000000000";

/// Computes the JA4 fingerprint of a ClientHello in both hashed and raw forms.
///
/// The fingerprint has three underscore separated sections. The first is ten
/// human readable characters: transport, version, whether SNI was present,
/// cipher count, extension count, and two characters derived from the first
/// ALPN value. The second is a truncated SHA256 of the cipher list sorted by
/// value. The third is a truncated SHA256 of the extension list sorted by value,
/// with SNI and ALPN removed and the signature algorithms appended in their
/// original order.
///
/// Sorting the cipher and extension lists before hashing is the whole reason
/// JA4 survived what killed JA3. When Chrome began shuffling its extension order
/// on every connection, JA3, which hashes extensions in wire order, produced a
/// fresh hash for every Chrome request. JA4 sorts first, so order shuffling
/// leaves the fingerprint unchanged.
#[must_use]
pub fn ja4(ch: &ClientHello, transport: Transport) -> Ja4Family {
    let prefix = ja4_prefix(ch, transport);

    let (cipher_csv, _) = sorted_hex_csv(&ch.cipher_suites, &[]);
    let cipher_hash = truncated_sha256(&cipher_csv);

    let ext_raw = ja4_extension_raw(ch);
    let ext_hash = truncated_sha256(&ext_raw);

    let hash = format!("{prefix}_{cipher_hash}_{ext_hash}");
    let raw = format!("{prefix}_{cipher_csv}_{ext_raw}");
    Ja4Family::new(hash, raw)
}

/// Computes the JA4S fingerprint of a ServerHello.
///
/// JA4S mirrors JA4 on the server side, with three differences that follow from
/// what a server controls. The server picks exactly one cipher suite, so the
/// cipher section is that single value in hex rather than a hash of a list. The
/// extensions are hashed in the order the server sent them, not sorted, because
/// a server does not shuffle its own extensions. And there is no SNI field,
/// because the server is not the party naming a host.
#[must_use]
pub fn ja4s(sh: &ServerHello, transport: Transport) -> Ja4Family {
    let version = ja4_version_code(sh.selected_version());
    let alpn = alpn_chars(sh.alpn_protocol());
    let ext_count = sh.extensions.len().min(99);

    let mut prefix = String::with_capacity(7);
    prefix.push(transport.marker());
    prefix.push_str(version);
    let _ = write!(prefix, "{ext_count:02}");
    prefix.push_str(&alpn);

    let cipher_hex = format!("{:04x}", sh.cipher_suite);

    let ext_csv = wire_order_hex_csv(
        &sh.extensions
            .iter()
            .map(|e| e.ext_type)
            .collect::<SmallVec<[u16; 16]>>(),
    );
    let ext_hash = truncated_sha256(&ext_csv);

    let hash = format!("{prefix}_{cipher_hex}_{ext_hash}");
    let raw = format!("{prefix}_{cipher_hex}_{ext_csv}");
    Ja4Family::new(hash, raw)
}

fn wire_order_hex_csv(values: &[u16]) -> String {
    let hexed: SmallVec<[String; 16]> = values.iter().map(|v| format!("{v:04x}")).collect();
    hexed.join(",")
}

fn ja4_prefix(ch: &ClientHello, transport: Transport) -> String {
    let version = select_version(ch);
    let sni = if ch.has_extension(extension::SERVER_NAME) {
        'd'
    } else {
        'i'
    };
    let cipher_count = capped_count(ch.cipher_suites.iter().copied());
    let ext_count = capped_count(ch.extensions.iter().map(|e| e.ext_type));
    let alpn = ja4_alpn(ch);

    let mut prefix = String::with_capacity(10);
    prefix.push(transport.marker());
    prefix.push_str(ja4_version_code(version));
    prefix.push(sni);
    let _ = write!(prefix, "{cipher_count:02}{ext_count:02}");
    prefix.push_str(&alpn);
    prefix
}

/// Selects the JA4 version word: the highest non GREASE value from the supported
/// versions extension when present, otherwise the legacy record version.
fn select_version(ch: &ClientHello) -> u16 {
    ch.supported_versions()
        .iter()
        .copied()
        .filter(|v| !is_grease(*v))
        .max()
        .unwrap_or(ch.legacy_version)
}

fn capped_count(values: impl Iterator<Item = u16>) -> usize {
    values.filter(|v| !is_grease(*v)).count().min(99)
}

/// Derives the two ALPN characters.
///
/// The implementation follows the published JA4 specification rather than the
/// FoxIO Python reference. The two diverge for ALPN values whose first or last
/// byte is not an ASCII alphanumeric: the specification says to print the first
/// and last characters of the hex encoding of the value, while the Python
/// reference emits a fixed fallback. The specification is the more informative
/// and more portable choice, so it is what this code does.
fn ja4_alpn(ch: &ClientHello) -> String {
    alpn_chars(ch.alpn_protocols().first().copied())
}

fn alpn_chars(first: Option<&[u8]>) -> String {
    let Some(first) = first else {
        return "00".to_string();
    };
    if first.is_empty() {
        return "00".to_string();
    }

    let first_byte = first[0];
    let last_byte = first[first.len() - 1];

    if is_ascii_alphanumeric(first_byte) && is_ascii_alphanumeric(last_byte) {
        let mut out = String::with_capacity(2);
        out.push(first_byte as char);
        out.push(last_byte as char);
        out
    } else {
        let encoded = hex::encode(first);
        let mut chars = encoded.chars();
        let first_char = chars.next().unwrap_or('0');
        let last_char = encoded.chars().last().unwrap_or('0');
        let mut out = String::with_capacity(2);
        out.push(first_char);
        out.push(last_char);
        out
    }
}

const fn is_ascii_alphanumeric(byte: u8) -> bool {
    byte.is_ascii_digit() || byte.is_ascii_uppercase() || byte.is_ascii_lowercase()
}

/// Builds the raw, pre hash extension string for section three.
///
/// The extension types are sorted by hex value after removing GREASE, SNI, and
/// ALPN. If a signature algorithms extension is present, its values are appended
/// after an underscore, in their original order. If it is absent, the string
/// ends without a trailing underscore, which is the behavior the specification
/// requires and which changes the resulting hash.
fn ja4_extension_raw(ch: &ClientHello) -> String {
    let excluded = [extension::SERVER_NAME, extension::ALPN];
    let ext_types: SmallVec<[u16; 16]> = ch.extensions.iter().map(|e| e.ext_type).collect();
    let (ext_csv, _) = sorted_hex_csv(&ext_types, &excluded);

    let sig_algs = ch.signature_algorithms();
    if ch.has_extension(extension::SIGNATURE_ALGORITHMS) {
        let sig_csv = unsorted_hex_csv(&sig_algs);
        format!("{ext_csv}_{sig_csv}")
    } else {
        ext_csv
    }
}

fn sorted_hex_csv(values: &[u16], excluded: &[u16]) -> (String, usize) {
    let mut hexed: SmallVec<[String; 32]> = values
        .iter()
        .copied()
        .filter(|v| !is_grease(*v) && !excluded.contains(v))
        .map(|v| format!("{v:04x}"))
        .collect();
    hexed.sort_unstable();
    (hexed.join(","), hexed.len())
}

fn unsorted_hex_csv(values: &[u16]) -> String {
    let hexed: SmallVec<[String; 16]> = values
        .iter()
        .copied()
        .filter(|v| !is_grease(*v))
        .map(|v| format!("{v:04x}"))
        .collect();
    hexed.join(",")
}

fn truncated_sha256(input: &str) -> String {
    if input.is_empty() {
        return EMPTY_HASH.to_string();
    }
    sha256_hex12(input.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::{EMPTY_HASH, truncated_sha256};

    #[test]
    fn empty_input_is_the_zero_hash() {
        assert_eq!(truncated_sha256(""), EMPTY_HASH);
    }

    #[test]
    fn truncation_is_twelve_hex_chars() {
        let h = truncated_sha256("1301,1302,1303");
        assert_eq!(h.len(), 12);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn foxio_cipher_section_vector() {
        let ciphers = "002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9";
        assert_eq!(truncated_sha256(ciphers), "8daaf6152771");
    }

    #[test]
    fn foxio_extension_section_vector() {
        let exts = "0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01_0403,0804,0401,0503,0805,0501,0806,0601";
        assert_eq!(truncated_sha256(exts), "e5627efa2ab1");
    }
}
