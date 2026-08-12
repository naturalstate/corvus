// ©AngelaMos | 2026
// registry.rs

//! Named constants for the slices of the TLS and DTLS registries that the
//! fingerprint algorithms reference by number.
//!
//! Wire values are kept as raw `u16` everywhere in this crate rather than being
//! decoded into a closed enum. A fingerprinting engine must preserve cipher and
//! extension values it has never seen, because a future RFC value or a vendor
//! specific extension is exactly the kind of detail that makes one client
//! distinguishable from another. Decoding into a closed enum would collapse all
//! unknown values into a single bucket and corrupt the fingerprint.

/// TLS and DTLS record content types (the first byte of a record).
pub mod content_type {
    pub const CHANGE_CIPHER_SPEC: u8 = 20;
    pub const ALERT: u8 = 21;
    pub const HANDSHAKE: u8 = 22;
    pub const APPLICATION_DATA: u8 = 23;
}

/// Handshake message types (the first byte of a handshake message body).
pub mod handshake_type {
    pub const CLIENT_HELLO: u8 = 1;
    pub const SERVER_HELLO: u8 = 2;
    pub const CERTIFICATE: u8 = 11;
}

/// Extension type numbers that the fingerprint algorithms treat specially.
pub mod extension {
    pub const SERVER_NAME: u16 = 0x0000;
    pub const SUPPORTED_GROUPS: u16 = 0x000a;
    pub const EC_POINT_FORMATS: u16 = 0x000b;
    pub const SIGNATURE_ALGORITHMS: u16 = 0x000d;
    pub const ALPN: u16 = 0x0010;
    pub const SUPPORTED_VERSIONS: u16 = 0x002b;
}

/// Legacy and negotiated protocol version words.
pub mod version {
    pub const SSL_2_0: u16 = 0x0002;
    pub const SSL_3_0: u16 = 0x0300;
    pub const TLS_1_0: u16 = 0x0301;
    pub const TLS_1_1: u16 = 0x0302;
    pub const TLS_1_2: u16 = 0x0303;
    pub const TLS_1_3: u16 = 0x0304;
    pub const DTLS_1_0: u16 = 0xfeff;
    pub const DTLS_1_2: u16 = 0xfefd;
    pub const DTLS_1_3: u16 = 0xfefc;
}

/// Maps a protocol version word to the two character JA4 version code.
///
/// The mapping is taken verbatim from the FoxIO JA4 specification. Unknown
/// words collapse to `00`, which is the specified fallback. DTLS words are
/// included even though the Python reference omits them, because the published
/// specification lists them and the Wireshark and Rust references honor them.
#[must_use]
pub fn ja4_version_code(word: u16) -> &'static str {
    match word {
        version::TLS_1_3 => "13",
        version::TLS_1_2 => "12",
        version::TLS_1_1 => "11",
        version::TLS_1_0 => "10",
        version::SSL_3_0 => "s3",
        version::SSL_2_0 => "s2",
        version::DTLS_1_0 => "d1",
        version::DTLS_1_2 => "d2",
        version::DTLS_1_3 => "d3",
        _ => "00",
    }
}

#[cfg(test)]
mod tests {
    use super::ja4_version_code;
    use super::version;

    #[test]
    fn known_versions_map() {
        assert_eq!(ja4_version_code(version::TLS_1_3), "13");
        assert_eq!(ja4_version_code(version::TLS_1_2), "12");
        assert_eq!(ja4_version_code(version::SSL_3_0), "s3");
        assert_eq!(ja4_version_code(version::DTLS_1_2), "d2");
    }

    #[test]
    fn unknown_version_falls_back() {
        assert_eq!(ja4_version_code(0x7f1d), "00");
    }
}
