// ©AngelaMos | 2026
// hash.rs

use sha2::{Digest, Sha256};

/// Returns the first twelve hex characters of the SHA256 digest of `bytes`.
///
/// The whole JA4 family truncates SHA256 to twelve hex characters, which is six
/// bytes of digest. Twelve characters is enough to make accidental collisions
/// vanishingly unlikely across the fingerprint space while keeping the
/// fingerprint short enough to read and to paste into a search box.
#[must_use]
pub fn sha256_hex12(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    hex::encode(&digest[..6])
}

#[cfg(test)]
mod tests {
    use super::sha256_hex12;

    #[test]
    fn known_digest_prefix() {
        assert_eq!(sha256_hex12(b""), "e3b0c44298fc");
    }
}
