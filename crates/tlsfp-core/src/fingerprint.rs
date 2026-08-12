// ©AngelaMos | 2026
// fingerprint.rs

use core::fmt;

use serde::Serialize;

/// A JA3 or JA3S fingerprint: the MD5 digest of the pre hash string.
///
/// JA3 is carried as the raw sixteen byte digest rather than a hex string so
/// that equality, hashing, and database keys operate on the compact binary form
/// and the hex rendering happens only at display boundaries.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(into = "String")]
pub struct Ja3([u8; 16]);

impl Ja3 {
    #[must_use]
    pub const fn from_digest(digest: [u8; 16]) -> Self {
        Self(digest)
    }

    #[must_use]
    pub const fn bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl fmt::Display for Ja3 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Ja3 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Ja3({self})")
    }
}

impl From<Ja3> for String {
    fn from(value: Ja3) -> Self {
        value.to_string()
    }
}

/// A fingerprint from the JA4 family, carried in both its hashed canonical form
/// and its raw pre hash form.
///
/// The raw form is the unhashed list of cipher and extension values. It is kept
/// alongside the hash because it is the form an analyst reads when explaining
/// why two clients differ, and because clustering on the raw lists is more
/// informative than clustering on opaque digests.
#[derive(Clone, PartialEq, Eq, Hash, Serialize)]
pub struct Ja4Family {
    pub hash: String,
    pub raw: String,
}

impl Ja4Family {
    #[must_use]
    pub fn new(hash: String, raw: String) -> Self {
        Self { hash, raw }
    }
}

impl fmt::Display for Ja4Family {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.hash)
    }
}

impl fmt::Debug for Ja4Family {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Ja4Family(hash={}, raw={})", self.hash, self.raw)
    }
}

#[cfg(test)]
mod tests {
    use super::{Ja3, Ja4Family};

    #[test]
    fn ja3_display_is_lowercase_hex() {
        let fp = Ja3::from_digest([
            0xad, 0xa7, 0x02, 0x06, 0xe4, 0x06, 0x42, 0xa3, 0xe4, 0x46, 0x1f, 0x35, 0x50, 0x32,
            0x41, 0xd5,
        ]);
        assert_eq!(fp.to_string(), "ada70206e40642a3e4461f35503241d5");
    }

    #[test]
    fn ja4_family_displays_hash() {
        let fp = Ja4Family::new("t13d1516h2_8daaf6152771_e5627efa2ab1".into(), "raw".into());
        assert_eq!(fp.to_string(), "t13d1516h2_8daaf6152771_e5627efa2ab1");
    }
}
