// ©AngelaMos | 2026
// grease.rs

/// The sixteen GREASE values reserved by RFC 8701.
///
/// GREASE (Generate Random Extensions And Sustain Extensibility) values are
/// inserted by clients into cipher lists, extension lists, supported groups,
/// supported versions, and signature algorithms. They are deliberate noise
/// whose only purpose is to keep middleboxes tolerant of unknown values. Both
/// JA3 and JA4 strip them before hashing so that the same client produces a
/// stable fingerprint regardless of which GREASE values it happened to pick.
///
/// Every value has the form `0xZaZa` where the two bytes are equal and the low
/// nibble of each is `a`.
pub const GREASE_VALUES: [u16; 16] = [
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
    0xcaca, 0xdada, 0xeaea, 0xfafa,
];

/// Returns true when `value` is one of the sixteen RFC 8701 GREASE values.
///
/// The check exploits the structural regularity of the GREASE set rather than
/// scanning the table: both bytes must be equal and the low nibble of each must
/// be `0xa`. This is a single pair of comparisons rather than a sixteen way
/// branch, which keeps it cheap on the per packet path.
#[inline]
#[must_use]
pub const fn is_grease(value: u16) -> bool {
    let high = (value >> 8) as u8;
    let low = (value & 0x00ff) as u8;
    high == low && (low & 0x0f) == 0x0a
}

#[cfg(test)]
mod tests {
    use super::{GREASE_VALUES, is_grease};

    #[test]
    fn table_matches_structural_check() {
        for v in 0..=u16::MAX {
            let in_table = GREASE_VALUES.contains(&v);
            assert_eq!(in_table, is_grease(v), "mismatch for {v:#06x}");
        }
    }

    #[test]
    fn known_non_grease_values() {
        for v in [0x0000_u16, 0x0010, 0x1301, 0x00ff, 0x5600, 0xc02f] {
            assert!(!is_grease(v), "{v:#06x} should not be grease");
        }
    }
}
