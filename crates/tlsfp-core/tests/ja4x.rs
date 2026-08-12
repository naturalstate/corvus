// ©AngelaMos | 2026
// ja4x.rs

//! Fuzz harness proving the X.509 certificate walk behind JA4X never panics.
//!
//! JA4X reads certificate bytes a passive observer takes straight off a cleartext
//! TLS 1.2 handshake, so a malformed or hostile certificate must be an ordinary
//! error rather than a crash, the same contract the TLS parser and the stream
//! reassembler hold and fuzz. This pairs with the constructed truncated
//! certificate unit test: arbitrary bytes in, never a panic out.

use proptest::prelude::*;

proptest! {
    #[test]
    fn ja4x_never_panics_on_arbitrary_bytes(
        bytes in proptest::collection::vec(any::<u8>(), 0..4096),
    ) {
        let _ = tlsfp_core::ja4x(&bytes);
    }
}
