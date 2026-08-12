// ©AngelaMos | 2026
// ja4t.rs

use std::fmt::Write as _;

use smallvec::SmallVec;

/// The TCP layer inputs to a JA4T fingerprint, read from a SYN or SYN ACK.
///
/// JA4T fingerprints the TCP stack rather than the TLS stack. It is computed
/// from fields that an operating system sets the same way on every connection
/// but that differ between operating systems: the advertised window size, the
/// kinds and order of TCP options, the maximum segment size, and the window
/// scale factor. Pairing it with JA4 exposes a class of evasion that TLS only
/// fingerprinting misses, where a tool wears a browser's TLS clothing while its
/// host operating system speaks with a different TCP accent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpFingerprintInput {
    pub window_size: u16,
    pub option_kinds: SmallVec<[u8; 8]>,
    pub mss: u16,
    pub window_scale: u8,
}

/// Computes the JA4T or JA4TS string.
///
/// The format is the window size, then the option kinds joined with hyphens,
/// then the maximum segment size, then the window scale, with the four parts
/// separated by underscores. A missing MSS or window scale option is reported as
/// zero. The same function serves both the client SYN, which yields JA4T, and
/// the server SYN ACK, which yields JA4TS.
#[must_use]
pub fn ja4t(input: &TcpFingerprintInput) -> String {
    let mut options = String::new();
    let mut first = true;
    for kind in &input.option_kinds {
        if !first {
            options.push('-');
        }
        first = false;
        let _ = write!(options, "{kind}");
    }

    format!(
        "{}_{}_{}_{}",
        input.window_size, options, input.mss, input.window_scale
    )
}

#[cfg(test)]
mod tests {
    use super::{TcpFingerprintInput, ja4t};
    use smallvec::SmallVec;

    fn input(window: u16, kinds: &[u8], mss: u16, scale: u8) -> TcpFingerprintInput {
        TcpFingerprintInput {
            window_size: window,
            option_kinds: SmallVec::from_slice(kinds),
            mss,
            window_scale: scale,
        }
    }

    #[test]
    fn foxio_windows_default_vector() {
        let i = input(64240, &[2, 1, 3, 1, 1, 4], 1460, 8);
        assert_eq!(ja4t(&i), "64240_2-1-3-1-1-4_1460_8");
    }

    #[test]
    fn foxio_windowed_vector() {
        let i = input(65535, &[2, 1, 3, 1, 1, 8, 4, 0, 0], 1346, 6);
        assert_eq!(ja4t(&i), "65535_2-1-3-1-1-8-4-0-0_1346_6");
    }

    #[test]
    fn missing_mss_and_scale_report_zero() {
        let i = input(8192, &[2, 4], 0, 0);
        assert_eq!(ja4t(&i), "8192_2-4_0_0");
    }
}
