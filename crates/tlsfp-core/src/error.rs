// ©AngelaMos | 2026
// error.rs

use thiserror::Error;

/// Errors produced while parsing TLS records, handshake messages, or QUIC
/// initial packets.
///
/// Every variant is stack only. No variant carries a heap allocation, so the
/// malformed packet path never touches the allocator. This matters because a
/// fingerprinting engine spends most of its time rejecting traffic that is not
/// a clean handshake, and allocating on each rejection adds jitter at line rate.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParseError {
    #[error("buffer too short: needed {needed} bytes, had {have}")]
    Truncated { needed: usize, have: usize },

    #[error("not a TLS handshake record (content type {0:#04x})")]
    NotHandshake(u8),

    #[error("unexpected handshake message type {0:#04x}")]
    UnexpectedHandshake(u8),

    #[error("length field {field} declares {declared} bytes but {available} remain")]
    LengthOverrun {
        field: &'static str,
        declared: usize,
        available: usize,
    },

    #[error("vector length {0} is not a whole number of elements")]
    Misaligned(usize),

    #[error("trailing {0} bytes after a complete message")]
    Trailing(usize),

    #[error("handshake message spans more bytes than the reassembly cap allows")]
    OversizedHandshake,

    #[error("malformed extension {ext_type:#06x}")]
    BadExtension { ext_type: u16 },

    #[error("not a QUIC long header initial packet")]
    NotQuicInitial,

    #[error("unsupported QUIC version {0:#010x}")]
    UnsupportedQuicVersion(u32),

    #[error("QUIC header protection or AEAD removal failed")]
    QuicCryptoFailure,
}

pub type Result<T> = core::result::Result<T, ParseError>;
