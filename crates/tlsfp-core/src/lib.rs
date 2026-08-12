// ©AngelaMos | 2026
// lib.rs

//! TLS handshake parsing and JA3/JA4 family fingerprint computation.
//!
//! This crate is the engine. It parses TLS records and handshake messages, the
//! TLS carried inside QUIC initial packets, and computes the JA3, JA3S, JA4,
//! JA4S, JA4H, JA4X, and JA4T fingerprints. It depends on nothing that touches
//! a network interface, a database, or an async runtime, so it can be embedded,
//! fuzzed, and unit tested in isolation.

pub mod der;
pub mod error;
pub mod fingerprint;
pub mod grease;
pub mod hash;
pub mod ja3;
pub mod ja4;
pub mod ja4h;
pub mod ja4t;
pub mod ja4x;
pub mod parse;
pub mod pipeline;
pub mod quic;
pub mod registry;

pub use error::{ParseError, Result};
pub use fingerprint::{Ja3, Ja4Family};
pub use grease::{GREASE_VALUES, is_grease};
pub use ja3::{ja3, ja3_string, ja3s, ja3s_string};
pub use ja4::{Transport, ja4, ja4s};
pub use ja4h::{HttpRequest, ja4h, parse_http_request};
pub use ja4t::{TcpFingerprintInput, ja4t};
pub use ja4x::ja4x;
pub use parse::{ClientHello, Extension, ServerHello};
pub use pipeline::event::{FingerprintEvent, StreamEvent};
pub use pipeline::source::{PacketSource, PcapFileSource, RawFrame, SourceError};
pub use pipeline::{Counters, Pipeline, PipelineConfig};
