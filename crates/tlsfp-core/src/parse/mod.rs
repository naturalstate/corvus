// ©AngelaMos | 2026
// mod.rs

//! Hand written, bounds checked TLS parsing.
//!
//! The parser is deliberately not built on a parser combinator framework. It is
//! the security critical core of the tool, and the byte by byte reader here maps
//! directly onto the wire format described in the TLS RFCs, which makes it easy
//! to audit against the specification. Reassembly of fragmented handshakes is
//! handled before parsing, so every parse function sees a complete message and
//! never has to model partial input.

pub mod cert;
pub mod hello;
pub mod reader;
pub mod record;

pub use cert::{CertificateList, certificate_der_list};
pub use hello::{ClientHello, Extension, ServerHello, parse_client_hello, parse_server_hello};
pub use reader::Reader;
pub use record::{
    first_handshake_message, handshake_bytes, is_sslv2_client_hello, parse_sslv2_client_hello,
};
