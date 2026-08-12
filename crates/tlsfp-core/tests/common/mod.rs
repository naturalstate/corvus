// ©AngelaMos | 2026
// mod.rs

//! Builders that assemble TLS handshake bytes for tests.
//!
//! Hand assembling wire bytes keeps the fingerprint tests honest. Rather than
//! trusting a higher level library to produce a ClientHello, the tests state the
//! exact cipher list, extension list, and extension bodies, then assert that the
//! parser and the fingerprint algorithms read them back the way the
//! specifications require.
//!
//! Each integration test binary links this module independently, so a builder
//! method that one binary does not call reads as dead code there even though
//! another binary uses it. The allow keeps that shared infrastructure honest
//! without scattering per method annotations.
#![allow(dead_code)]

/// Assembles a ClientHello handshake message body.
#[derive(Default)]
pub struct ClientHelloBuilder {
    legacy_version: u16,
    cipher_suites: Vec<u16>,
    extensions: Vec<(u16, Vec<u8>)>,
}

impl ClientHelloBuilder {
    pub fn new() -> Self {
        Self {
            legacy_version: 0x0303,
            ..Self::default()
        }
    }

    pub fn legacy_version(mut self, v: u16) -> Self {
        self.legacy_version = v;
        self
    }

    pub fn ciphers(mut self, suites: &[u16]) -> Self {
        self.cipher_suites = suites.to_vec();
        self
    }

    pub fn extension(mut self, ext_type: u16, data: Vec<u8>) -> Self {
        self.extensions.push((ext_type, data));
        self
    }

    /// Adds a server name indication extension for the given host.
    pub fn sni(self, host: &str) -> Self {
        let host = host.as_bytes();
        let mut entry = vec![0u8];
        push_u16_vec(&mut entry, host);
        let mut data = Vec::new();
        push_u16_vec(&mut data, &entry);
        self.extension(0x0000, data)
    }

    /// Adds a supported groups extension.
    pub fn supported_groups(self, groups: &[u16]) -> Self {
        let mut list = Vec::new();
        for g in groups {
            list.extend_from_slice(&g.to_be_bytes());
        }
        let mut data = Vec::new();
        push_u16_vec(&mut data, &list);
        self.extension(0x000a, data)
    }

    /// Adds an elliptic curve point formats extension.
    pub fn ec_point_formats(self, formats: &[u8]) -> Self {
        let mut data = Vec::new();
        push_u8_vec(&mut data, formats);
        self.extension(0x000b, data)
    }

    /// Adds a signature algorithms extension.
    pub fn signature_algorithms(self, algs: &[u16]) -> Self {
        let mut list = Vec::new();
        for a in algs {
            list.extend_from_slice(&a.to_be_bytes());
        }
        let mut data = Vec::new();
        push_u16_vec(&mut data, &list);
        self.extension(0x000d, data)
    }

    /// Adds an ALPN extension advertising the given protocols.
    pub fn alpn(self, protos: &[&[u8]]) -> Self {
        let mut list = Vec::new();
        for p in protos {
            push_u8_vec(&mut list, p);
        }
        let mut data = Vec::new();
        push_u16_vec(&mut data, &list);
        self.extension(0x0010, data)
    }

    /// Adds a supported versions extension.
    pub fn supported_versions(self, versions: &[u16]) -> Self {
        let mut list = Vec::new();
        for v in versions {
            list.extend_from_slice(&v.to_be_bytes());
        }
        let mut data = Vec::new();
        push_u8_vec(&mut data, &list);
        self.extension(0x002b, data)
    }

    /// Returns the handshake message body, the input to `parse_client_hello`.
    pub fn build_body(&self) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&self.legacy_version.to_be_bytes());
        body.extend_from_slice(&[0u8; 32]);
        body.push(0);

        let mut ciphers = Vec::new();
        for c in &self.cipher_suites {
            ciphers.extend_from_slice(&c.to_be_bytes());
        }
        push_u16_vec(&mut body, &ciphers);

        push_u8_vec(&mut body, &[0]);

        let mut exts = Vec::new();
        for (ext_type, data) in &self.extensions {
            exts.extend_from_slice(&ext_type.to_be_bytes());
            push_u16_vec(&mut exts, data);
        }
        push_u16_vec(&mut body, &exts);
        body
    }

    /// Wraps the handshake body in a handshake header and a TLS record so the
    /// result is a complete record stream.
    pub fn build_record(&self) -> Vec<u8> {
        let body = self.build_body();
        let mut msg = vec![1u8];
        push_u24_vec(&mut msg, &body);

        let mut record = vec![22u8, 0x03, 0x01];
        push_u16_vec(&mut record, &msg);
        record
    }
}

fn push_u8_vec(out: &mut Vec<u8>, data: &[u8]) {
    out.push(u8::try_from(data.len()).unwrap());
    out.extend_from_slice(data);
}

fn push_u16_vec(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(&u16::try_from(data.len()).unwrap().to_be_bytes());
    out.extend_from_slice(data);
}

fn push_u24_vec(out: &mut Vec<u8>, data: &[u8]) {
    let len = u32::try_from(data.len()).unwrap();
    out.extend_from_slice(&len.to_be_bytes()[1..]);
    out.extend_from_slice(data);
}
