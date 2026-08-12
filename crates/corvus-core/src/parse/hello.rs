// ©AngelaMos | 2026
// hello.rs

use smallvec::SmallVec;

use crate::error::Result;
use crate::parse::reader::Reader;
use crate::registry::extension;

/// A single TLS extension as it appeared on the wire.
///
/// The extension body is borrowed from the packet, not copied. Specific
/// extensions are decoded on demand through the accessor methods on
/// [`ClientHello`] so that the common parse path does no work for extensions a
/// given fingerprint does not read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Extension<'pkt> {
    pub ext_type: u16,
    pub data: &'pkt [u8],
}

/// A parsed ClientHello, holding exactly what the fingerprint algorithms read.
///
/// Cipher suites and extensions are stored in wire order. Order is preserved
/// because JA3 hashes extensions in their original order, and because the
/// difference between wire order and sorted order is itself a signal: a client
/// that permutes its extension order on every connection is doing something a
/// fixed order client is not.
#[derive(Debug, Clone)]
pub struct ClientHello<'pkt> {
    pub legacy_version: u16,
    pub cipher_suites: SmallVec<[u16; 32]>,
    pub extensions: SmallVec<[Extension<'pkt>; 16]>,
    pub is_sslv2: bool,
}

/// A parsed ServerHello.
///
/// The server selects exactly one cipher suite, so `cipher_suite` is a single
/// value rather than a list. Extensions are again kept in wire order.
#[derive(Debug, Clone)]
pub struct ServerHello<'pkt> {
    pub legacy_version: u16,
    pub cipher_suite: u16,
    pub extensions: SmallVec<[Extension<'pkt>; 16]>,
}

fn parse_extensions<'pkt>(r: &mut Reader<'pkt>) -> Result<SmallVec<[Extension<'pkt>; 16]>> {
    let mut exts = SmallVec::new();
    if r.is_empty() {
        return Ok(exts);
    }
    let mut block = r.sub_u16_vec()?;
    while !block.is_empty() {
        let ext_type = block.u16()?;
        let data = block.take_u16_vec()?;
        exts.push(Extension { ext_type, data });
    }
    Ok(exts)
}

/// Parses the body of a ClientHello handshake message.
///
/// The input is the message body, meaning the four byte handshake header has
/// already been stripped. The session id, which fingerprinting ignores, is
/// skipped, as are the compression methods; getting those two skips right is a
/// classic source of bugs because a parser that forgets them reads the wrong
/// bytes as cipher suites.
pub fn parse_client_hello(body: &[u8]) -> Result<ClientHello<'_>> {
    let mut r = Reader::new(body);
    let legacy_version = r.u16()?;
    let _random = r.take(32)?;
    let _session_id = r.take_u8_vec()?;

    let mut cipher_reader = r.sub_u16_vec()?;
    let mut cipher_suites = SmallVec::new();
    while !cipher_reader.is_empty() {
        cipher_suites.push(cipher_reader.u16()?);
    }

    let _compression = r.take_u8_vec()?;
    let extensions = parse_extensions(&mut r)?;

    Ok(ClientHello {
        legacy_version,
        cipher_suites,
        extensions,
        is_sslv2: false,
    })
}

/// Parses the body of a ServerHello handshake message.
pub fn parse_server_hello(body: &[u8]) -> Result<ServerHello<'_>> {
    let mut r = Reader::new(body);
    let legacy_version = r.u16()?;
    let _random = r.take(32)?;
    let _session_id = r.take_u8_vec()?;
    let cipher_suite = r.u16()?;
    let _compression = r.u8()?;
    let extensions = parse_extensions(&mut r)?;

    Ok(ServerHello {
        legacy_version,
        cipher_suite,
        extensions,
    })
}

impl<'pkt> ServerHello<'pkt> {
    fn extension(&self, ext_type: u16) -> Option<&Extension<'pkt>> {
        self.extensions.iter().find(|e| e.ext_type == ext_type)
    }

    /// Returns the version the server selected.
    ///
    /// In TLS 1.3 the negotiated version lives in the supported versions
    /// extension as a single value rather than in the legacy version word, which
    /// the server pins to TLS 1.2 for compatibility. JA4S reads the real version
    /// from the extension when it is present.
    #[must_use]
    pub fn selected_version(&self) -> u16 {
        self.extension(extension::SUPPORTED_VERSIONS)
            .and_then(|ext| {
                let mut r = Reader::new(ext.data);
                r.u16().ok()
            })
            .unwrap_or(self.legacy_version)
    }

    /// Returns the ALPN protocol the server chose, if any.
    #[must_use]
    pub fn alpn_protocol(&self) -> Option<&'pkt [u8]> {
        let ext = self.extension(extension::ALPN)?;
        let mut r = Reader::new(ext.data);
        let mut list = r.sub_u16_vec().ok()?;
        list.take_u8_vec().ok().filter(|p| !p.is_empty())
    }
}

impl<'pkt> ClientHello<'pkt> {
    fn extension(&self, ext_type: u16) -> Option<&Extension<'pkt>> {
        self.extensions.iter().find(|e| e.ext_type == ext_type)
    }

    #[must_use]
    pub fn has_extension(&self, ext_type: u16) -> bool {
        self.extension(ext_type).is_some()
    }

    /// Returns the server name from the SNI extension, if a host name entry is
    /// present.
    #[must_use]
    pub fn server_name(&self) -> Option<&'pkt str> {
        let ext = self.extension(extension::SERVER_NAME)?;
        let mut list = Reader::new(ext.data).sub_u16_vec().ok()?;
        while !list.is_empty() {
            let name_type = list.u8().ok()?;
            let name = list.take_u16_vec().ok()?;
            if name_type == 0 {
                return core::str::from_utf8(name).ok();
            }
        }
        None
    }

    /// Returns the supported groups, the field JA3 calls elliptic curves.
    #[must_use]
    pub fn supported_groups(&self) -> SmallVec<[u16; 16]> {
        self.u16_list(extension::SUPPORTED_GROUPS)
    }

    /// Returns the elliptic curve point formats.
    #[must_use]
    pub fn ec_point_formats(&self) -> SmallVec<[u8; 4]> {
        let mut out = SmallVec::new();
        let Some(ext) = self.extension(extension::EC_POINT_FORMATS) else {
            return out;
        };
        let mut r = Reader::new(ext.data);
        let Ok(list) = r.take_u8_vec() else {
            return out;
        };
        out.extend_from_slice(list);
        out
    }

    /// Returns the protocol versions the client offers in the supported versions
    /// extension. JA4 selects its version field from the highest non GREASE
    /// value here when the extension is present.
    #[must_use]
    pub fn supported_versions(&self) -> SmallVec<[u16; 8]> {
        let mut out = SmallVec::new();
        let Some(ext) = self.extension(extension::SUPPORTED_VERSIONS) else {
            return out;
        };
        let mut r = Reader::new(ext.data);
        let Ok(list) = r.take_u8_vec() else {
            return out;
        };
        let mut inner = Reader::new(list);
        while let Ok(v) = inner.u16() {
            out.push(v);
        }
        out
    }

    /// Returns the signature algorithms in their original order. JA4 appends
    /// these, unsorted, to the extension hash input.
    #[must_use]
    pub fn signature_algorithms(&self) -> SmallVec<[u16; 16]> {
        self.u16_list(extension::SIGNATURE_ALGORITHMS)
    }

    /// Returns the ALPN protocol identifiers in order. JA4 uses the first one.
    #[must_use]
    pub fn alpn_protocols(&self) -> SmallVec<[&'pkt [u8]; 4]> {
        let mut out = SmallVec::new();
        let Some(ext) = self.extension(extension::ALPN) else {
            return out;
        };
        let mut r = Reader::new(ext.data);
        let Ok(mut list) = r.sub_u16_vec() else {
            return out;
        };
        while let Ok(proto) = list.take_u8_vec() {
            out.push(proto);
        }
        out
    }

    fn u16_list(&self, ext_type: u16) -> SmallVec<[u16; 16]> {
        let mut out = SmallVec::new();
        let Some(ext) = self.extension(ext_type) else {
            return out;
        };
        let mut r = Reader::new(ext.data);
        let Ok(list) = r.take_u16_vec() else {
            return out;
        };
        let mut inner = Reader::new(list);
        while let Ok(v) = inner.u16() {
            out.push(v);
        }
        out
    }
}
