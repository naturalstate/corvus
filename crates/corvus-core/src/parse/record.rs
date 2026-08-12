// ©AngelaMos | 2026
// record.rs

use std::borrow::Cow;

use smallvec::SmallVec;

use crate::error::{ParseError, Result};
use crate::parse::hello::ClientHello;
use crate::parse::reader::Reader;
use crate::registry::content_type;

/// Reassembles the cleartext handshake flight from a TLS record stream.
///
/// A handshake message can be split across several TLS records, and several
/// short messages can share one record. This walks the record framing and
/// concatenates the payloads of the handshake records so the caller sees one
/// contiguous handshake byte stream. The common case is a single record holding
/// a single ClientHello, and that case borrows the original bytes with no copy.
/// Only genuinely fragmented flights allocate.
///
/// Records carrying anything other than handshake data are ignored. In TLS 1.3
/// the later handshake messages travel inside records typed as application data
/// and are encrypted, so they never reach this function, which is correct: the
/// only handshake bytes we can read in the clear are the first flight.
pub fn handshake_bytes(stream: &[u8]) -> Result<Cow<'_, [u8]>> {
    let mut segments: SmallVec<[&[u8]; 4]> = SmallVec::new();
    let mut r = Reader::new(stream);

    while r.remaining() >= 5 {
        let ctype = r.u8()?;
        let _version = r.u16()?;
        let payload = r.take_u16_vec()?;
        if ctype == content_type::HANDSHAKE {
            segments.push(payload);
        } else if !segments.is_empty() {
            break;
        }
    }

    match segments.as_slice() {
        [] => Err(ParseError::Truncated {
            needed: 5,
            have: stream.len(),
        }),
        [only] => Ok(Cow::Borrowed(*only)),
        many => {
            let mut joined = Vec::with_capacity(many.iter().map(|s| s.len()).sum());
            for seg in many {
                joined.extend_from_slice(seg);
            }
            Ok(Cow::Owned(joined))
        }
    }
}

/// Returns the body of the first handshake message of the requested type.
///
/// The handshake header is a one byte type and a three byte length. This walks
/// the messages in the reassembled flight and returns the body slice of the
/// first one whose type matches, so the caller never has to reason about the
/// header widths.
pub fn first_handshake_message(handshake: &[u8], want_type: u8) -> Result<&[u8]> {
    let mut r = Reader::new(handshake);
    while r.remaining() >= 4 {
        let msg_type = r.u8()?;
        let len = r.u24()? as usize;
        let body = r.take(len)?;
        if msg_type == want_type {
            return Ok(body);
        }
    }
    Err(ParseError::UnexpectedHandshake(want_type))
}

/// Returns true when the stream begins with an SSLv2 style ClientHello.
///
/// SSLv2 framing sets the high bit of the first length byte and places the
/// message type in the first body byte. Type 1 is CLIENT-HELLO. Some old
/// malware opens with this backward compatible hello even when it intends to
/// negotiate TLS, so detecting it keeps the TLS parser from misreading the
/// SSLv2 header as a TLS record.
#[must_use]
pub fn is_sslv2_client_hello(stream: &[u8]) -> bool {
    stream.len() >= 3 && (stream[0] & 0x80) != 0 && stream[2] == 1
}

/// Parses an SSLv2 style ClientHello into the common ClientHello shape.
///
/// SSLv2 carries no extensions, supported groups, or point formats, so those
/// stay empty, which matches the community consensus for fingerprinting an
/// SSLv2 hello. Cipher specs are three bytes each. Specs that begin with a zero
/// byte are SSLv3 and TLS cipher suites carried in the backward compatible
/// hello, and those are the values a fingerprint cares about, so they are
/// extracted as their two byte suite numbers. True SSLv2 only specs are
/// counted but cannot be expressed as two byte suites and are skipped.
pub fn parse_sslv2_client_hello(stream: &[u8]) -> Result<ClientHello<'static>> {
    let mut r = Reader::new(stream);
    let len_hi = r.u8()? & 0x7f;
    let len_lo = r.u8()?;
    let _record_len = (u16::from(len_hi) << 8) | u16::from(len_lo);

    let msg_type = r.u8()?;
    if msg_type != 1 {
        return Err(ParseError::UnexpectedHandshake(msg_type));
    }

    let legacy_version = r.u16()?;
    let cipher_spec_len = r.u16()? as usize;
    let session_id_len = r.u16()? as usize;
    let challenge_len = r.u16()? as usize;

    let cipher_specs = r.take(cipher_spec_len)?;
    let _session_id = r.take(session_id_len)?;
    let _challenge = r.take(challenge_len)?;

    let mut cipher_suites = SmallVec::new();
    let mut specs = Reader::new(cipher_specs);
    while specs.remaining() >= 3 {
        let kind = specs.u8()?;
        let suite = specs.u16()?;
        if kind == 0 {
            cipher_suites.push(suite);
        }
    }

    Ok(ClientHello {
        legacy_version,
        cipher_suites,
        extensions: SmallVec::new(),
        is_sslv2: true,
    })
}

#[cfg(test)]
mod tests {
    use super::{first_handshake_message, handshake_bytes, is_sslv2_client_hello};
    use crate::registry::handshake_type;

    fn record(ctype: u8, payload: &[u8]) -> Vec<u8> {
        let mut v = vec![ctype, 0x03, 0x03];
        let len = u16::try_from(payload.len()).unwrap();
        v.extend_from_slice(&len.to_be_bytes());
        v.extend_from_slice(payload);
        v
    }

    #[test]
    fn single_record_borrows() {
        let stream = record(22, &[0x01, 0x00, 0x00, 0x00]);
        let hs = handshake_bytes(&stream).unwrap();
        assert!(matches!(hs, std::borrow::Cow::Borrowed(_)));
        assert_eq!(hs.as_ref(), &[0x01, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn fragmented_records_join() {
        let mut stream = record(22, &[0x01, 0x00, 0x00, 0x06, 0xaa, 0xbb]);
        stream.extend(record(22, &[0xcc, 0xdd, 0xee, 0xff]));
        let hs = handshake_bytes(&stream).unwrap();
        assert!(matches!(hs, std::borrow::Cow::Owned(_)));
        assert_eq!(hs.as_ref().len(), 10);
    }

    #[test]
    fn finds_the_requested_message() {
        let hs = [
            0x02, 0x00, 0x00, 0x01, 0x99, 0x01, 0x00, 0x00, 0x02, 0xaa, 0xbb,
        ];
        let body = first_handshake_message(&hs, handshake_type::CLIENT_HELLO).unwrap();
        assert_eq!(body, &[0xaa, 0xbb]);
    }

    #[test]
    fn sslv2_detection() {
        assert!(is_sslv2_client_hello(&[0x80, 0x2e, 0x01, 0x00, 0x02]));
        assert!(!is_sslv2_client_hello(&[0x16, 0x03, 0x01, 0x00]));
    }
}
