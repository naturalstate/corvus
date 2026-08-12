// ©AngelaMos | 2026
// tls.rs

use std::borrow::Cow;

use crate::ja3::{ja3, ja3_string, ja3s, ja3s_string};
use crate::ja4::{Transport, ja4, ja4s};
use crate::ja4h::{ja4h, parse_http_request};
use crate::ja4x::ja4x;
use crate::parse::reader::Reader;
use crate::parse::{
    certificate_der_list, is_sslv2_client_hello, parse_client_hello, parse_server_hello,
    parse_sslv2_client_hello,
};
use crate::pipeline::event::StreamEvent;
use crate::registry::{content_type, handshake_type, version};

/// How many bytes the sniffer needs before it gives up on classifying a
/// stream. Every protocol this pipeline recognizes shows its hand within the
/// first few bytes; eight covers the longest HTTP method prefix.
const SNIFF_DECISION_LEN: usize = 8;

/// The HTTP methods the sniffer accepts as the start of a cleartext request.
const HTTP_METHOD_PREFIXES: [&[u8]; 9] = [
    b"GET ",
    b"POST ",
    b"PUT ",
    b"HEAD ",
    b"DELETE ",
    b"OPTIONS ",
    b"PATCH ",
    b"TRACE ",
    b"CONNECT ",
];

/// A stream whose HTTP request head has not finished inside this many bytes
/// is not worth waiting on.
const HTTP_HEAD_CAP: usize = 8 * 1024;

const HTTP_HEAD_TERMINATOR: &[u8] = b"\r\n\r\n";

/// A TLS record payload cannot exceed 2^14 plus expansion; RFC 8446 allows
/// 255 bytes of expansion on top of the 16384 byte plaintext limit. A length
/// beyond that means the stream is not actually TLS record framing.
const MAX_TLS_RECORD_LEN: usize = 16384 + 255;

/// What one direction of a flow is, as far as the protocol layer can tell.
#[derive(Debug)]
pub enum StreamProtocol {
    /// Not enough bytes yet to say.
    Undecided,
    /// TLS record framing; the cleartext first flight is being extracted.
    Tls(TlsFlight),
    /// A cleartext HTTP/1.x request head is being accumulated.
    Http,
    /// Recognized and fully harvested; the stream needs no more buffering.
    Done,
    /// Unrecognized or unparseable; the stream is ignored.
    Ignored,
}

impl StreamProtocol {
    /// True when this direction will never produce another event, which is
    /// the signal to drop its reassembly buffers.
    #[must_use]
    pub fn finished(&self) -> bool {
        matches!(self, StreamProtocol::Done | StreamProtocol::Ignored)
    }

    /// True when the stream was recognized as TLS but the capture ended
    /// before a complete hello could be read. Feeds the miss rate counter
    /// that tells an operator their capture is clipping handshakes.
    #[must_use]
    pub fn unfinished_tls(&self) -> bool {
        match self {
            StreamProtocol::Tls(flight) => !flight.saw_any_message,
            _ => false,
        }
    }
}

/// Incremental extraction state for one direction's cleartext TLS flight.
///
/// Only what must survive between walks lives here. A ClientHello ends its
/// direction immediately, so it needs no flag; a ServerHello does not, since
/// a TLS 1.2 Certificate may still be in flight behind it, so the emission
/// guard for it persists.
#[derive(Debug, Default)]
pub struct TlsFlight {
    emitted_server_hello: bool,
    saw_any_message: bool,
}

/// Drives protocol detection and extraction over one direction of a stream.
///
/// `stream` is always the full contiguous bytes from the start of the
/// direction; the extractor re-walks them on each call. That sounds wasteful
/// and is not: the walk is linear over at most the reassembly cap, the
/// interesting messages sit in the first packets, and re-walking from the
/// start is what makes a message that arrives split across three segments
/// parse correctly with no incremental parser state to get wrong.
///
/// Returns events through `sink` and updates `proto` in place.
pub fn advance(proto: &mut StreamProtocol, stream: &[u8], sink: &mut impl FnMut(StreamEvent)) {
    if matches!(proto, StreamProtocol::Undecided) {
        *proto = sniff(stream);
    }
    match proto {
        StreamProtocol::Undecided | StreamProtocol::Done | StreamProtocol::Ignored => {}
        StreamProtocol::Tls(_) => advance_tls(proto, stream, sink),
        StreamProtocol::Http => advance_http(proto, stream, sink),
    }
}

/// Classifies the first bytes of a stream.
fn sniff(stream: &[u8]) -> StreamProtocol {
    if stream.len() >= 3 {
        if stream[0] == content_type::HANDSHAKE && stream[1] == 0x03 && stream[2] <= 0x04 {
            return StreamProtocol::Tls(TlsFlight::default());
        }
        if is_sslv2_client_hello(stream) {
            return StreamProtocol::Tls(TlsFlight::default());
        }
    }
    if stream.len() >= SNIFF_DECISION_LEN {
        if HTTP_METHOD_PREFIXES.iter().any(|m| stream.starts_with(m)) {
            return StreamProtocol::Http;
        }
        return StreamProtocol::Ignored;
    }
    StreamProtocol::Undecided
}

fn advance_http(proto: &mut StreamProtocol, stream: &[u8], sink: &mut impl FnMut(StreamEvent)) {
    let head_end = stream
        .windows(HTTP_HEAD_TERMINATOR.len())
        .position(|w| w == HTTP_HEAD_TERMINATOR);
    let Some(head_end) = head_end else {
        if stream.len() > HTTP_HEAD_CAP {
            *proto = StreamProtocol::Ignored;
        }
        return;
    };

    let head = &stream[..head_end + HTTP_HEAD_TERMINATOR.len()];
    if let Some(request) = parse_http_request(head) {
        let host = request
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("host"))
            .map(|(_, value)| value.clone());
        let user_agent = request
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("user-agent"))
            .map(|(_, value)| value.clone());
        sink(StreamEvent::HttpRequest {
            ja4h: ja4h(&request),
            method: request.method.clone(),
            host,
            user_agent,
        });
        *proto = StreamProtocol::Done;
    } else {
        *proto = StreamProtocol::Ignored;
    }
}

fn advance_tls(proto: &mut StreamProtocol, stream: &[u8], sink: &mut impl FnMut(StreamEvent)) {
    if is_sslv2_client_hello(stream) {
        advance_sslv2(proto, stream, sink);
        return;
    }

    let Some(flight_bytes) = collect_flight(stream) else {
        *proto = StreamProtocol::Ignored;
        return;
    };

    let StreamProtocol::Tls(flight) = proto else {
        return;
    };
    let mut done = walk_messages(flight, flight_bytes.handshake.as_ref(), sink);
    if flight_bytes.flight_closed && !done {
        done = true;
    }
    if done {
        *proto = StreamProtocol::Done;
    }
}

fn advance_sslv2(proto: &mut StreamProtocol, stream: &[u8], sink: &mut impl FnMut(StreamEvent)) {
    match parse_sslv2_client_hello(stream) {
        Ok(hello) => {
            sink(StreamEvent::ClientHello {
                ja3: ja3(&hello),
                ja3_raw: ja3_string(&hello),
                ja4: ja4(&hello, Transport::Tcp),
                sni: None,
                alpn: None,
            });
            *proto = StreamProtocol::Done;
        }
        Err(crate::error::ParseError::Truncated { .. }) => {}
        Err(_) => *proto = StreamProtocol::Ignored,
    }
}

struct FlightBytes<'stream> {
    handshake: Cow<'stream, [u8]>,
    /// True when a non handshake record followed the handshake records, which
    /// in cleartext TLS means the readable part of the flight is over.
    flight_closed: bool,
}

/// Collects the payloads of the leading complete handshake records.
///
/// Unlike the strict reassembled flight walker in the parse module, this
/// tolerates a trailing partial record, because the stream is still growing.
/// Returns `None` when the bytes stop looking like TLS record framing at all.
fn collect_flight(stream: &[u8]) -> Option<FlightBytes<'_>> {
    let mut segments: Vec<&[u8]> = Vec::new();
    let mut r = Reader::new(stream);
    let mut flight_closed = false;

    while r.remaining() >= 5 {
        let Ok(ctype) = r.u8() else { break };
        let Ok(record_version) = r.u16() else { break };
        if !matches!(
            ctype,
            content_type::CHANGE_CIPHER_SPEC
                | content_type::ALERT
                | content_type::HANDSHAKE
                | content_type::APPLICATION_DATA
        ) {
            return None;
        }
        if (record_version & 0xff00) != 0x0300 || (record_version & 0x00ff) > 0x04 {
            return None;
        }
        let Ok(declared) = r.u16() else { break };
        if declared as usize > MAX_TLS_RECORD_LEN {
            return None;
        }
        let Ok(payload) = r.take(declared as usize) else {
            break;
        };
        if ctype == content_type::HANDSHAKE {
            segments.push(payload);
        } else if !segments.is_empty() {
            flight_closed = true;
            break;
        }
    }

    let handshake = match segments.as_slice() {
        [] => Cow::Borrowed(&[][..]),
        [only] => Cow::Borrowed(*only),
        many => {
            let mut joined = Vec::with_capacity(many.iter().map(|s| s.len()).sum());
            for seg in many {
                joined.extend_from_slice(seg);
            }
            Cow::Owned(joined)
        }
    };
    Some(FlightBytes {
        handshake,
        flight_closed,
    })
}

/// Walks the complete handshake messages in the flight, emitting fingerprints
/// for the ones that carry them. Returns true when this direction has yielded
/// everything it ever will.
fn walk_messages(
    flight: &mut TlsFlight,
    handshake: &[u8],
    sink: &mut impl FnMut(StreamEvent),
) -> bool {
    let mut r = Reader::new(handshake);
    while r.remaining() >= 4 {
        let Ok(msg_type) = r.u8() else { break };
        let Ok(len) = r.u24() else { break };
        let Ok(body) = r.take(len as usize) else {
            break;
        };
        flight.saw_any_message = true;

        match msg_type {
            handshake_type::CLIENT_HELLO => {
                if let Ok(hello) = parse_client_hello(body) {
                    sink(StreamEvent::ClientHello {
                        ja3: ja3(&hello),
                        ja3_raw: ja3_string(&hello),
                        ja4: ja4(&hello, Transport::Tcp),
                        sni: hello.server_name().map(str::to_owned),
                        alpn: hello
                            .alpn_protocols()
                            .first()
                            .map(|p| String::from_utf8_lossy(p).into_owned()),
                    });
                }
                return true;
            }
            handshake_type::SERVER_HELLO => {
                if !flight.emitted_server_hello {
                    if let Ok(hello) = parse_server_hello(body) {
                        flight.emitted_server_hello = true;
                        let negotiated_tls13 = hello.selected_version() == version::TLS_1_3;
                        sink(StreamEvent::ServerHello {
                            ja3s: ja3s(&hello),
                            ja3s_raw: ja3s_string(&hello),
                            ja4s: ja4s(&hello, Transport::Tcp),
                        });
                        if negotiated_tls13 {
                            return true;
                        }
                    }
                }
            }
            handshake_type::CERTIFICATE => {
                if let Ok(certs) = certificate_der_list(body) {
                    for cert in certs {
                        if let Ok(fingerprint) = ja4x(cert) {
                            sink(StreamEvent::Certificate { ja4x: fingerprint });
                        }
                    }
                }
                return true;
            }
            _ => {}
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::{StreamProtocol, advance, sniff};
    use crate::pipeline::event::StreamEvent;

    fn record(payload: &[u8]) -> Vec<u8> {
        let mut v = vec![0x16, 0x03, 0x01];
        v.extend_from_slice(&u16::try_from(payload.len()).unwrap().to_be_bytes());
        v.extend_from_slice(payload);
        v
    }

    #[test]
    fn sniffs_tls_http_and_garbage() {
        assert!(matches!(
            sniff(&[0x16, 0x03, 0x01, 0x00, 0x05]),
            StreamProtocol::Tls(_)
        ));
        assert!(matches!(sniff(b"GET / HTTP/1.1\r\n"), StreamProtocol::Http));
        assert!(matches!(
            sniff(b"SSH-2.0-OpenSSH_9.7"),
            StreamProtocol::Ignored
        ));
        assert!(matches!(sniff(b"GE"), StreamProtocol::Undecided));
    }

    #[test]
    fn http_request_yields_ja4h_once_head_completes() {
        let mut proto = StreamProtocol::Undecided;
        let mut events = Vec::new();

        let partial = b"GET / HTTP/1.1\r\nHost: example.com\r\n";
        advance(&mut proto, partial, &mut |e| events.push(e));
        assert!(events.is_empty());
        assert!(matches!(proto, StreamProtocol::Http));

        let full = b"GET / HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n";
        advance(&mut proto, full, &mut |e| events.push(e));
        assert_eq!(events.len(), 1);
        assert!(matches!(
            &events[0],
            StreamEvent::HttpRequest { method, host: Some(h), .. }
                if method == "GET" && h == "example.com"
        ));
        assert!(proto.finished());
    }

    #[test]
    fn partial_tls_record_waits_for_more_bytes() {
        let mut proto = StreamProtocol::Undecided;
        let mut events = Vec::new();

        let full = record(&[0x01, 0x00, 0x00, 0x02, 0xaa, 0xbb]);
        advance(&mut proto, &full[..7], &mut |e| events.push(e));
        assert!(events.is_empty());
        assert!(matches!(proto, StreamProtocol::Tls(_)));
        assert!(!proto.finished());
    }

    #[test]
    fn nonsense_record_length_poisons_the_stream() {
        let mut proto = StreamProtocol::Undecided;
        let mut events = Vec::new();

        let stream = [0x16, 0x03, 0x01, 0xff, 0xff, 0x00, 0x00, 0x00];
        advance(&mut proto, &stream, &mut |e| events.push(e));
        assert!(matches!(proto, StreamProtocol::Ignored));
        assert!(events.is_empty());
    }
}
