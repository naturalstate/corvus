// ©AngelaMos | 2026
// decode.rs

use std::net::{IpAddr, SocketAddr};

use etherparse::{EtherType, NetSlice, SlicedPacket, TransportSlice};
use smallvec::SmallVec;

use crate::ja4t::TcpFingerprintInput;

/// LINKTYPE registry numbers this decoder understands.
///
/// The values come from the tcpdump link layer header type registry. They are
/// redeclared here as plain constants because pcap file readers and live
/// captures both report them as bare integers, and the decoder is the single
/// place that interprets them.
pub mod link_type {
    pub const NULL: i32 = 0;
    pub const ETHERNET: i32 = 1;
    pub const RAW: i32 = 101;
    pub const LOOP: i32 = 108;
    pub const LINUX_SLL: i32 = 113;
    pub const IPV4: i32 = 228;
    pub const IPV6: i32 = 229;
    pub const LINUX_SLL2: i32 = 276;
}

/// The BSD null and loopback link headers are four bytes of address family.
const NULL_HEADER_LEN: usize = 4;

/// The Linux cooked capture v2 header is twenty bytes with the protocol in the
/// first two.
const SLL2_HEADER_LEN: usize = 20;

/// The TCP kind numbers the JA4T walk extracts values from.
const TCP_OPT_END: u8 = 0;
const TCP_OPT_NOP: u8 = 1;
const TCP_OPT_MSS: u8 = 2;
const TCP_OPT_WSCALE: u8 = 3;
const TCP_OPT_MSS_LEN: u8 = 4;
const TCP_OPT_WSCALE_LEN: u8 = 3;

/// The TCP flag bits, exactly as byte thirteen of the header carries them.
///
/// Keeping the flags as the wire bitfield instead of a fistful of bools means
/// the struct mirrors the protocol and reads the byte the packet already
/// holds, rather than rebuilding it from a handful of accessor calls. Adding
/// a flag later is then a constant, not a field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpFlags(u8);

impl TcpFlags {
    pub const FIN: u8 = 0x01;
    pub const SYN: u8 = 0x02;
    pub const RST: u8 = 0x04;
    pub const ACK: u8 = 0x10;

    /// The offset of the flags byte within a TCP header.
    const FLAGS_BYTE: usize = 13;

    #[must_use]
    pub const fn new(bits: u8) -> Self {
        Self(bits)
    }

    /// Reads the flags byte from a TCP header slice.
    ///
    /// A missing byte cannot happen for a slice the decoder hands in, since
    /// the transport layer is only present when a full header parsed, but the
    /// bounds checked read keeps this honest under direct unit testing.
    #[must_use]
    fn from_header(header: &[u8]) -> Self {
        Self(header.get(Self::FLAGS_BYTE).copied().unwrap_or(0))
    }

    #[must_use]
    pub const fn syn(self) -> bool {
        self.0 & Self::SYN != 0
    }

    #[must_use]
    pub const fn ack(self) -> bool {
        self.0 & Self::ACK != 0
    }

    #[must_use]
    pub const fn fin(self) -> bool {
        self.0 & Self::FIN != 0
    }

    #[must_use]
    pub const fn rst(self) -> bool {
        self.0 & Self::RST != 0
    }
}

/// The TCP level facts about one decoded segment.
#[derive(Debug, Clone, Copy)]
pub struct TcpMeta {
    pub seq: u32,
    pub flags: TcpFlags,
    pub window_size: u16,
}

/// One TCP segment decoded out of a captured frame.
///
/// Addresses are directional: `src` sent this segment to `dst`. The JA4T
/// input is walked eagerly, but only for SYN packets, because those are the
/// only packets whose options JA4T reads and the walk needs the option bytes
/// that do not outlive the decode.
#[derive(Debug)]
pub struct DecodedSegment<'pkt> {
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub tcp: TcpMeta,
    pub syn_fingerprint: Option<TcpFingerprintInput>,
    pub payload: &'pkt [u8],
}

/// One UDP datagram decoded out of a captured frame.
///
/// Addresses are directional like a TCP segment's. The payload is the UDP
/// data, which the pipeline hands to the QUIC layer; a datagram that turns
/// out not to be QUIC is simply ignored there, since UDP carries far more
/// than QUIC and the fingerprinter only reads the handshake it understands.
#[derive(Debug)]
pub struct DecodedDatagram<'pkt> {
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub payload: &'pkt [u8],
}

/// One transport payload decoded out of a captured frame.
///
/// The decoder surfaces the two transports the pipeline fingerprints: TCP,
/// which carries TLS and HTTP, and UDP, which carries QUIC. Everything else
/// is a [`Skip`].
#[derive(Debug)]
pub enum Decoded<'pkt> {
    Tcp(DecodedSegment<'pkt>),
    Udp(DecodedDatagram<'pkt>),
}

/// Why a frame produced no transport payload. The distinction only feeds
/// counters, but the counters are how an operator learns what a capture was
/// made of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Skip {
    UnsupportedLinkType,
    NotIp,
    NotTransport,
    Malformed,
}

/// Decodes a captured frame down to its transport payload, if it has one the
/// pipeline fingerprints.
///
/// VLAN tags, including stacked QinQ, are stepped over by etherparse. Frames
/// the decoder does not understand are skipped with a reason rather than
/// failing the capture: a fingerprinting pipeline must shrug off the GRE
/// tunnel, the ARP chatter, and the malformed frame that share every real
/// network with the TLS and QUIC it cares about.
pub fn decode_frame(link: i32, data: &[u8]) -> Result<Decoded<'_>, Skip> {
    let sliced = match link {
        link_type::ETHERNET => SlicedPacket::from_ethernet(data),
        link_type::LINUX_SLL => SlicedPacket::from_linux_sll(data),
        link_type::RAW | link_type::IPV4 | link_type::IPV6 => SlicedPacket::from_ip(data),
        link_type::NULL | link_type::LOOP => {
            let Some(inner) = data.get(NULL_HEADER_LEN..) else {
                return Err(Skip::Malformed);
            };
            SlicedPacket::from_ip(inner)
        }
        link_type::LINUX_SLL2 => {
            let Some(proto) = data.first_chunk::<2>() else {
                return Err(Skip::Malformed);
            };
            let Some(inner) = data.get(SLL2_HEADER_LEN..) else {
                return Err(Skip::Malformed);
            };
            SlicedPacket::from_ether_type(EtherType(u16::from_be_bytes(*proto)), inner)
        }
        _ => return Err(Skip::UnsupportedLinkType),
    };
    let sliced = sliced.map_err(|_| Skip::Malformed)?;

    let (src_ip, dst_ip): (IpAddr, IpAddr) = match &sliced.net {
        Some(NetSlice::Ipv4(v4)) => (
            IpAddr::V4(v4.header().source_addr()),
            IpAddr::V4(v4.header().destination_addr()),
        ),
        Some(NetSlice::Ipv6(v6)) => (
            IpAddr::V6(v6.header().source_addr()),
            IpAddr::V6(v6.header().destination_addr()),
        ),
        Some(NetSlice::Arp(_)) | None => return Err(Skip::NotIp),
    };

    match &sliced.transport {
        Some(TransportSlice::Tcp(tcp)) => {
            let flags = TcpFlags::from_header(tcp.slice());
            let syn_fingerprint = flags
                .syn()
                .then(|| tcp_fingerprint_input(tcp.window_size(), tcp.options()));

            Ok(Decoded::Tcp(DecodedSegment {
                src: SocketAddr::new(src_ip, tcp.source_port()),
                dst: SocketAddr::new(dst_ip, tcp.destination_port()),
                tcp: TcpMeta {
                    seq: tcp.sequence_number(),
                    flags,
                    window_size: tcp.window_size(),
                },
                syn_fingerprint,
                payload: tcp.payload(),
            }))
        }
        Some(TransportSlice::Udp(udp)) => Ok(Decoded::Udp(DecodedDatagram {
            src: SocketAddr::new(src_ip, udp.source_port()),
            dst: SocketAddr::new(dst_ip, udp.destination_port()),
            payload: udp.payload(),
        })),
        _ => Err(Skip::NotTransport),
    }
}

/// Walks raw TCP options into the JA4T input.
///
/// JA4T records every option kind in order, including each NOP and each
/// trailing end of list byte, because the padding pattern is part of how an
/// operating system's stack writes a SYN. The walk is deliberately tolerant:
/// a truncated or nonsense length byte ends the walk after recording the kind
/// it was found on, so a hostile SYN cannot push the parser out of bounds.
pub fn tcp_fingerprint_input(window_size: u16, options: &[u8]) -> TcpFingerprintInput {
    let mut kinds: SmallVec<[u8; 8]> = SmallVec::new();
    let mut mss = 0u16;
    let mut window_scale = 0u8;

    let mut i = 0;
    while i < options.len() {
        let kind = options[i];
        kinds.push(kind);
        if kind == TCP_OPT_END || kind == TCP_OPT_NOP {
            i += 1;
            continue;
        }
        let Some(&len) = options.get(i + 1) else {
            break;
        };
        if len < 2 {
            break;
        }
        let Some(body) = options.get(i + 2..i + usize::from(len)) else {
            break;
        };
        if kind == TCP_OPT_MSS && len == TCP_OPT_MSS_LEN {
            if let Some(value) = body.first_chunk::<2>() {
                mss = u16::from_be_bytes(*value);
            }
        }
        if kind == TCP_OPT_WSCALE && len == TCP_OPT_WSCALE_LEN {
            if let Some(&value) = body.first() {
                window_scale = value;
            }
        }
        i += usize::from(len);
    }

    TcpFingerprintInput {
        window_size,
        option_kinds: kinds,
        mss,
        window_scale,
    }
}

#[cfg(test)]
mod tests {
    use super::{Decoded, Skip, TcpFlags, decode_frame, link_type, tcp_fingerprint_input};
    use crate::ja4t::ja4t;
    use etherparse::PacketBuilder;

    fn tcp_segment(link: i32, data: &[u8]) -> super::DecodedSegment<'_> {
        match decode_frame(link, data) {
            Ok(Decoded::Tcp(seg)) => seg,
            other => panic!("expected a TCP segment, got {other:?}"),
        }
    }

    fn tcp_frame(payload: &[u8]) -> Vec<u8> {
        let builder = PacketBuilder::ethernet2([1; 6], [2; 6])
            .ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64)
            .tcp(40000, 443, 1000, 64240);
        let mut out = Vec::with_capacity(builder.size(payload.len()));
        builder.write(&mut out, payload).unwrap();
        out
    }

    #[test]
    fn flags_byte_decodes_to_the_right_bits() {
        let syn = TcpFlags::from_header(&[0u8; 14]);
        assert!(!syn.syn());

        let mut header = [0u8; 20];
        header[13] = TcpFlags::SYN | TcpFlags::ACK;
        let flags = TcpFlags::from_header(&header);
        assert!(flags.syn() && flags.ack());
        assert!(!flags.fin() && !flags.rst());

        assert!(!TcpFlags::from_header(&[]).syn());
    }

    #[test]
    fn decodes_an_ethernet_tcp_frame() {
        let frame = tcp_frame(b"hello");
        let seg = tcp_segment(link_type::ETHERNET, &frame);
        assert_eq!(seg.src.to_string(), "10.0.0.1:40000");
        assert_eq!(seg.dst.to_string(), "10.0.0.2:443");
        assert_eq!(seg.tcp.seq, 1000);
        assert_eq!(seg.payload, b"hello");
    }

    #[test]
    fn decodes_a_vlan_tagged_frame() {
        let builder = PacketBuilder::ethernet2([1; 6], [2; 6])
            .single_vlan(etherparse::VlanId::try_new(7).unwrap())
            .ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64)
            .tcp(40000, 443, 1, 64240);
        let mut frame = Vec::with_capacity(builder.size(0));
        builder.write(&mut frame, &[]).unwrap();

        let seg = tcp_segment(link_type::ETHERNET, &frame);
        assert_eq!(seg.dst.port(), 443);
    }

    #[test]
    fn decodes_a_udp_datagram() {
        let builder = PacketBuilder::ethernet2([1; 6], [2; 6])
            .ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64)
            .udp(50000, 443);
        let mut udp = Vec::with_capacity(builder.size(4));
        builder.write(&mut udp, &[0xde, 0xad, 0xbe, 0xef]).unwrap();

        let Ok(Decoded::Udp(datagram)) = decode_frame(link_type::ETHERNET, &udp) else {
            panic!("expected a UDP datagram");
        };
        assert_eq!(datagram.src.to_string(), "10.0.0.1:50000");
        assert_eq!(datagram.dst.port(), 443);
        assert_eq!(datagram.payload, &[0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn non_transport_and_garbage_are_skips_not_panics() {
        let builder = PacketBuilder::ethernet2([1; 6], [2; 6])
            .ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64)
            .icmpv4_echo_request(1, 1);
        let mut icmp = Vec::with_capacity(builder.size(0));
        builder.write(&mut icmp, &[]).unwrap();

        assert!(matches!(
            decode_frame(link_type::ETHERNET, &icmp),
            Err(Skip::NotTransport)
        ));
        assert!(matches!(
            decode_frame(link_type::ETHERNET, &[0x01, 0x02]),
            Err(Skip::Malformed)
        ));
        assert!(matches!(
            decode_frame(147, &icmp),
            Err(Skip::UnsupportedLinkType)
        ));
    }

    #[test]
    fn ja4t_walk_reproduces_the_windows_default_vector() {
        let options = [
            0x02, 0x04, 0x05, 0xb4, 0x01, 0x03, 0x03, 0x08, 0x01, 0x01, 0x04, 0x02,
        ];
        let input = tcp_fingerprint_input(64240, &options);
        assert_eq!(ja4t(&input), "64240_2-1-3-1-1-4_1460_8");
    }

    #[test]
    fn ja4t_walk_counts_trailing_end_of_list_padding() {
        let options = [
            0x02, 0x04, 0x05, 0x42, 0x01, 0x03, 0x03, 0x06, 0x01, 0x01, 0x08, 0x0a, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x02, 0x00, 0x00,
        ];
        let input = tcp_fingerprint_input(65535, &options);
        assert_eq!(ja4t(&input), "65535_2-1-3-1-1-8-4-0-0_1346_6");
    }

    #[test]
    fn ja4t_walk_survives_truncated_options() {
        let input = tcp_fingerprint_input(1024, &[0x02, 0x04, 0x05]);
        assert_eq!(input.option_kinds.as_slice(), &[0x02]);
        assert_eq!(input.mss, 0);

        let zero_len = tcp_fingerprint_input(1024, &[0x05, 0x00, 0x02]);
        assert_eq!(zero_len.option_kinds.as_slice(), &[0x05]);
    }
}
