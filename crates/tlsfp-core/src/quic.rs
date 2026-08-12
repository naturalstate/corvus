// ©AngelaMos | 2026
// quic.rs

//! QUIC version 1 Initial packet decryption, from RFC 9001 and RFC 9000.
//!
//! A QUIC ClientHello is not sent in the clear. It travels inside CRYPTO
//! frames in one or more Initial packets, and those packets are encrypted,
//! even though the key is derivable by anyone who sees the connection start.
//! The point of that encryption is not secrecy. It is ossification defence:
//! by protecting the Initial under a key derived from a connection ID that
//! every observer can read, QUIC forces middleboxes to either implement the
//! whole scheme or leave the packet alone, which keeps the wire format free
//! to evolve. A passive fingerprinter is the rare observer that genuinely
//! wants to read the handshake, so it implements the whole scheme.
//!
//! The recipe, from RFC 9001 Section 5.2 and Section 5.4, is:
//!
//! 1. The initial secret is `HKDF-Extract(initial_salt, dcid)`, where `dcid`
//!    is the Destination Connection ID of the client's first Initial packet
//!    and `initial_salt` is a constant fixed by the QUIC version.
//! 2. The client traffic secret is `HKDF-Expand-Label(initial_secret,
//!    "client in", "", 32)`, and from it come the AEAD key, the AEAD IV, and
//!    the header protection key, each its own `HKDF-Expand-Label`.
//! 3. Header protection masks the low bits of the first byte and the whole
//!    packet number with `AES-ECB(hp, sample)`, where `sample` is sixteen
//!    bytes of ciphertext taken four bytes past the start of the packet
//!    number field. Removing it reveals the packet number length and value.
//! 4. The payload is `AEAD_AES_128_GCM`, with the unprotected header as
//!    associated data and a nonce built by XORing the packet number into the
//!    IV.
//!
//! Everything here is bounds checked and allocation light. A malformed or
//! truncated Initial is an ordinary error, never a panic, because this code
//! runs against whatever a network hands it.

use std::collections::BTreeMap;

use aes::Aes128;
use aes::cipher::{BlockEncrypt, KeyInit as _, generic_array::GenericArray};
use aes_gcm::Aes128Gcm;
use aes_gcm::aead::AeadInPlace;
use hkdf::Hkdf;
use sha2::Sha256;
use smallvec::SmallVec;

use crate::error::{ParseError, Result};
use crate::registry::handshake_type;

/// The QUIC version 1 code point, from RFC 9000.
pub const VERSION_1: u32 = 0x0000_0001;

/// The QUIC version 2 code point, from RFC 9369.
pub const VERSION_2: u32 = 0x6b33_43cf;

/// The version 1 Initial salt, from RFC 9001 Section 5.2. This constant is
/// what binds a set of Initial keys to one QUIC version: a different version
/// uses a different salt, so keys derived under the wrong salt simply fail
/// the AEAD tag.
const INITIAL_SALT_V1: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

/// The version 2 Initial salt, from RFC 9369 Section 3.3.1. QUIC v2 deliberately
/// changes the salt, the key derivation labels, and the long header type code
/// for Initial away from their v1 values, so an observer must implement the
/// version on purpose rather than assume v1 framing.
const INITIAL_SALT_V2: [u8; 20] = [
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb,
    0xf9, 0xbd, 0x2e, 0xd9,
];

const KEY_LEN: usize = 16;
const IV_LEN: usize = 12;
const HP_LEN: usize = 16;

/// The header protection sample is sixteen bytes, the AES block size.
const SAMPLE_LEN: usize = 16;

/// The AEAD authentication tag occupies the last sixteen bytes of the
/// protected payload.
const TAG_LEN: usize = 16;

/// Header protection assumes a four byte packet number when locating the
/// sample, because the true length is not known until protection is removed.
const PN_SAMPLE_OFFSET: usize = 4;

/// A connection ID is at most twenty bytes in QUIC version 1 (RFC 9000
/// Section 17.2). A longer length field marks the packet as not version 1
/// framing and is rejected rather than trusted.
const MAX_CID_LEN: usize = 20;

/// The high bit of the first byte marks a long header; the next bit is the
/// version independent fixed bit. The two type bits identify an Initial, but
/// their value differs by version, `0b00` in v1 and `0b01` in v2, so the type
/// code is carried per version rather than as one constant.
const LONG_HEADER_FORM: u8 = 0x80;
const PACKET_TYPE_MASK: u8 = 0x30;

/// Header protection masks the low four bits of a long header's first byte.
const LONG_HEADER_PN_MASK: u8 = 0x0f;

/// The two low bits of the unprotected first byte hold the packet number
/// length, biased by one.
const PN_LEN_MASK: u8 = 0x03;

/// QUIC frame type codes that may appear in an Initial packet, from RFC 9000
/// Section 12.4. Anything outside this set means the decrypted bytes are not
/// a well formed Initial payload, which is treated as a decryption failure
/// rather than guessed past.
mod frame {
    pub const PADDING: u8 = 0x00;
    pub const PING: u8 = 0x01;
    pub const ACK: u8 = 0x02;
    pub const ACK_ECN: u8 = 0x03;
    pub const CRYPTO: u8 = 0x06;
    pub const CONNECTION_CLOSE: u8 = 0x1c;
}

/// Reads a QUIC variable length integer, returning the value and the number
/// of bytes it consumed.
///
/// The length lives in the top two bits of the first byte, giving a one, two,
/// four, or eight byte encoding. A buffer too short for the indicated length
/// is an error, not a truncated read.
fn read_varint(buf: &[u8]) -> Result<(u64, usize)> {
    let first = *buf.first().ok_or(short(1, 0))?;
    let len = 1usize << (first >> 6);
    let bytes = buf.get(..len).ok_or(short(len, buf.len()))?;
    let mut value = u64::from(first & 0x3f);
    for &b in &bytes[1..] {
        value = (value << 8) | u64::from(b);
    }
    Ok((value, len))
}

const fn short(needed: usize, have: usize) -> ParseError {
    ParseError::Truncated { needed, have }
}

/// Decodes a truncated packet number into the full value, from RFC 9000
/// Appendix A.3.
///
/// The wire carries only the low bits of the packet number; the rest is
/// inferred from the largest packet number already seen so that the value
/// lands in the window around what was expected next. The very first Initial
/// on a flow has no prior packet, so its truncated value is taken as is,
/// which is correct because a connection's first packet numbers start at zero
/// and never need the window arithmetic.
fn decode_packet_number(largest: Option<u64>, truncated: u64, pn_nbits: u32) -> u64 {
    let Some(largest) = largest else {
        return truncated;
    };
    let expected = largest + 1;
    let win = 1u64 << pn_nbits;
    let hwin = win / 2;
    let mask = win - 1;
    let candidate = (expected & !mask) | truncated;
    if candidate + hwin <= expected && candidate < (1u64 << 62) - win {
        return candidate + win;
    }
    if candidate > expected + hwin && candidate >= win {
        return candidate - win;
    }
    candidate
}

/// Builds the `HkdfLabel` structure that QUIC and TLS 1.3 feed to
/// HKDF-Expand, from RFC 8446 Section 7.1.
///
/// The structure is the output length as a sixteen bit integer, then the
/// label prefixed by its own one byte length, then an empty context prefixed
/// by a zero length byte. QUIC always uses the `tls13 ` prefix and an empty
/// context for Initial keys.
fn hkdf_expand_label(secret: &[u8], label: &[u8], out: &mut [u8]) {
    const PREFIX: &[u8] = b"tls13 ";
    let mut info: SmallVec<[u8; 32]> = SmallVec::new();
    let out_len = u16::try_from(out.len()).expect("Initial key material is never that long");
    info.extend_from_slice(&out_len.to_be_bytes());
    info.push(u8::try_from(PREFIX.len() + label.len()).expect("Initial labels are short"));
    info.extend_from_slice(PREFIX);
    info.extend_from_slice(label);
    info.push(0);

    let hk = Hkdf::<Sha256>::from_prk(secret).expect("the secret is one SHA-256 block");
    hk.expand(&info, out)
        .expect("Initial output never exceeds the HKDF limit");
}

/// The version specific inputs to Initial key derivation: the HKDF salt, the
/// key, IV, and header protection labels, and the long header type code that
/// marks an Initial packet.
///
/// QUIC v1 (RFC 9001) and v2 (RFC 9369) differ in all of these. Binding them to
/// the version is what makes keys derived under the wrong version fail the AEAD
/// tag rather than silently misread a packet, and the `client in` secret label
/// is shared because it comes from the TLS 1.3 derivation, which v2 left alone.
#[derive(Clone, Copy)]
struct QuicVersion {
    salt: &'static [u8; 20],
    key_label: &'static [u8],
    iv_label: &'static [u8],
    hp_label: &'static [u8],
    initial_type: u8,
}

impl QuicVersion {
    const V1: QuicVersion = QuicVersion {
        salt: &INITIAL_SALT_V1,
        key_label: b"quic key",
        iv_label: b"quic iv",
        hp_label: b"quic hp",
        initial_type: 0x00,
    };

    const V2: QuicVersion = QuicVersion {
        salt: &INITIAL_SALT_V2,
        key_label: b"quicv2 key",
        iv_label: b"quicv2 iv",
        hp_label: b"quicv2 hp",
        initial_type: 0x10,
    };

    /// Returns the parameters for a known QUIC version code, or `None` for a
    /// version this build has no Initial salt for.
    fn from_code(code: u32) -> Option<QuicVersion> {
        match code {
            VERSION_1 => Some(Self::V1),
            VERSION_2 => Some(Self::V2),
            _ => None,
        }
    }
}

/// The AEAD and header protection keys for one direction of one QUIC Initial.
pub struct InitialKeys {
    key: [u8; KEY_LEN],
    iv: [u8; IV_LEN],
    hp: [u8; HP_LEN],
}

impl InitialKeys {
    /// Derives the client's Initial keys from a Destination Connection ID, under
    /// the salt and labels of the given QUIC version.
    ///
    /// A passive observer derives these from the connection ID alone, with no
    /// secret input, which is exactly why the AEAD tag rather than secrecy is
    /// what tells a client Initial apart from a server one: only a packet the
    /// client actually protected under these keys will verify.
    #[must_use]
    fn client(dcid: &[u8], version: QuicVersion) -> Self {
        let (initial_secret, _) = Hkdf::<Sha256>::extract(Some(version.salt), dcid);
        let mut client_secret = [0u8; 32];
        hkdf_expand_label(&initial_secret, b"client in", &mut client_secret);

        let mut keys = Self {
            key: [0u8; KEY_LEN],
            iv: [0u8; IV_LEN],
            hp: [0u8; HP_LEN],
        };
        hkdf_expand_label(&client_secret, version.key_label, &mut keys.key);
        hkdf_expand_label(&client_secret, version.iv_label, &mut keys.iv);
        hkdf_expand_label(&client_secret, version.hp_label, &mut keys.hp);
        keys
    }
}

/// One QUIC Initial packet located within a UDP datagram, still protected.
///
/// The fields outside header protection, the connection IDs, the token, and
/// the length, are read on construction; the first byte and the packet number
/// stay protected until [`InitialPacket::open`] removes protection and
/// decrypts the payload. The datagram may carry several coalesced packets, so
/// `next_offset` says where the following packet begins.
pub struct InitialPacket<'pkt> {
    datagram: &'pkt [u8],
    /// The Destination Connection ID, which seeds key derivation.
    pub dcid: &'pkt [u8],
    /// The QUIC version this packet declared, selecting the salt and labels its
    /// client keys derive under.
    version: QuicVersion,
    /// Absolute offset of this packet's first byte within the datagram.
    start: usize,
    /// Absolute offset of the packet number field within the datagram.
    pn_offset: usize,
    /// Absolute offset one past this packet's protected payload.
    end: usize,
    /// Absolute offset where the next coalesced packet would begin.
    pub next_offset: usize,
}

/// A successfully opened Initial: its decrypted frame bytes and packet number.
pub struct OpenedInitial {
    pub packet_number: u64,
    pub frames: Vec<u8>,
}

impl<'pkt> InitialPacket<'pkt> {
    /// Parses one long header Initial packet starting at `start` in a
    /// datagram, reading only the unprotected header fields.
    ///
    /// Returns [`ParseError::NotQuicInitial`] when the bytes at `start` are
    /// not a long header Initial, and [`ParseError::UnsupportedQuicVersion`]
    /// when the packet is a long header of a QUIC version this code has no
    /// salt for. Both are routine on real traffic and feed counters rather
    /// than failing a capture.
    pub fn parse(datagram: &'pkt [u8], start: usize) -> Result<Self> {
        let buf = datagram.get(start..).ok_or(ParseError::NotQuicInitial)?;
        let first = *buf.first().ok_or(ParseError::NotQuicInitial)?;
        if first & LONG_HEADER_FORM == 0 {
            return Err(ParseError::NotQuicInitial);
        }

        let version_code = u32::from_be_bytes(
            buf.get(1..5)
                .ok_or(ParseError::NotQuicInitial)?
                .try_into()
                .expect("a four byte slice is four bytes"),
        );
        let Some(version) = QuicVersion::from_code(version_code) else {
            return Err(ParseError::UnsupportedQuicVersion(version_code));
        };
        if first & PACKET_TYPE_MASK != version.initial_type {
            return Err(ParseError::NotQuicInitial);
        }

        let mut pos = 5usize;
        let dcid = read_cid(buf, &mut pos)?;
        let _scid = read_cid(buf, &mut pos)?;

        let (token_len, n) = read_varint(buf.get(pos..).ok_or(ParseError::NotQuicInitial)?)
            .map_err(|_| ParseError::NotQuicInitial)?;
        pos += n;
        let token_len = usize::try_from(token_len).map_err(|_| ParseError::NotQuicInitial)?;
        pos = pos
            .checked_add(token_len)
            .ok_or(ParseError::NotQuicInitial)?;

        let (length, n) = read_varint(buf.get(pos..).ok_or(ParseError::NotQuicInitial)?)
            .map_err(|_| ParseError::NotQuicInitial)?;
        pos += n;
        let length = usize::try_from(length).map_err(|_| ParseError::NotQuicInitial)?;

        let pn_offset = start + pos;
        let end = pn_offset
            .checked_add(length)
            .ok_or(ParseError::NotQuicInitial)?;
        if end > datagram.len() {
            return Err(ParseError::NotQuicInitial);
        }

        Ok(Self {
            datagram,
            dcid,
            version,
            start,
            pn_offset,
            end,
            next_offset: end,
        })
    }

    /// Derives the client Initial keys for this packet, from its own Destination
    /// Connection ID under the salt and labels of the version it declared.
    #[must_use]
    pub fn client_keys(&self) -> InitialKeys {
        InitialKeys::client(self.dcid, self.version)
    }

    /// Removes header protection and decrypts the payload, returning the
    /// cleartext QUIC frames.
    ///
    /// `largest_pn` is the largest packet number already decrypted on this
    /// flow, used to reconstruct the full packet number for the AEAD nonce.
    /// A failure to authenticate is reported as
    /// [`ParseError::QuicCryptoFailure`]; for a passive observer this most
    /// often means the packet was a server Initial, protected under keys the
    /// observer did not derive, rather than corruption.
    pub fn open(&self, keys: &InitialKeys, largest_pn: Option<u64>) -> Result<OpenedInitial> {
        let sample_start = self.pn_offset + PN_SAMPLE_OFFSET;
        let sample = self
            .datagram
            .get(sample_start..sample_start + SAMPLE_LEN)
            .ok_or(ParseError::QuicCryptoFailure)?;

        let mask = header_protection_mask(&keys.hp, sample);

        let protected_first = self.datagram[self.start];
        let first = protected_first ^ (mask[0] & LONG_HEADER_PN_MASK);
        let pn_len = usize::from(first & PN_LEN_MASK) + 1;

        let pn_end = self.pn_offset + pn_len;
        if pn_end > self.end {
            return Err(ParseError::QuicCryptoFailure);
        }
        let mut pn_bytes = [0u8; 4];
        let mut truncated = 0u64;
        for i in 0..pn_len {
            let clear = self.datagram[self.pn_offset + i] ^ mask[1 + i];
            pn_bytes[i] = clear;
            truncated = (truncated << 8) | u64::from(clear);
        }
        let pn_nbits = u32::try_from(pn_len * 8).expect("the packet number is at most four bytes");
        let packet_number = decode_packet_number(largest_pn, truncated, pn_nbits);

        let mut header: SmallVec<[u8; 64]> = SmallVec::new();
        header.push(first);
        header.extend_from_slice(&self.datagram[self.start + 1..self.pn_offset]);
        header.extend_from_slice(&pn_bytes[..pn_len]);

        let ciphertext = self
            .datagram
            .get(pn_end..self.end)
            .ok_or(ParseError::QuicCryptoFailure)?;
        if ciphertext.len() < TAG_LEN {
            return Err(ParseError::QuicCryptoFailure);
        }
        let split = ciphertext.len() - TAG_LEN;
        let mut frames = ciphertext[..split].to_vec();
        let tag = GenericArray::from_slice(&ciphertext[split..]);

        let nonce = aead_nonce(&keys.iv, packet_number);
        let cipher =
            Aes128Gcm::new_from_slice(&keys.key).map_err(|_| ParseError::QuicCryptoFailure)?;
        cipher
            .decrypt_in_place_detached(GenericArray::from_slice(&nonce), &header, &mut frames, tag)
            .map_err(|_| ParseError::QuicCryptoFailure)?;

        Ok(OpenedInitial {
            packet_number,
            frames,
        })
    }
}

/// Reads a one byte length prefixed connection ID, advancing the cursor.
fn read_cid<'pkt>(buf: &'pkt [u8], pos: &mut usize) -> Result<&'pkt [u8]> {
    let len = usize::from(*buf.get(*pos).ok_or(ParseError::NotQuicInitial)?);
    if len > MAX_CID_LEN {
        return Err(ParseError::NotQuicInitial);
    }
    let start = *pos + 1;
    let cid = buf
        .get(start..start + len)
        .ok_or(ParseError::NotQuicInitial)?;
    *pos = start + len;
    Ok(cid)
}

/// Computes the five byte header protection mask, `AES-ECB(hp, sample)`.
fn header_protection_mask(hp: &[u8; HP_LEN], sample: &[u8]) -> [u8; 5] {
    let cipher = Aes128::new_from_slice(hp).expect("the header protection key is sixteen bytes");
    let mut block = GenericArray::clone_from_slice(sample);
    cipher.encrypt_block(&mut block);
    let mut mask = [0u8; 5];
    mask.copy_from_slice(&block[..5]);
    mask
}

/// Builds the AEAD nonce by XORing the packet number into the static IV, from
/// RFC 9001 Section 5.3.
fn aead_nonce(iv: &[u8; IV_LEN], packet_number: u64) -> [u8; IV_LEN] {
    let mut nonce = *iv;
    let pn = packet_number.to_be_bytes();
    for i in 0..8 {
        nonce[IV_LEN - 8 + i] ^= pn[i];
    }
    nonce
}

/// Walks the frames in a decrypted Initial payload, handing each CRYPTO
/// frame's offset and bytes to `on_crypto`.
///
/// Only the frame types RFC 9000 Section 12.4 permits in an Initial packet
/// are recognized. An unrecognized type means the bytes are not a valid
/// Initial payload after all, reported as [`ParseError::QuicCryptoFailure`];
/// since the AEAD tag already authenticated these bytes, that points at a
/// version or framing this code does not model rather than at an attacker.
pub fn walk_crypto_frames(frames: &[u8], mut on_crypto: impl FnMut(u64, &[u8])) -> Result<()> {
    let mut pos = 0usize;
    while pos < frames.len() {
        let ty = frames[pos];
        pos += 1;
        match ty {
            frame::PADDING | frame::PING => {}
            frame::ACK | frame::ACK_ECN => {
                let (_largest, n) = read_varint(&frames[pos..])?;
                pos += n;
                let (_delay, n) = read_varint(&frames[pos..])?;
                pos += n;
                let (range_count, n) = read_varint(&frames[pos..])?;
                pos += n;
                let (_first_range, n) = read_varint(&frames[pos..])?;
                pos += n;
                for _ in 0..range_count {
                    let (_gap, n) = read_varint(&frames[pos..])?;
                    pos += n;
                    let (_len, n) = read_varint(&frames[pos..])?;
                    pos += n;
                }
                if ty == frame::ACK_ECN {
                    for _ in 0..3 {
                        let (_ecn, n) = read_varint(&frames[pos..])?;
                        pos += n;
                    }
                }
            }
            frame::CRYPTO => {
                let (offset, n) = read_varint(&frames[pos..])?;
                pos += n;
                let (len, n) = read_varint(&frames[pos..])?;
                pos += n;
                let len = usize::try_from(len).map_err(|_| ParseError::QuicCryptoFailure)?;
                let end = pos.checked_add(len).ok_or(ParseError::QuicCryptoFailure)?;
                let data = frames.get(pos..end).ok_or(ParseError::QuicCryptoFailure)?;
                on_crypto(offset, data);
                pos = end;
            }
            frame::CONNECTION_CLOSE => {
                let (_code, n) = read_varint(&frames[pos..])?;
                pos += n;
                let (_frame_type, n) = read_varint(&frames[pos..])?;
                pos += n;
                let (reason_len, n) = read_varint(&frames[pos..])?;
                pos += n;
                let reason_len =
                    usize::try_from(reason_len).map_err(|_| ParseError::QuicCryptoFailure)?;
                pos = pos
                    .checked_add(reason_len)
                    .filter(|&p| p <= frames.len())
                    .ok_or(ParseError::QuicCryptoFailure)?;
            }
            _ => return Err(ParseError::QuicCryptoFailure),
        }
    }
    Ok(())
}

/// Reassembles the cleartext handshake stream that CRYPTO frames carry.
///
/// CRYPTO frames are the QUIC analogue of a TCP byte stream: each carries an
/// absolute offset, frames can arrive out of order and span packets, and a
/// ClientHello routinely splits across several. This is the QUIC counterpart
/// of the TCP reassembler, kept separate because CRYPTO offsets are sixty
/// four bit and start at zero per stream rather than at a negotiated sequence
/// number. Contiguous bytes from offset zero accumulate in one buffer;
/// everything ahead of the write cursor parks until the gap before it fills.
/// Both buffers are capped so a hostile sender cannot turn the assembler into
/// a memory bomb.
pub struct CryptoAssembler {
    assembled: Vec<u8>,
    pending: BTreeMap<u64, Vec<u8>>,
    pending_bytes: usize,
    max_bytes: usize,
    overflowed: bool,
}

impl CryptoAssembler {
    #[must_use]
    pub fn new(max_bytes: usize) -> Self {
        Self {
            assembled: Vec::new(),
            pending: BTreeMap::new(),
            pending_bytes: 0,
            max_bytes,
            overflowed: false,
        }
    }

    /// Returns the contiguous handshake bytes assembled from offset zero.
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.assembled
    }

    /// Adds one CRYPTO frame's bytes at their stream offset.
    ///
    /// Bytes wholly before the write cursor are duplicates and ignored; bytes
    /// straddling it extend the contiguous run and then pull in any parked
    /// segments the new bytes made contiguous; bytes wholly ahead of it park.
    /// Anything that would push either buffer past its cap is dropped and the
    /// assembler latches an overflow so the flow can be abandoned.
    pub fn push(&mut self, offset: u64, data: &[u8]) {
        if data.is_empty() || self.overflowed {
            return;
        }
        let Ok(cursor) = u64::try_from(self.assembled.len()) else {
            self.overflowed = true;
            return;
        };

        if offset > cursor {
            self.park(offset, data);
            return;
        }
        let skip = usize::try_from(cursor - offset).unwrap_or(usize::MAX);
        if skip >= data.len() {
            return;
        }
        if !self.extend(&data[skip..]) {
            return;
        }
        self.drain_pending();
    }

    fn extend(&mut self, bytes: &[u8]) -> bool {
        if self.assembled.len() + bytes.len() > self.max_bytes {
            self.overflowed = true;
            return false;
        }
        self.assembled.extend_from_slice(bytes);
        true
    }

    fn park(&mut self, offset: u64, data: &[u8]) {
        if self.pending_bytes + data.len() > self.max_bytes {
            self.overflowed = true;
            return;
        }
        if let Some(existing) = self.pending.get(&offset) {
            if existing.len() >= data.len() {
                return;
            }
            self.pending_bytes -= existing.len();
        }
        self.pending_bytes += data.len();
        self.pending.insert(offset, data.to_vec());
    }

    fn drain_pending(&mut self) {
        while let Some((&offset, _)) = self.pending.iter().next() {
            let Ok(cursor) = u64::try_from(self.assembled.len()) else {
                self.overflowed = true;
                return;
            };
            if offset > cursor {
                break;
            }
            let segment = self.pending.remove(&offset).expect("offset just observed");
            self.pending_bytes -= segment.len();
            let skip = usize::try_from(cursor - offset).unwrap_or(usize::MAX);
            if skip < segment.len() && !self.extend(&segment[skip..]) {
                return;
            }
        }
    }

    /// Returns the body of the leading ClientHello once it is fully present.
    ///
    /// The QUIC Initial cryptographic stream begins with the ClientHello
    /// handshake message: a one byte type, a three byte length, then the
    /// body. This reports the body once the contiguous bytes hold all of it,
    /// reports that the stream does not begin with a ClientHello, or reports
    /// that more bytes are still needed.
    #[must_use]
    pub fn client_hello(&self) -> ClientHelloState<'_> {
        if self.assembled.len() < 4 {
            return if self.overflowed {
                ClientHelloState::Abandoned
            } else {
                ClientHelloState::Incomplete
            };
        }
        if self.assembled[0] != handshake_type::CLIENT_HELLO {
            return ClientHelloState::NotClientHello;
        }
        let len = usize::from(self.assembled[1]) << 16
            | usize::from(self.assembled[2]) << 8
            | usize::from(self.assembled[3]);
        match self.assembled.get(4..4 + len) {
            Some(body) => ClientHelloState::Ready(body),
            None if self.overflowed => ClientHelloState::Abandoned,
            None => ClientHelloState::Incomplete,
        }
    }
}

/// What [`CryptoAssembler::client_hello`] found in the assembled bytes.
#[derive(Debug, PartialEq, Eq)]
pub enum ClientHelloState<'a> {
    /// The full ClientHello body is present.
    Ready(&'a [u8]),
    /// More CRYPTO bytes are needed before the ClientHello is complete.
    Incomplete,
    /// The stream does not begin with a ClientHello and never will.
    NotClientHello,
    /// A buffer cap was hit; the flow should be given up.
    Abandoned,
}

#[cfg(test)]
mod tests {
    use super::{
        ClientHelloState, CryptoAssembler, InitialKeys, InitialPacket, QuicVersion,
        decode_packet_number, hkdf_expand_label, read_varint, walk_crypto_frames,
    };

    /// RFC 9000 Appendix A.1 sample variable length integer decodings.
    #[test]
    fn varint_matches_rfc9000_appendix_a1() {
        assert_eq!(
            read_varint(&hex("c2197c5eff14e88c")).unwrap(),
            (151_288_809_941_952_652, 8)
        );
        assert_eq!(read_varint(&hex("9d7f3e7d")).unwrap(), (494_878_333, 4));
        assert_eq!(read_varint(&hex("7bbd")).unwrap(), (15_293, 2));
        assert_eq!(read_varint(&hex("25")).unwrap(), (37, 1));
        assert_eq!(read_varint(&hex("4025")).unwrap(), (37, 2));
    }

    /// RFC 9000 Appendix A.3 sample packet number decoding.
    #[test]
    fn packet_number_decode_matches_rfc9000_appendix_a3() {
        assert_eq!(
            decode_packet_number(Some(0xa82f_30ea), 0x9b32, 16),
            0xa82f_9b32
        );
        assert_eq!(decode_packet_number(None, 2, 8), 2);
    }

    /// RFC 9001 Appendix A.1 derives a known set of client Initial keys from
    /// the sample Destination Connection ID.
    #[test]
    fn client_initial_keys_match_rfc9001_appendix_a1() {
        let dcid = hex("8394c8f03e515708");
        let keys = InitialKeys::client(&dcid, QuicVersion::V1);
        assert_eq!(keys.key.to_vec(), hex("1f369613dd76d5467730efcbe3b1a22d"));
        assert_eq!(keys.iv.to_vec(), hex("fa044b2f42a3fd3b46fb255c"));
        assert_eq!(keys.hp.to_vec(), hex("9f50449e04a0e810283a1e9933adedd2"));
    }

    /// RFC 9369 Appendix A derives the QUIC v2 client Initial keys from the same
    /// sample Destination Connection ID, under the v2 salt and labels.
    #[test]
    fn client_initial_keys_match_rfc9369_appendix_a() {
        let dcid = hex("8394c8f03e515708");
        let keys = InitialKeys::client(&dcid, QuicVersion::V2);
        assert_eq!(keys.key.to_vec(), hex("8b1a0bc121284290a29e0971b5cd045d"));
        assert_eq!(keys.iv.to_vec(), hex("91f73e2351d8fa91660e909f"));
        assert_eq!(keys.hp.to_vec(), hex("45b95e15235d6f45a6b19cbcb0294ba9"));
    }

    /// RFC 9001 Appendix A.1 also pins the intermediate expand label output.
    #[test]
    fn expand_label_reproduces_rfc9001_client_secret() {
        let dcid = hex("8394c8f03e515708");
        let (initial_secret, _) =
            hkdf::Hkdf::<sha2::Sha256>::extract(Some(&super::INITIAL_SALT_V1), &dcid);
        let mut client_secret = [0u8; 32];
        hkdf_expand_label(&initial_secret, b"client in", &mut client_secret);
        assert_eq!(
            client_secret.to_vec(),
            hex("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea")
        );
    }

    /// RFC 9001 Appendix A.2 carries the full protected client Initial. Its
    /// decryption must recover the documented CRYPTO frame and a parseable
    /// ClientHello.
    #[test]
    fn opens_rfc9001_appendix_a2_client_initial() {
        let datagram = rfc9001_a2_protected_packet();
        let packet = InitialPacket::parse(&datagram, 0).unwrap();
        assert_eq!(packet.dcid, &hex("8394c8f03e515708")[..]);

        let keys = packet.client_keys();
        let opened = packet.open(&keys, None).unwrap();
        assert_eq!(opened.packet_number, 2);

        let expected_head = hex("060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e868");
        assert_eq!(&opened.frames[..expected_head.len()], &expected_head[..]);

        let mut assembler = CryptoAssembler::new(1 << 16);
        walk_crypto_frames(&opened.frames, |offset, data| assembler.push(offset, data)).unwrap();
        let ClientHelloState::Ready(body) = assembler.client_hello() else {
            panic!("expected a complete ClientHello");
        };
        let hello = crate::parse::parse_client_hello(body).unwrap();
        assert!(!hello.cipher_suites.is_empty());
    }

    #[test]
    fn assembler_orders_out_of_order_crypto_frames() {
        let mut a = CryptoAssembler::new(1 << 16);
        a.push(5, b"world");
        assert_eq!(a.client_hello(), ClientHelloState::Incomplete);
        a.push(0, b"hello");
        assert_eq!(a.data(), b"helloworld");
    }

    #[test]
    fn assembler_ignores_pure_duplicates_and_overlap() {
        let mut a = CryptoAssembler::new(1 << 16);
        a.push(0, b"hello");
        a.push(0, b"hel");
        a.push(2, b"llo world");
        assert_eq!(a.data(), b"hello world");
    }

    #[test]
    fn assembler_latches_overflow_past_the_cap() {
        let mut a = CryptoAssembler::new(8);
        a.push(0, b"12345678");
        a.push(8, b"9");
        assert_eq!(a.data(), b"12345678");
        assert_eq!(a.client_hello(), ClientHelloState::NotClientHello);
    }

    #[test]
    fn non_quic_bytes_are_not_an_initial() {
        let udp = b"GET / HTTP/1.1\r\n";
        assert!(InitialPacket::parse(udp, 0).is_err());
    }

    /// A QUIC v2 long header Initial is recognized by its version code and its
    /// remapped Initial type bits, `0b01`, where the v1 Initial code `0b00` is
    /// not an Initial in v2. This proves the version specific parse logic; the v2
    /// key schedule is pinned by the keys KAT above, and the AEAD decryption path
    /// is the one the RFC 9001 Appendix A.2 test already exercises unchanged.
    #[test]
    fn parses_a_quic_v2_initial_header() {
        let mut packet = vec![0xd3];
        packet.extend_from_slice(&super::VERSION_2.to_be_bytes());
        packet.push(8);
        packet.extend_from_slice(&hex("8394c8f03e515708"));
        packet.push(0);
        packet.push(0);
        packet.push(0x10);
        packet.extend_from_slice(&[0u8; 16]);

        let parsed = InitialPacket::parse(&packet, 0).unwrap();
        assert_eq!(parsed.dcid, &hex("8394c8f03e515708")[..]);

        let mut v1_type = packet.clone();
        v1_type[0] = 0xc3;
        assert!(InitialPacket::parse(&v1_type, 0).is_err());
    }

    fn hex(s: &str) -> Vec<u8> {
        ::hex::decode(s).unwrap()
    }

    /// The protected client Initial packet from RFC 9001 Appendix A.2.
    fn rfc9001_a2_protected_packet() -> Vec<u8> {
        hex(concat!(
            "c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11",
            "d242b123dc9bd8bab936b47d92ec356c0bab7df5976d27cd449f63300099f399",
            "1c260ec4c60d17b31f8429157bb35a1282a643a8d2262cad67500cadb8e7378c",
            "8eb7539ec4d4905fed1bee1fc8aafba17c750e2c7ace01e6005f80fcb7df6212",
            "30c83711b39343fa028cea7f7fb5ff89eac2308249a02252155e2347b63d58c5",
            "457afd84d05dfffdb20392844ae812154682e9cf012f9021a6f0be17ddd0c208",
            "4dce25ff9b06cde535d0f920a2db1bf362c23e596d11a4f5a6cf3948838a3aec",
            "4e15daf8500a6ef69ec4e3feb6b1d98e610ac8b7ec3faf6ad760b7bad1db4ba3",
            "485e8a94dc250ae3fdb41ed15fb6a8e5eba0fc3dd60bc8e30c5c4287e53805db",
            "059ae0648db2f64264ed5e39be2e20d82df566da8dd5998ccabdae053060ae6c",
            "7b4378e846d29f37ed7b4ea9ec5d82e7961b7f25a9323851f681d582363aa5f8",
            "9937f5a67258bf63ad6f1a0b1d96dbd4faddfcefc5266ba6611722395c906556",
            "be52afe3f565636ad1b17d508b73d8743eeb524be22b3dcbc2c7468d54119c74",
            "68449a13d8e3b95811a198f3491de3e7fe942b330407abf82a4ed7c1b311663a",
            "c69890f4157015853d91e923037c227a33cdd5ec281ca3f79c44546b9d90ca00",
            "f064c99e3dd97911d39fe9c5d0b23a229a234cb36186c4819e8b9c5927726632",
            "291d6a418211cc2962e20fe47feb3edf330f2c603a9d48c0fcb5699dbfe58964",
            "25c5bac4aee82e57a85aaf4e2513e4f05796b07ba2ee47d80506f8d2c25e50fd",
            "14de71e6c418559302f939b0e1abd576f279c4b2e0feb85c1f28ff18f58891ff",
            "ef132eef2fa09346aee33c28eb130ff28f5b766953334113211996d20011a198",
            "e3fc433f9f2541010ae17c1bf202580f6047472fb36857fe843b19f5984009dd",
            "c324044e847a4f4a0ab34f719595de37252d6235365e9b84392b061085349d73",
            "203a4a13e96f5432ec0fd4a1ee65accdd5e3904df54c1da510b0ff20dcc0c77f",
            "cb2c0e0eb605cb0504db87632cf3d8b4dae6e705769d1de354270123cb11450e",
            "fc60ac47683d7b8d0f811365565fd98c4c8eb936bcab8d069fc33bd801b03ade",
            "a2e1fbc5aa463d08ca19896d2bf59a071b851e6c239052172f296bfb5e724047",
            "90a2181014f3b94a4e97d117b438130368cc39dbb2d198065ae3986547926cd2",
            "162f40a29f0c3c8745c0f50fba3852e566d44575c29d39a03f0cda721984b6f4",
            "40591f355e12d439ff150aab7613499dbd49adabc8676eef023b15b65bfc5ca0",
            "6948109f23f350db82123535eb8a7433bdabcb909271a6ecbcb58b936a88cd4e",
            "8f2e6ff5800175f113253d8fa9ca8885c2f552e657dc603f252e1a8e308f76f0",
            "be79e2fb8f5d5fbbe2e30ecadd220723c8c0aea8078cdfcb3868263ff8f09400",
            "54da48781893a7e49ad5aff4af300cd804a6b6279ab3ff3afb64491c85194aab",
            "760d58a606654f9f4400e8b38591356fbf6425aca26dc85244259ff2b19c41b9",
            "f96f3ca9ec1dde434da7d2d392b905ddf3d1f9af93d1af5950bd493f5aa731b4",
            "056df31bd267b6b90a079831aaf579be0a39013137aac6d404f518cfd4684064",
            "7e78bfe706ca4cf5e9c5453e9f7cfd2b8b4c8d169a44e55c88d4a9a7f9474241",
            "e221af44860018ab0856972e194cd934",
        ))
    }
}
