// ©AngelaMos | 2026
// source.rs

use std::fs::File;
use std::io::Read;
use std::path::Path;

use pcap_parser::traits::PcapReaderIterator;
use pcap_parser::{Block, PcapBlockOwned, PcapError, PcapHeader, create_reader};
use thiserror::Error;

/// How many bytes of buffer the file reader starts with.
///
/// A single capture block must fit in the buffer. Offload features such as TSO
/// can put frames far larger than an MTU into a capture, so the buffer starts
/// generous and can still grow up to [`MAX_BUFFER_CAPACITY`] if a bigger block
/// appears.
const INITIAL_BUFFER_CAPACITY: usize = 1024 * 1024;

/// The ceiling for buffer growth. A block larger than this is treated as a
/// malformed capture rather than a reason to exhaust memory.
const MAX_BUFFER_CAPACITY: usize = 64 * 1024 * 1024;

/// Timestamp units per second when a capture does not say otherwise.
///
/// Both the legacy pcap format and the pcapng default are microsecond
/// resolution.
const DEFAULT_UNITS_PER_SECOND: u64 = 1_000_000;

const NANOS_PER_SECOND: u64 = 1_000_000_000;
const NANOS_PER_MICRO: u64 = 1_000;

/// Errors produced while reading frames from a capture source.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SourceError {
    #[error("failed to read capture: {0}")]
    Io(#[from] std::io::Error),

    #[error("not a pcap or pcapng capture")]
    NotACapture,

    #[error("capture block exceeds the {MAX_BUFFER_CAPACITY} byte buffer ceiling")]
    BlockTooLarge,

    #[error("malformed capture: {0}")]
    Malformed(String),

    #[error("capture source failed: {0}")]
    Capture(String),
}

/// One link layer frame as captured, with the metadata needed to decode it.
#[derive(Debug, Clone, Copy)]
pub struct RawFrame<'src> {
    /// Capture timestamp in nanoseconds since the epoch. Zero when the capture
    /// format carries no timestamp for this frame.
    pub ts_nanos: u64,
    /// The link layer type, using the tcpdump LINKTYPE registry numbers.
    pub link_type: i32,
    pub data: &'src [u8],
}

/// A source of captured frames.
///
/// The trait is a lending iterator: each frame borrows from the source and is
/// only valid until the next call. That shape fits both file readers, which
/// hand out windows into an internal buffer, and live captures, which hand out
/// the kernel's buffer. A consumer that needs to keep a frame longer copies
/// it, and that decision stays visible at the call site.
pub trait PacketSource {
    /// Returns the next frame, or `None` when the source is exhausted.
    fn next_frame(&mut self) -> Result<Option<RawFrame<'_>>, SourceError>;
}

/// Per interface metadata from a pcapng interface description block.
#[derive(Debug, Clone, Copy)]
struct InterfaceInfo {
    link_type: i32,
    units_per_second: u64,
    ts_offset_seconds: i64,
}

/// Everything in the source except the parser, split out so the borrow of the
/// parser's buffer held by a block and the mutable borrow needed to stage a
/// frame land on different fields.
#[derive(Default)]
struct SourceState {
    interfaces: Vec<InterfaceInfo>,
    legacy: Option<InterfaceInfo>,
    legacy_nanos: bool,
    frame: Vec<u8>,
    frame_ts_nanos: u64,
    frame_link_type: i32,
}

impl SourceState {
    /// Copies a frame out of the parser's buffer so the borrow on the parser
    /// can end before the block is consumed.
    fn stage(&mut self, ts_nanos: u64, link_type: i32, data: &[u8]) {
        self.frame.clear();
        self.frame.extend_from_slice(data);
        self.frame_ts_nanos = ts_nanos;
        self.frame_link_type = link_type;
    }

    fn handle_legacy_header(&mut self, header: &PcapHeader) {
        self.legacy = Some(InterfaceInfo {
            link_type: header.network.0,
            units_per_second: DEFAULT_UNITS_PER_SECOND,
            ts_offset_seconds: 0,
        });
        self.legacy_nanos = header.is_nanosecond_precision();
    }

    /// Stages a packet block. Returns false for metadata blocks.
    fn handle_block(&mut self, block: &PcapBlockOwned<'_>) -> bool {
        match block {
            PcapBlockOwned::LegacyHeader(header) => {
                self.handle_legacy_header(header);
                false
            }
            PcapBlockOwned::Legacy(frame) => {
                let Some(meta) = self.legacy else {
                    return false;
                };
                let fraction = if self.legacy_nanos {
                    u64::from(frame.ts_usec)
                } else {
                    u64::from(frame.ts_usec) * NANOS_PER_MICRO
                };
                let ts = u64::from(frame.ts_sec)
                    .saturating_mul(NANOS_PER_SECOND)
                    .saturating_add(fraction);
                let len = frame.data.len().min(frame.caplen as usize);
                self.stage(ts, meta.link_type, &frame.data[..len]);
                true
            }
            PcapBlockOwned::NG(Block::SectionHeader(_)) => {
                self.interfaces.clear();
                false
            }
            PcapBlockOwned::NG(Block::InterfaceDescription(idb)) => {
                self.interfaces.push(InterfaceInfo {
                    link_type: idb.linktype.0,
                    units_per_second: idb.ts_resolution().unwrap_or(DEFAULT_UNITS_PER_SECOND),
                    ts_offset_seconds: idb.ts_offset(),
                });
                false
            }
            PcapBlockOwned::NG(Block::EnhancedPacket(epb)) => {
                let Some(meta) = self.interfaces.get(epb.if_id as usize).copied() else {
                    return false;
                };
                let units = (u64::from(epb.ts_high) << 32) | u64::from(epb.ts_low);
                let ts = scale_to_nanos(units, meta.units_per_second, meta.ts_offset_seconds);
                let len = epb.data.len().min(epb.caplen as usize);
                self.stage(ts, meta.link_type, &epb.data[..len]);
                true
            }
            PcapBlockOwned::NG(Block::SimplePacket(spb)) => {
                let Some(meta) = self.interfaces.first().copied() else {
                    return false;
                };
                let len = spb.data.len().min(spb.origlen as usize);
                self.stage(0, meta.link_type, &spb.data[..len]);
                true
            }
            PcapBlockOwned::NG(_) => false,
        }
    }
}

/// Reads frames from a pcap or pcapng file.
///
/// The two formats are probed automatically. pcapng is handled with its full
/// generality: every interface carries its own link type and timestamp
/// resolution, multiple sections reset the interface list, and metadata blocks
/// such as name resolution and decryption secrets are skipped rather than
/// treated as packets. A truncated final packet, the signature of a capture
/// that was stopped rather than closed, ends iteration cleanly and is reported
/// through [`PcapFileSource::truncated`] instead of failing the whole file.
pub struct PcapFileSource {
    reader: Box<dyn PcapReaderIterator>,
    state: SourceState,
    buffer_capacity: usize,
    truncated: bool,
    finished: bool,
}

impl PcapFileSource {
    /// Opens a capture file from a path.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, SourceError> {
        Self::from_reader(File::open(path)?)
    }

    /// Builds a source from any byte reader holding pcap or pcapng data.
    pub fn from_reader(reader: impl Read + 'static) -> Result<Self, SourceError> {
        let reader = create_reader(INITIAL_BUFFER_CAPACITY, reader).map_err(|e| match e {
            PcapError::HeaderNotRecognized | PcapError::Eof => SourceError::NotACapture,
            PcapError::ReadError => SourceError::Io(std::io::Error::other("read failed")),
            other => SourceError::Malformed(other.to_string()),
        })?;
        Ok(Self {
            reader,
            state: SourceState::default(),
            buffer_capacity: INITIAL_BUFFER_CAPACITY,
            truncated: false,
            finished: false,
        })
    }

    /// Returns true when the file ended in the middle of a block.
    pub fn truncated(&self) -> bool {
        self.truncated
    }
}

impl PacketSource for PcapFileSource {
    fn next_frame(&mut self) -> Result<Option<RawFrame<'_>>, SourceError> {
        if self.finished {
            return Ok(None);
        }
        loop {
            let staged = match self.reader.next() {
                Ok((offset, block)) => {
                    let staged = self.state.handle_block(&block);
                    self.reader.consume(offset);
                    staged
                }
                Err(PcapError::Eof) => {
                    self.finished = true;
                    return Ok(None);
                }
                Err(PcapError::UnexpectedEof) => {
                    self.finished = true;
                    self.truncated = true;
                    return Ok(None);
                }
                Err(PcapError::Incomplete(_)) => {
                    self.reader
                        .refill()
                        .map_err(|e| SourceError::Malformed(e.to_string()))?;
                    continue;
                }
                Err(PcapError::BufferTooSmall) => {
                    let grown = self.buffer_capacity.saturating_mul(2);
                    if grown > MAX_BUFFER_CAPACITY || !self.reader.grow(grown) {
                        self.finished = true;
                        return Err(SourceError::BlockTooLarge);
                    }
                    self.buffer_capacity = grown;
                    continue;
                }
                Err(PcapError::ReadError) => {
                    self.finished = true;
                    return Err(SourceError::Io(std::io::Error::other("read failed")));
                }
                Err(
                    e @ (PcapError::HeaderNotRecognized
                    | PcapError::NomError(..)
                    | PcapError::OwnedNomError(..)),
                ) => {
                    self.finished = true;
                    return Err(SourceError::Malformed(e.to_string()));
                }
            };
            if staged {
                return Ok(Some(RawFrame {
                    ts_nanos: self.state.frame_ts_nanos,
                    link_type: self.state.frame_link_type,
                    data: &self.state.frame,
                }));
            }
        }
    }
}

/// Converts a timestamp in interface units to nanoseconds since the epoch.
///
/// The arithmetic runs in 128 bits so the conversion stays exact for every
/// resolution pcapng can express, including nanosecond counts that already
/// fill most of a u64.
fn scale_to_nanos(units: u64, units_per_second: u64, offset_seconds: i64) -> u64 {
    if units_per_second == 0 {
        return 0;
    }
    let nanos = u128::from(units) * u128::from(NANOS_PER_SECOND) / u128::from(units_per_second);
    let offset = i128::from(offset_seconds) * i128::from(NANOS_PER_SECOND);
    u64::try_from(
        i128::try_from(nanos)
            .unwrap_or(i128::MAX)
            .saturating_add(offset),
    )
    .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::{PacketSource, PcapFileSource, SourceError, scale_to_nanos};

    fn legacy_pcap(frames: &[&[u8]]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&0xa1b2_c3d4_u32.to_le_bytes());
        v.extend_from_slice(&2u16.to_le_bytes());
        v.extend_from_slice(&4u16.to_le_bytes());
        v.extend_from_slice(&0i32.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(&65535u32.to_le_bytes());
        v.extend_from_slice(&1u32.to_le_bytes());
        for (i, frame) in frames.iter().enumerate() {
            let len = u32::try_from(frame.len()).unwrap();
            v.extend_from_slice(&u32::try_from(i + 1).unwrap().to_le_bytes());
            v.extend_from_slice(&500_000u32.to_le_bytes());
            v.extend_from_slice(&len.to_le_bytes());
            v.extend_from_slice(&len.to_le_bytes());
            v.extend_from_slice(frame);
        }
        v
    }

    #[test]
    fn reads_legacy_frames_with_timestamps() {
        let data = legacy_pcap(&[&[0xaa; 14], &[0xbb; 20]]);
        let mut source = PcapFileSource::from_reader(std::io::Cursor::new(data)).unwrap();

        let one = source.next_frame().unwrap().unwrap();
        assert_eq!(one.link_type, 1);
        assert_eq!(one.ts_nanos, 1_500_000_000);
        assert_eq!(one.data.len(), 14);

        let two = source.next_frame().unwrap().unwrap();
        assert_eq!(two.data, &[0xbb; 20]);

        assert!(source.next_frame().unwrap().is_none());
        assert!(!source.truncated());
    }

    #[test]
    fn truncated_final_frame_ends_cleanly() {
        let mut data = legacy_pcap(&[&[0xaa; 14], &[0xbb; 20]]);
        data.truncate(data.len() - 5);
        let mut source = PcapFileSource::from_reader(std::io::Cursor::new(data)).unwrap();

        assert!(source.next_frame().unwrap().is_some());
        assert!(source.next_frame().unwrap().is_none());
        assert!(source.truncated());
        assert!(source.next_frame().unwrap().is_none());
    }

    #[test]
    fn garbage_is_not_a_capture() {
        let err = PcapFileSource::from_reader(std::io::Cursor::new(vec![0x55; 64]))
            .err()
            .unwrap();
        assert!(matches!(err, SourceError::NotACapture));
    }

    #[test]
    fn timestamp_scaling_is_exact_for_common_resolutions() {
        assert_eq!(scale_to_nanos(1_500_000, 1_000_000, 0), 1_500_000_000);
        assert_eq!(scale_to_nanos(7, 1_000_000_000, 0), 7);
        assert_eq!(scale_to_nanos(1, 1, 1), 2_000_000_000);
    }
}
