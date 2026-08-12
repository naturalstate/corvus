// ©AngelaMos | 2026
// flow.rs

use std::collections::BTreeMap;
use std::net::SocketAddr;

/// A bidirectional flow identity.
///
/// The two endpoints are stored in sorted order so that a packet and its reply
/// hash to the same key. Which endpoint is the client is a separate question,
/// answered by who sent the SYN or, failing that, who spoke a ClientHello, and
/// it is deliberately not baked into the key: captures routinely start in the
/// middle of connections, and a key that guessed wrong would split one
/// conversation into two.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub lo: SocketAddr,
    pub hi: SocketAddr,
}

/// Which endpoint of a [`FlowKey`] sent a given segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    FromLo,
    FromHi,
}

impl Direction {
    #[must_use]
    pub const fn index(self) -> usize {
        match self {
            Direction::FromLo => 0,
            Direction::FromHi => 1,
        }
    }

    /// The source and destination addresses of traffic flowing this way.
    #[must_use]
    pub const fn addresses(self, key: &FlowKey) -> (SocketAddr, SocketAddr) {
        match self {
            Direction::FromLo => (key.lo, key.hi),
            Direction::FromHi => (key.hi, key.lo),
        }
    }
}

impl FlowKey {
    /// Normalizes a directional (source, destination) pair into a key plus the
    /// direction the packet travelled.
    #[must_use]
    pub fn from_pair(src: SocketAddr, dst: SocketAddr) -> (Self, Direction) {
        if src <= dst {
            (Self { lo: src, hi: dst }, Direction::FromLo)
        } else {
            (Self { lo: dst, hi: src }, Direction::FromHi)
        }
    }
}

/// The midpoint of the sequence space. In TCP serial arithmetic an offset at
/// or beyond this point is read as the segment sitting behind the anchor, not
/// absurdly far ahead of it.
const HALF_SERIAL_SPACE: u32 = 0x8000_0000;

/// Resource limits for one reassembled direction of one flow.
#[derive(Debug, Clone, Copy)]
pub struct ReassemblyLimits {
    /// Most contiguous bytes kept. Everything a passive fingerprinter reads
    /// sits in the first kilobytes of a stream, so this is a cap on patience,
    /// not on correctness.
    pub max_assembled_bytes: usize,
    /// Most bytes parked in the out of order buffer.
    pub max_pending_bytes: usize,
    /// Most segments parked in the out of order buffer.
    pub max_pending_segments: usize,
}

/// What [`StreamReassembler::push`] did with a segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushOutcome {
    /// The contiguous stream grew; the protocol layer should look again.
    Grew,
    /// Nothing new: a duplicate, pure overlap, or empty segment.
    Unchanged,
    /// The segment was parked out of order for later.
    Parked,
    /// The segment fell outside the window this reassembler is willing to
    /// track, or a buffer limit was hit, and it was dropped.
    Dropped,
}

/// Reassembles one direction of a TCP stream into contiguous bytes.
///
/// This is the piece most toy fingerprinting tools skip, and skipping it is
/// why they miss handshakes: a ClientHello, and even more so a certificate
/// chain, regularly spans several segments, and those segments arrive
/// reordered on any path with packet loss. The reassembler anchors at the
/// sequence number the SYN names or, on a flow whose start the capture
/// missed, at the first segment it sees. Everything else is a relative
/// offset from that anchor in wrapping serial arithmetic: in order segments
/// append to one contiguous buffer, out of order segments park in a map
/// keyed by offset until the gap before them fills.
///
/// Data from before the anchor on a SYN-less flow is gone; a streaming
/// engine cannot retroactively prepend, and accepting that loss explicitly
/// is what Suricata does for midstream pickup too. A segment that straddles
/// the anchor is trimmed to its useful part rather than discarded.
///
/// Overlaps resolve first write wins: bytes already accepted are never
/// rewritten by a later segment. A passive observer cannot know which copy
/// the receiver kept, and the CVE-2018-6794 capture in the test corpus exists
/// precisely because inconsistent overlap handling let attackers show an IDS
/// a different stream than the one the victim read. First write wins is one
/// deterministic, documented answer.
#[derive(Debug)]
pub struct StreamReassembler {
    limits: ReassemblyLimits,
    anchor: Option<u32>,
    assembled: Vec<u8>,
    pending: BTreeMap<u32, Vec<u8>>,
    pending_bytes: usize,
    released: bool,
    capped: bool,
}

impl StreamReassembler {
    #[must_use]
    pub fn new(limits: ReassemblyLimits) -> Self {
        Self {
            limits,
            anchor: None,
            assembled: Vec::new(),
            pending: BTreeMap::new(),
            pending_bytes: 0,
            released: false,
            capped: false,
        }
    }

    /// The contiguous bytes assembled so far, from the anchor onward.
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.assembled
    }

    /// Pins the stream start, used when a SYN reveals the true initial
    /// sequence number before any data arrives. Later anchors are ignored.
    pub fn anchor(&mut self, seq: u32) {
        if self.anchor.is_none() {
            self.anchor = Some(seq);
        }
    }

    /// Drops every buffer and refuses all future data.
    ///
    /// Called once the protocol layer has what it needs, or knows it never
    /// will. This is what keeps memory flat when a capture contains long
    /// lived flows: the flow entry stays, the payload buffers do not.
    pub fn release(&mut self) {
        self.assembled = Vec::new();
        self.pending = BTreeMap::new();
        self.pending_bytes = 0;
        self.released = true;
    }

    #[must_use]
    pub fn released(&self) -> bool {
        self.released
    }

    /// True when the assembled cap was hit and the tail of the stream is gone.
    #[must_use]
    pub fn capped(&self) -> bool {
        self.capped
    }

    /// Offers one segment to the stream.
    pub fn push(&mut self, seq: u32, payload: &[u8]) -> PushOutcome {
        if self.released || payload.is_empty() {
            return PushOutcome::Unchanged;
        }
        if self.capped {
            return PushOutcome::Dropped;
        }
        let anchor = *self.anchor.get_or_insert(seq);

        let offset = seq.wrapping_sub(anchor);
        if offset >= HALF_SERIAL_SPACE {
            let stale = offset.wrapping_neg() as usize;
            if stale >= payload.len() {
                return PushOutcome::Unchanged;
            }
            return self.push(anchor, &payload[stale..]);
        }
        let window_end = self
            .limits
            .max_assembled_bytes
            .saturating_add(self.limits.max_pending_bytes);
        if offset as usize > window_end {
            return PushOutcome::Dropped;
        }

        let assembled_len = self.assembled.len();
        if (offset as usize) < assembled_len {
            let overlap = assembled_len - offset as usize;
            if overlap >= payload.len() {
                return PushOutcome::Unchanged;
            }
            return self.append_in_order(&payload[overlap..]);
        }
        if offset as usize == assembled_len {
            return self.append_in_order(payload);
        }

        if self.pending.len() >= self.limits.max_pending_segments
            || self.pending_bytes.saturating_add(payload.len()) > self.limits.max_pending_bytes
        {
            return PushOutcome::Dropped;
        }
        match self.pending.entry(offset) {
            std::collections::btree_map::Entry::Occupied(existing) => {
                if existing.get().len() >= payload.len() {
                    return PushOutcome::Unchanged;
                }
                self.pending_bytes += payload.len() - existing.get().len();
                *existing.into_mut() = payload.to_vec();
            }
            std::collections::btree_map::Entry::Vacant(slot) => {
                self.pending_bytes += payload.len();
                slot.insert(payload.to_vec());
            }
        }
        PushOutcome::Parked
    }

    fn append_in_order(&mut self, payload: &[u8]) -> PushOutcome {
        let room = self
            .limits
            .max_assembled_bytes
            .saturating_sub(self.assembled.len());
        if room == 0 {
            self.mark_capped();
            return PushOutcome::Dropped;
        }
        let take = payload.len().min(room);
        self.assembled.extend_from_slice(&payload[..take]);
        if take < payload.len() {
            self.mark_capped();
        } else {
            self.drain_pending();
        }
        PushOutcome::Grew
    }

    /// Splices parked segments onto the contiguous buffer while they touch it.
    fn drain_pending(&mut self) {
        while let Some(entry) = self.pending.first_entry() {
            let offset = *entry.key() as usize;
            if offset > self.assembled.len() {
                break;
            }
            let segment = entry.remove();
            self.pending_bytes -= segment.len();
            let overlap = self.assembled.len() - offset;
            if overlap >= segment.len() {
                continue;
            }
            let room = self
                .limits
                .max_assembled_bytes
                .saturating_sub(self.assembled.len());
            let take = (segment.len() - overlap).min(room);
            self.assembled
                .extend_from_slice(&segment[overlap..overlap + take]);
            if take < segment.len() - overlap {
                self.mark_capped();
                return;
            }
        }
    }

    /// Once the assembled cap is hit nothing later can ever become contiguous,
    /// so the parked segments are garbage. Drop them and refuse new data, but
    /// keep the assembled prefix: it is still a valid stream head and whatever
    /// the protocol layer already read from it stands.
    fn mark_capped(&mut self) {
        self.capped = true;
        self.pending = BTreeMap::new();
        self.pending_bytes = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::{FlowKey, PushOutcome, ReassemblyLimits, StreamReassembler};

    fn limits() -> ReassemblyLimits {
        ReassemblyLimits {
            max_assembled_bytes: 64,
            max_pending_bytes: 64,
            max_pending_segments: 4,
        }
    }

    fn reasm() -> StreamReassembler {
        StreamReassembler::new(limits())
    }

    #[test]
    fn both_directions_share_one_key() {
        let a: std::net::SocketAddr = "10.0.0.1:40000".parse().unwrap();
        let b: std::net::SocketAddr = "10.0.0.2:443".parse().unwrap();
        let (forward, fwd_dir) = FlowKey::from_pair(a, b);
        let (reverse, rev_dir) = FlowKey::from_pair(b, a);
        assert_eq!(forward, reverse);
        assert_ne!(fwd_dir, rev_dir);
        assert_eq!(fwd_dir.addresses(&forward), (a, b));
        assert_eq!(rev_dir.addresses(&reverse), (b, a));
    }

    #[test]
    fn in_order_segments_concatenate() {
        let mut r = reasm();
        assert_eq!(r.push(100, b"hell"), PushOutcome::Grew);
        assert_eq!(r.push(104, b"o"), PushOutcome::Grew);
        assert_eq!(r.data(), b"hello");
    }

    #[test]
    fn out_of_order_segments_wait_for_the_gap() {
        let mut r = reasm();
        assert_eq!(r.push(100, b"hell"), PushOutcome::Grew);
        assert_eq!(r.push(107, b"orld"), PushOutcome::Parked);
        assert_eq!(r.data(), b"hell");
        assert_eq!(r.push(104, b"o w"), PushOutcome::Grew);
        assert_eq!(r.data(), b"hello world");
    }

    #[test]
    fn anchor_from_syn_orders_data_arriving_backwards() {
        let mut r = reasm();
        r.anchor(1000);
        assert_eq!(r.push(1004, b"data"), PushOutcome::Parked);
        assert_eq!(r.push(1000, b"more"), PushOutcome::Grew);
        assert_eq!(r.data(), b"moredata");
    }

    #[test]
    fn retransmissions_change_nothing() {
        let mut r = reasm();
        r.push(100, b"abcdef");
        assert_eq!(r.push(100, b"abcdef"), PushOutcome::Unchanged);
        assert_eq!(r.push(102, b"cd"), PushOutcome::Unchanged);
        assert_eq!(r.data(), b"abcdef");
    }

    #[test]
    fn overlapping_segment_keeps_the_first_write() {
        let mut r = reasm();
        r.push(100, b"abcdef");
        assert_eq!(r.push(103, b"XXXghi"), PushOutcome::Grew);
        assert_eq!(r.data(), b"abcdefghi");
    }

    #[test]
    fn parked_overlap_keeps_the_first_write_too() {
        let mut r = reasm();
        r.anchor(100);
        assert_eq!(r.push(104, b"efgh"), PushOutcome::Parked);
        assert_eq!(r.push(100, b"abcdEFG"), PushOutcome::Grew);
        assert_eq!(r.data(), b"abcdEFGh");
    }

    #[test]
    fn sequence_numbers_wrap_around_zero() {
        let mut r = reasm();
        let anchor = u32::MAX - 1;
        assert_eq!(r.push(anchor, b"ab"), PushOutcome::Grew);
        assert_eq!(r.push(0, b"cd"), PushOutcome::Grew);
        assert_eq!(r.push(2, b"ef"), PushOutcome::Grew);
        assert_eq!(r.data(), b"abcdef");
    }

    #[test]
    fn stale_pre_anchor_data_is_ignored_and_far_future_dropped() {
        let mut r = reasm();
        r.push(1000, b"ab");
        assert_eq!(r.push(990, b"old"), PushOutcome::Unchanged);
        assert_eq!(r.push(100_000, b"far"), PushOutcome::Dropped);
        assert_eq!(r.data(), b"ab");
    }

    #[test]
    fn segment_straddling_the_anchor_is_trimmed_not_lost() {
        let mut r = reasm();
        r.anchor(1000);
        assert_eq!(r.push(996, b"oldNEW"), PushOutcome::Grew);
        assert_eq!(r.data(), b"EW");
    }

    #[test]
    fn assembled_cap_truncates_but_keeps_the_prefix() {
        let mut r = reasm();
        let big = vec![0x41u8; 100];
        assert_eq!(r.push(0, &big), PushOutcome::Grew);
        assert_eq!(r.data().len(), limits().max_assembled_bytes);
        assert_eq!(r.push(100, b"more"), PushOutcome::Dropped);
    }

    #[test]
    fn pending_limits_drop_excess_segments() {
        let mut r = reasm();
        r.anchor(0);
        assert_eq!(r.push(10, b"a"), PushOutcome::Parked);
        assert_eq!(r.push(20, b"b"), PushOutcome::Parked);
        assert_eq!(r.push(30, b"c"), PushOutcome::Parked);
        assert_eq!(r.push(40, b"d"), PushOutcome::Parked);
        assert_eq!(r.push(50, b"e"), PushOutcome::Dropped);
    }

    #[test]
    fn release_drops_buffers_and_refuses_data() {
        let mut r = reasm();
        r.push(0, b"abc");
        r.release();
        assert!(r.released());
        assert_eq!(r.data(), b"");
        assert_eq!(r.push(3, b"def"), PushOutcome::Unchanged);
    }
}
