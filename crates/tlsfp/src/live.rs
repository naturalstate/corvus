// ©AngelaMos | 2026
// live.rs

//! Live capture behind the same [`PacketSource`] seam the file path uses.
//!
//! libpcap blocks, tokio must not, and the two meet here. A dedicated OS
//! thread owns the activated capture handle and does nothing but pull
//! frames and push them into a bounded channel. A `std::thread` rather
//! than `spawn_blocking` because an indefinite capture loop parked on the
//! blocking pool would pin one of its slots forever. The channel is
//! bounded so a slow consumer backs pressure up into the kernel ring
//! buffer, where overload becomes a counted drop in [`CaptureStats`]
//! instead of unbounded memory growth here. The consumer side is
//! [`LiveSource`]: a synchronous [`PacketSource`] for anything that wants
//! to block, and [`LiveSource::next_frame_async`] for the tokio side of
//! the bridge. Both feed the exact pipeline the pcap file path uses.
//!
//! The capture handle runs non-blocking and the thread waits on `poll`
//! with a bounded timeout, not on libpcap's own read timeout. That read
//! timeout cannot be relied on to bound a read: on a silent interface
//! several platforms never start its timer, so a `next_packet` call would
//! park until the next frame arrives, which on an idle link can be never.
//! Owning the wait through `poll` is what lets the loop notice a stop
//! request promptly no matter how quiet the wire is.

use std::io::ErrorKind;
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;

use pcap::{Active, Capture, Device};
use rustix::event::{PollFd, PollFlags, Timespec, poll};
use smallvec::SmallVec;
use thiserror::Error;

use tlsfp_core::{PacketSource, RawFrame, SourceError};

/// Kernel side prefilter applied before frames ever reach userspace.
///
/// Every TCP segment stays: TLS runs on any port, JA4T wants the SYNs, and
/// JA4H wants cleartext HTTP wherever it appears. UDP narrows to 443,
/// where QUIC lives. Everything else, ARP, ICMP, DNS, mDNS, DHCP, drops in
/// the kernel for the cost of a BPF program, not a context switch.
pub const DEFAULT_BPF_FILTER: &str = "tcp or (udp and port 443)";

/// Full frames, never clipped. A truncated segment would punch a hole in
/// TCP reassembly and silently end fingerprinting for that stream, and
/// offloads like GRO can hand the capture socket frames far beyond the
/// wire MTU.
const SNAPLEN: i32 = 65_535;

/// How long the capture thread waits in `poll` before looping back to
/// re-check the stop flag. This is the upper bound on shutdown latency on
/// an idle interface, and it is paid only as latency, never as busy work.
const POLL_TIMEOUT_MILLIS: i64 = 100;

/// Kernel capture buffer. This is the shock absorber while the channel is
/// full: bursts queue here, and only when it overflows does the kernel
/// drop, visibly, into [`CaptureStats::kernel_dropped`].
const KERNEL_BUFFER_BYTES: i32 = 4 * 1024 * 1024;

/// Frames in flight between the capture thread and the consumer. Bounded
/// so the bridge applies backpressure instead of growing without limit.
const CHANNEL_CAPACITY: usize = 512;

/// Frames at or under this size live inline in the channel message, no
/// heap allocation per frame. Sized to cover an ethernet frame at the
/// usual 1500 MTU plus VLAN tags; offload jumbos spill to the heap.
const INLINE_FRAME_BYTES: usize = 2048;

const NANOS_PER_SECOND: u64 = 1_000_000_000;
const NANOS_PER_MILLI: i64 = 1_000_000;
const NANOS_PER_MICRO: u64 = 1_000;

/// Errors that prevent a live capture from starting.
#[derive(Debug, Error)]
pub enum LiveError {
    #[error("{0}")]
    Open(String),

    #[error("invalid BPF filter {filter:?}: {source}")]
    Filter { filter: String, source: pcap::Error },

    #[error("failed to start the capture thread: {0}")]
    Spawn(std::io::Error),
}

/// Knobs for a live capture session.
#[derive(Debug, Clone)]
pub struct LiveConfig {
    /// BPF program text compiled into the kernel before capture begins.
    pub filter: String,
    /// Whether to ask the interface for traffic beyond its own addresses.
    pub promiscuous: bool,
}

impl Default for LiveConfig {
    fn default() -> Self {
        Self {
            filter: DEFAULT_BPF_FILTER.to_owned(),
            promiscuous: true,
        }
    }
}

/// Final tallies from the kernel side of a finished capture.
///
/// `kernel_dropped` is the honesty number: frames the kernel discarded
/// because the consumer fell behind. When it is nonzero, an absence of
/// fingerprints is not evidence of an absence of handshakes.
#[derive(Debug, Clone, Copy, Default)]
pub struct CaptureStats {
    pub received: u64,
    pub kernel_dropped: u64,
    pub interface_dropped: u64,
}

/// Asks the capture thread to stop, from any thread or task.
///
/// The request is honored within one poll timeout: the capture loop
/// checks the flag between packets, and an idle interface wakes it every
/// [`POLL_TIMEOUT_MILLIS`]. Relaxed ordering is enough because the flag
/// carries no data of its own: every captured frame crosses the channel
/// and every error crosses the `OnceLock`, each of which synchronizes
/// itself, and the join in [`LiveSource::close`] is the final barrier.
#[derive(Debug, Clone)]
pub struct StopHandle(Arc<AtomicBool>);

impl StopHandle {
    pub fn stop(&self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

/// One frame copied out of the kernel buffer, owned so it can cross the
/// thread boundary.
struct CapturedFrame {
    ts_nanos: u64,
    data: SmallVec<[u8; INLINE_FRAME_BYTES]>,
}

/// Frames from a live interface, behind the [`PacketSource`] seam.
///
/// Construction activates the interface, installs the BPF filter, and
/// spawns the capture thread. From then on this type is the receiving end
/// of the bridge: [`PacketSource::next_frame`] blocks for synchronous
/// consumers, [`LiveSource::next_frame_async`] suspends for tokio ones,
/// and both hand out frames borrowing from an internal staging buffer
/// exactly like [`tlsfp_core::PcapFileSource`] does.
pub struct LiveSource {
    receiver: flume::Receiver<CapturedFrame>,
    staged: CapturedFrame,
    link_type: i32,
    stop: Arc<AtomicBool>,
    failure: Arc<OnceLock<String>>,
    failure_reported: bool,
    thread: Option<JoinHandle<Option<CaptureStats>>>,
}

impl LiveSource {
    /// Opens an interface by name and starts capturing immediately.
    pub fn open(interface: &str, config: &LiveConfig) -> Result<Self, LiveError> {
        let inactive = Capture::from_device(interface)
            .map_err(|error| open_error(interface, &error))?
            .promisc(config.promiscuous)
            .snaplen(SNAPLEN)
            .immediate_mode(true)
            .buffer_size(KERNEL_BUFFER_BYTES);
        let mut capture = inactive
            .open()
            .map_err(|error| open_error(interface, &error))?;
        capture
            .filter(&config.filter, true)
            .map_err(|source| LiveError::Filter {
                filter: config.filter.clone(),
                source,
            })?;
        let capture = capture
            .setnonblock()
            .map_err(|error| open_error(interface, &error))?;
        let link_type = capture.get_datalink().0;

        let (sender, receiver) = flume::bounded(CHANNEL_CAPACITY);
        let stop = Arc::new(AtomicBool::new(false));
        let failure = Arc::new(OnceLock::new());
        let thread = std::thread::Builder::new()
            .name("tlsfp-capture".to_owned())
            .spawn({
                let stop = Arc::clone(&stop);
                let failure = Arc::clone(&failure);
                move || capture_loop(capture, &sender, &stop, &failure)
            })
            .map_err(LiveError::Spawn)?;

        Ok(Self {
            receiver,
            staged: CapturedFrame {
                ts_nanos: 0,
                data: SmallVec::new(),
            },
            link_type,
            stop,
            failure,
            failure_reported: false,
            thread: Some(thread),
        })
    }

    /// Returns a handle that requests a graceful stop of the capture.
    pub fn stop_handle(&self) -> StopHandle {
        StopHandle(Arc::clone(&self.stop))
    }

    /// The async twin of [`PacketSource::next_frame`] for the tokio side
    /// of the bridge: suspends instead of blocking, then stages and
    /// returns the frame through the same internals.
    pub async fn next_frame_async(&mut self) -> Result<Option<RawFrame<'_>>, SourceError> {
        let received = self.receiver.recv_async().await;
        match received {
            Ok(frame) => Ok(Some(self.stage(frame))),
            Err(_) => self.drained(),
        }
    }

    /// Stops the capture, waits for the thread to finish, and returns the
    /// kernel's final counts. `None` when the statistics could not be
    /// read.
    pub fn close(mut self) -> Option<CaptureStats> {
        self.stop.store(true, Ordering::Relaxed);
        let thread = self.thread.take();
        drop(self);
        thread.and_then(|handle| handle.join().ok()).flatten()
    }

    fn stage(&mut self, frame: CapturedFrame) -> RawFrame<'_> {
        self.staged = frame;
        RawFrame {
            ts_nanos: self.staged.ts_nanos,
            link_type: self.link_type,
            data: &self.staged.data,
        }
    }

    /// Maps channel disconnection to the trait's vocabulary: a recorded
    /// capture failure surfaces as an error exactly once, then the source
    /// reads as exhausted; a clean shutdown reads as exhausted from the
    /// start.
    fn drained(&mut self) -> Result<Option<RawFrame<'_>>, SourceError> {
        if self.failure_reported {
            return Ok(None);
        }
        match self.failure.get() {
            Some(message) => {
                self.failure_reported = true;
                Err(SourceError::Capture(message.clone()))
            }
            None => Ok(None),
        }
    }
}

impl PacketSource for LiveSource {
    fn next_frame(&mut self) -> Result<Option<RawFrame<'_>>, SourceError> {
        match self.receiver.recv() {
            Ok(frame) => Ok(Some(self.stage(frame))),
            Err(_) => self.drained(),
        }
    }
}

/// Dropping the source signals the capture thread instead of joining it.
/// The receiver field drops right after, which unblocks a capture thread
/// parked on a full channel, so the thread always exits on its own within
/// one poll timeout. [`LiveSource::close`] is the path that also waits
/// and collects statistics.
impl Drop for LiveSource {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// The capture thread: wait for readability, drain the ring, repeat.
///
/// Each turn polls the capture fd with a bounded timeout. A timeout is the
/// heartbeat that lets an idle interface still notice a stop request. When
/// the fd is readable the loop drains every queued packet before polling
/// again, since one readiness signal can cover a burst. A full channel
/// makes `send` block, which stops the draining, which lets the kernel
/// buffer absorb the burst and count what it sheds. The non-blocking
/// handle reports an empty ring as `TimeoutExpired`, the signal to go wait
/// again. An error or hangup latched on the fd, the mark of an interface
/// going down, is drained of any last packets and then ends the loop,
/// because `poll` keeps reporting a latched condition as ready and would
/// otherwise spin a core over an empty ring. Any other capture or poll
/// error is recorded for the consumer and ends the loop.
fn capture_loop(
    mut capture: Capture<Active>,
    sender: &flume::Sender<CapturedFrame>,
    stop: &AtomicBool,
    failure: &OnceLock<String>,
) -> Option<CaptureStats> {
    let timeout = Timespec {
        tv_sec: 0,
        tv_nsec: POLL_TIMEOUT_MILLIS * NANOS_PER_MILLI,
    };
    'capture: while !stop.load(Ordering::Relaxed) {
        let revents = {
            let mut fds = [PollFd::new(&capture, PollFlags::IN)];
            match poll(&mut fds, Some(&timeout)) {
                Ok(0) | Err(rustix::io::Errno::INTR) => None,
                Ok(_) => Some(fds[0].revents()),
                Err(error) => {
                    let _ = failure.set(format!("waiting on the capture failed: {error}"));
                    break 'capture;
                }
            }
        };
        let Some(revents) = revents else {
            continue;
        };
        loop {
            if stop.load(Ordering::Relaxed) {
                break 'capture;
            }
            match capture.next_packet() {
                Ok(packet) => {
                    let frame = CapturedFrame {
                        ts_nanos: timeval_to_nanos(
                            packet.header.ts.tv_sec,
                            packet.header.ts.tv_usec,
                        ),
                        data: SmallVec::from_slice(packet.data),
                    };
                    if sender.send(frame).is_err() {
                        break 'capture;
                    }
                }
                Err(pcap::Error::TimeoutExpired) => break,
                Err(error) => {
                    let _ = failure.set(error.to_string());
                    break 'capture;
                }
            }
        }
        if revents.intersects(PollFlags::ERR | PollFlags::HUP | PollFlags::NVAL) {
            let _ = failure.set("the capture interface reported an error or hangup".to_owned());
            break 'capture;
        }
    }
    capture.stats().ok().map(|stat| CaptureStats {
        received: u64::from(stat.received),
        kernel_dropped: u64::from(stat.dropped),
        interface_dropped: u64::from(stat.if_dropped),
    })
}

/// Converts a capture timestamp to nanoseconds since the epoch, the unit
/// [`RawFrame`] carries. Generic over the integer widths because libc's
/// timeval fields differ across platforms. Saturates rather than wraps,
/// and clamps timestamps from before the epoch to zero.
fn timeval_to_nanos(sec: impl Into<i64>, micros: impl Into<i64>) -> u64 {
    let sec = u64::try_from(sec.into()).unwrap_or(0);
    let micros = u64::try_from(micros.into()).unwrap_or(0);
    sec.saturating_mul(NANOS_PER_SECOND)
        .saturating_add(micros.saturating_mul(NANOS_PER_MICRO))
}

/// Builds the open failure message an operator can act on: the underlying
/// error, the capability grant when the cause is permissions, and the
/// interfaces libpcap can actually see.
fn open_error(interface: &str, error: &pcap::Error) -> LiveError {
    use std::fmt::Write as _;

    let mut message = format!("cannot open capture on {interface}: {error}");
    if is_permission_denied(error) {
        let binary = std::env::current_exe().map_or_else(
            |_| "$(command -v tlsfp)".to_owned(),
            |path| path.display().to_string(),
        );
        let _ = write!(
            message,
            "\nlive capture needs CAP_NET_RAW; grant it once per build with:\n  sudo setcap cap_net_raw,cap_net_admin=eip {binary}"
        );
    }
    if let Ok(devices) = Device::list() {
        if !devices.is_empty() {
            let names: Vec<String> = devices.into_iter().map(|device| device.name).collect();
            let _ = write!(message, "\navailable interfaces: {}", names.join(", "));
        }
    }
    LiveError::Open(message)
}

/// libpcap has no structured permission error; it reports activation
/// failures as text. The two phrasings Linux produces both name the
/// problem, which is enough to decide whether the setcap hint belongs in
/// the message.
fn is_permission_denied(error: &pcap::Error) -> bool {
    match error {
        pcap::Error::PcapError(message) => {
            let lower = message.to_ascii_lowercase();
            lower.contains("permission") || lower.contains("not permitted")
        }
        pcap::Error::IoError(kind) => *kind == ErrorKind::PermissionDenied,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::OnceLock;
    use std::sync::atomic::AtomicBool;

    use etherparse::PacketBuilder;
    use smallvec::SmallVec;

    use tlsfp_core::{PacketSource, Pipeline, PipelineConfig, SourceError};

    use super::{CapturedFrame, LiveConfig, LiveSource, timeval_to_nanos};

    fn source_from_parts(
        receiver: flume::Receiver<CapturedFrame>,
        failure: Arc<OnceLock<String>>,
    ) -> LiveSource {
        LiveSource {
            receiver,
            staged: CapturedFrame {
                ts_nanos: 0,
                data: SmallVec::new(),
            },
            link_type: 1,
            stop: Arc::new(AtomicBool::new(false)),
            failure,
            failure_reported: false,
            thread: None,
        }
    }

    fn frame(ts_nanos: u64, data: &[u8]) -> CapturedFrame {
        CapturedFrame {
            ts_nanos,
            data: SmallVec::from_slice(data),
        }
    }

    #[test]
    fn frames_cross_the_bridge_in_order_and_end_cleanly() {
        let (sender, receiver) = flume::bounded(8);
        let producer = std::thread::spawn(move || {
            for i in 0..100u64 {
                sender.send(frame(i, &i.to_be_bytes())).unwrap();
            }
        });

        let mut source = source_from_parts(receiver, Arc::new(OnceLock::new()));
        for i in 0..100u64 {
            let staged = source.next_frame().unwrap().unwrap();
            assert_eq!(staged.ts_nanos, i);
            assert_eq!(staged.link_type, 1);
            assert_eq!(staged.data, i.to_be_bytes());
        }
        assert!(source.next_frame().unwrap().is_none());
        producer.join().unwrap();
    }

    #[test]
    fn capture_failure_surfaces_once_then_reads_exhausted() {
        let (sender, receiver) = flume::bounded::<CapturedFrame>(1);
        let failure = Arc::new(OnceLock::new());
        failure.set("the interface went away".to_owned()).unwrap();
        drop(sender);

        let mut source = source_from_parts(receiver, failure);
        let error = source.next_frame().unwrap_err();
        assert!(matches!(
            error,
            SourceError::Capture(message) if message.contains("went away")
        ));
        assert!(source.next_frame().unwrap().is_none());
    }

    #[test]
    fn live_frames_feed_the_same_pipeline_as_files() {
        let request = b"GET / HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n";
        let builder = PacketBuilder::ethernet2([1; 6], [2; 6])
            .ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64)
            .tcp(40000, 80, 1000, 64240);
        let mut bytes = Vec::with_capacity(builder.size(request.len()));
        builder.write(&mut bytes, request).unwrap();

        let (sender, receiver) = flume::bounded(8);
        sender.send(frame(7, &bytes)).unwrap();
        drop(sender);

        let mut source = source_from_parts(receiver, Arc::new(OnceLock::new()));
        let mut pipeline = Pipeline::new(PipelineConfig::default());
        let mut events = Vec::new();
        pipeline
            .run(&mut source, |event| events.push(event))
            .unwrap();

        assert_eq!(events.len(), 1);
        assert!(events[0].to_string().contains("http_request"));
        assert_eq!(events[0].src.to_string(), "10.0.0.1:40000");
        assert_eq!(pipeline.counters().tcp_segments, 1);
    }

    #[tokio::test]
    async fn async_bridge_yields_frames_then_reads_exhausted() {
        let (sender, receiver) = flume::bounded(2);
        let mut source = source_from_parts(receiver, Arc::new(OnceLock::new()));

        sender.send(frame(1, &[0xab])).unwrap();
        drop(sender);

        let staged = source.next_frame_async().await.unwrap().unwrap();
        assert_eq!(staged.ts_nanos, 1);
        assert_eq!(staged.data, [0xab]);
        assert!(source.next_frame_async().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn async_bridge_surfaces_capture_failure() {
        let (sender, receiver) = flume::bounded::<CapturedFrame>(1);
        let failure = Arc::new(OnceLock::new());
        failure.set("device vanished".to_owned()).unwrap();
        drop(sender);

        let mut source = source_from_parts(receiver, failure);
        let error = source.next_frame_async().await.unwrap_err();
        assert!(matches!(error, SourceError::Capture(_)));
        assert!(source.next_frame_async().await.unwrap().is_none());
    }

    #[test]
    fn timeval_conversion_scales_clamps_and_saturates() {
        assert_eq!(timeval_to_nanos(1i64, 500_000i64), 1_500_000_000);
        assert_eq!(timeval_to_nanos(0i64, 7i64), 7_000);
        assert_eq!(timeval_to_nanos(-5i64, 0i64), 0);
        assert_eq!(timeval_to_nanos(0i64, -1i64), 0);
        assert_eq!(timeval_to_nanos(i64::MAX, 999_999i64), u64::MAX);
    }

    #[test]
    #[ignore = "needs CAP_NET_RAW or root: sudo -E cargo test -p tlsfp -- --ignored"]
    fn loopback_capture_sees_a_syn() {
        let config = LiveConfig {
            filter: "tcp and port 39999".to_owned(),
            promiscuous: false,
        };
        let mut source = LiveSource::open("lo", &config).unwrap();
        let _ = std::net::TcpStream::connect(("127.0.0.1", 39999));

        let seen = source.next_frame().unwrap().expect("a SYN on loopback");
        assert!(!seen.data.is_empty());

        let stats = source.close().expect("final capture statistics");
        assert!(stats.received >= 1);
    }
}
