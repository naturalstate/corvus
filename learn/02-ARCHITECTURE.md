<!-- ©AngelaMos | 2026 -->
<!-- 02-ARCHITECTURE.md -->

# JA3/JA4 TLS Fingerprinting: Architecture

This document describes how the tool is put together: the three crates and why they are separate, the capture pipeline a frame flows through, the intelligence store that judges a fingerprint, and the threat model that shaped every bound. Read [01-CONCEPTS.md](./01-CONCEPTS.md) first; this assumes you know what the fingerprints are.

## The three-crate split

The project is one Cargo workspace with three crates in a strict dependency line. Nothing points backwards.

```
   ┌──────────────────────────────────────────────────────────┐
   │  tlsfp-core     the engine                                │
   │  parses TLS, reassembles TCP, decrypts QUIC, hashes.      │
   │  Depends on NOTHING that touches a network, a database,   │
   │  or an async runtime. Forbids `unsafe`. Fuzzable.         │
   └───────────────────────────┬──────────────────────────────┘
                               │  tlsfp-core::FingerprintEvent
   ┌───────────────────────────┴──────────────────────────────┐
   │  tlsfp-intel    the judgement                             │
   │  owns a bundled SQLite database. Matches a fingerprint    │
   │  to a verdict, runs the detection rules, records alerts.  │
   │  Synchronous on purpose. Depends only on tlsfp-core.      │
   └───────────────────────────┬──────────────────────────────┘
                               │  MatchReport + Alert
   ┌───────────────────────────┴──────────────────────────────┐
   │  tlsfp          the binary                                │
   │  the clap CLI and the axum web dashboard. Wires a packet  │
   │  source to the engine to the store to a writer.           │
   └──────────────────────────────────────────────────────────┘
```

The reason for the split is testability and blast radius. `tlsfp-core` has no I/O, so the entire fingerprinting engine runs byte-exact in unit tests against vendored captures, with no network, no clock, and no database to mock. It can be fuzzed in isolation, which matters because it parses hostile input. `tlsfp-intel` adds exactly one concern, persistence and judgement, and depends only on the engine's output type. The binary is the only crate that knows about interfaces, runtimes, and the terminal. A bug in the dashboard cannot reach the parser; a parser change cannot break the database schema.

## The capture pipeline

Inside `tlsfp-core`, a raw frame becomes a fingerprint by flowing through a fixed sequence of stages. Each stage is a separate module so it can be understood and tested alone.

```
  PacketSource          decode             flow reassembly        protocol            fingerprint
  ────────────          ──────             ───────────────        ────────            ───────────
  pcap file       ┌─> strip Ethernet  ┌─> StreamReassembler  ┌─> watch for a    ┌─> ja3()  ja4()
  pcapng file ────┤   strip IP         │   per (src,dst,      │   TLS record or  │   ja4h() ja4x()
  live (libpcap)  │   keep TCP segment │    sport,dport):     │   an HTTP head   │   ja4t()
  QUIC initial    └─> or UDP datagram  │    order, dedup,     │   in the         └─> StreamEvent
                                       │    resolve overlap,  │   contiguous          + addrs + ts
                      decode.rs        │    bound buffers     │   bytes              = FingerprintEvent
                                       │                      │
                      source.rs        └── flow.rs            └── tls.rs            event.rs
```

**`source.rs`** abstracts where frames come from. `PcapFileSource` reads a file; the binary's `LiveSource` reads an interface. Both yield a `RawFrame` (a timestamp, a link type, and a byte slice). The engine does not know or care which it got.

**`decode.rs`** strips the link and network layers off a frame and yields either a TCP `DecodedSegment` or a UDP `DecodedDatagram`, or a `Skip` reason if the frame is not interesting. This is also where the TCP SYN options are walked for JA4T, before reassembly, because JA4T reads the SYN itself, not the stream it opens.

**`flow.rs`** is the reassembly engine and the heart of the capture path. It keeps a table of flows keyed by the four-tuple. For each direction of each flow it maintains a contiguous byte buffer and a set of parked out-of-order segments. When a segment fills the gap before a parked run, the run is merged in. Overlaps are resolved. This is the stage that makes a ClientHello split across three reordered segments parse correctly, and it is the stage most carefully bounded against abuse (see the threat model below).

**`tls.rs`** watches each reassembled stream for something to fingerprint: a complete TLS handshake flight (ClientHello, ServerHello, Certificate) or the head of a cleartext HTTP request. When it recognizes one, it parses it (`parse/`) and computes the fingerprint.

**`event.rs`** defines the output. A `StreamEvent` is the fingerprint plus its kind:

```rust
pub enum StreamEvent {
    ClientHello { ja3, ja4, sni, alpn, user_agent, ... },
    ServerHello { ja3s, ja4s, ... },
    Certificate { ja4x },
    HttpRequest { ja4h, method, user_agent, ... },
    TcpSyn     { ja4t },
    TcpSynAck  { ja4ts },
}
```

Wrapped with the source and destination addresses and a timestamp, it becomes a `FingerprintEvent`, the single type that crosses the boundary out of the engine. Everything downstream consumes `FingerprintEvent` and nothing else.

The QUIC path (`quic.rs`) is a parallel entry into the same fingerprint code. A UDP datagram on the QUIC path is parsed as a QUIC Initial, its keys are derived from its Connection ID, its payload is decrypted, its CRYPTO frames are reassembled into a ClientHello, and that ClientHello goes through the same `ja4()` as a TCP one, emerging with a `q` transport marker.

## The intelligence store

`tlsfp-intel` turns a `FingerprintEvent` into a judgement. It owns an embedded SQLite database, which is the right choice here: zero configuration, a single file, transactional, and able to support a dashboard reading while a sensor writes (it opens in WAL mode with a busy timeout for exactly that). The store is **synchronous**, deliberately. A lookup is one indexed query and a capture is a plain loop; wrapping that in an async runtime would add complexity and buy nothing. The async runtime lives only in the web server, where concurrent readers genuinely exist.

```
   FingerprintEvent
         │
         ▼
   ┌───────────────────────────────────────────────┐
   │  matcher.rs   exact lookup by (kind, value)    │
   │               + JA4 fuzzy match on the         │   intel_fingerprint
   │               (prefix, cipher-hash) columns    │   intel_source
   │               -> MatchReport (verdict, score)  │
   └───────────────────┬───────────────────────────┘
                       │
   ┌───────────────────┴───────────────────────────┐
   │  detect.rs    records the observation, then    │   observation
   │               runs six rules over a time        │   alert
   │               window, raising Alerts            │
   │  signal.rs    the User-Agent / OS heuristics    │
   │               the correlation rules read        │
   └────────────────────────────────────────────────┘
```

**Schema (`schema.rs`).** Versioned migrations build five tables: `intel_source` (one row per feed, with its license), `intel_fingerprint` (the fingerprints, with `part_a`/`part_b` columns precomputed for JA4 fuzzy matching), `observation` (every fingerprint the sensor has seen, with its IP and time), and `alert` (every detection that fired). The observation and alert tables are what make the correlation rules possible: they give the sensor a memory.

**Seeding (`seed.rs`).** Three feeds are compiled into the binary as CSV and loaded with no network call: abuse.ch SSLBL (97 malware JA3s, CC0), the Salesforce `osx-nix` JA3 list (157 benign client JA3s, BSD-3), and a small curated C2 set (17 fingerprints). 271 in total. An optional `intel import` pulls ja4db.com and validates each record on the way in.

**Matching (`matcher.rs`).** An exact match is a single indexed lookup. A JA4 *fuzzy* match handles the reality that a client's full JA4 may not be in the feed but its capability-and-cipher prefix is: the value is split into its prefix and cipher-hash parts, and a hit on those alone is reported at a lower confidence. The hits are scored into a `MatchReport` with a threat score and a confidence, the two numbers the rest of the tool acts on.

**Detection (`detect.rs` + `signal.rs`).** For each event, the engine first records an observation, then runs six rules, all inside one transaction so the observation and any alerts it raises commit together:

| Rule | Fires when | Severity |
|------|-----------|----------|
| `known_bad` | the fingerprint matches a malicious feed entry | high / critical |
| `ua_mismatch` | a JA4 disagrees with the User-Agent seen from the same IP (**the headline**) | high |
| `os_mismatch` | a JA4T's OS disagrees with the OS the User-Agent claims | medium |
| `first_seen` | this fingerprint has never been observed before | info |
| `fp_rotation` | one IP has shown an unusual number of distinct fingerprints in the window | medium |
| `monoculture` | one fingerprint has appeared from an unusual number of IPs in the window | low |

The correlation rules (`ua_mismatch`, `os_mismatch`) are the ones that catch evasion, and they are why the store keeps a memory: to know that the IP now sending a forged-Chrome JA4 also sent, ten seconds ago, an HTTP request whose User-Agent it can compare against. `signal.rs` holds the heuristics they read, for example that a Windows TCP stack and a Linux one differ in their SYN options, so a JA4T can be checked against a `User-Agent` that claims Windows.

## The binary: CLI and dashboard

`tlsfp` is the only crate that touches the outside world.

- **`cli.rs`** is the clap command tree: `pcap`, `live`, `serve`, and the `intel` subcommands. It owns the streaming output, the JSON serialization, and the wiring of a source to the engine to the store.
- **`live.rs`** runs libpcap on a dedicated OS thread and bridges it to an async consumer, because libpcap's blocking read cannot be safely driven from inside the async runtime. It also drops privileges to the two capabilities capture needs.
- **`report.rs`** is the forensic `--report` builder. Instead of streaming one line per event, it accumulates an in-process picture of every endpoint, fingerprint, and miss, then prints one ranked summary, folding in intelligence and detection automatically whenever a database is present.
- **`serve.rs`** is the axum dashboard. It serves the built frontend assets and streams events and alerts to the browser over Server-Sent Events. The live feed has three sources: a replayed capture file (paced, optionally looping), a live interface, or, by default, a tail of the database so a separate `tlsfp live --detect` sensor surfaces in the browser.

```
   tlsfp live --detect ──writes──> intel.db <──tails── tlsfp serve ──SSE──> browser
                                   (WAL mode lets the reader and writer share the file)
```

This is the deployment shape the WAL mode and busy timeout exist for: a headless sensor writing alerts into the database on one process, and a dashboard reading them out on another, against the same file, without either blocking the other.

## The threat model

A passive sensor processes input chosen entirely by an adversary. Anyone on the monitored network can send it any bytes. The architecture treats every input as hostile and bounds every cost.

**What the tool defends against:**

- **Malformed packets.** Every parser in the engine returns a typed error on bad input and never reads out of bounds, because the engine forbids `unsafe`. A truncated length, an extension that claims more bytes than the record holds, a certificate that ends mid-field: all are errors, not crashes. The JA4X parser, which walks the most hostile format (X.509 DER), is fuzzed with a property test to prove it.
- **Memory exhaustion via the flow table.** An attacker who opens millions of flows, or sends segments with a gap that never fills, would grow an unbounded reassembler without limit. The flow table has a hard cap on tracked flows, an idle timeout that evicts the stale, and per-direction ceilings on both contiguous and parked-out-of-order bytes. The cost of an adversarial capture is fixed and survivable.
- **A QUIC decryption that releases unverified plaintext.** The QUIC path verifies the AEAD tag before trusting the decrypted CRYPTO frames, so a forged Initial fails the tag and is dropped rather than feeding garbage to the parser.

**What the tool explicitly does not do:**

- **It does not decrypt application data.** It reads only what is plaintext on the wire: the handshake, the cleartext HTTP head, the QUIC Initial. It never has a private key and never sees TLS-1.3 certificates or HTTP/2 headers, which are encrypted.
- **It does not attribute.** A fingerprint identifies a toolchain, not an actor. A `known_bad` hit means "this came from a known-suspicious toolchain," not "this is attacker X." The Emotet / Cobalt Strike JA3 collision is the standing reminder.
- **It does not actively probe.** It sends nothing. A target cannot detect the sensor by watching for scans, because there are none.

## Where to go next

- [03-IMPLEMENTATION.md](./03-IMPLEMENTATION.md) traces one frame all the way through this architecture, from `decode.rs` to a row in the `alert` table.
- [ALGORITHMS.md](./ALGORITHMS.md) opens up the fingerprint stage: the exact byte construction of each hash and the QUIC key schedule.
- [CONFORMANCE.md](./CONFORMANCE.md) records the published vector each stage is pinned to and every deliberate boundary.
