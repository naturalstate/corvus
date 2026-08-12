<!-- ©AngelaMos | 2026 -->
<!-- 03-IMPLEMENTATION.md -->

# JA3/JA4 TLS Fingerprinting: Implementation

This document walks the code. It follows one packet from the moment it is read off disk to the moment a row lands in the `alert` table, then pulls out the three patterns that make the engine safe on a hostile network. It names files and functions, never line numbers, so it stays correct as the code moves. Read [02-ARCHITECTURE.md](./02-ARCHITECTURE.md) first for the map.

## A frame's journey, end to end

Run `tlsfp pcap traffic.pcapng --detect`. Here is what happens to one frame carrying a ClientHello.

### 1. The source yields a frame

`PcapFileSource::open` (in `pipeline/source.rs`) opens the capture and `next_frame` hands back a `RawFrame`: a timestamp in nanoseconds, the link type, and a borrowed byte slice. The slice borrows the source's own read buffer, so no copy happens here. The binary's `Pipeline::run` loop pulls frames and feeds each to `Pipeline::feed`.

### 2. Decode strips the lower layers

`decode_frame` (in `pipeline/decode.rs`) uses `etherparse` to peel off the Ethernet and IP headers. It returns a `Decoded` value: a `DecodedSegment` for TCP (with the four-tuple, the sequence number, the flags, and the payload), a `DecodedDatagram` for UDP, or a `Skip` if the frame is not something we fingerprint. If the segment is a bare SYN, this is also where the TCP options are walked for JA4T, because JA4T reads the SYN itself, not the stream.

### 3. The flow table reassembles the stream

The segment's four-tuple becomes a `FlowKey`, and `FlowKey::from_pair` also returns a `Direction` so the two halves of the conversation stay separate. The pipeline looks up (or creates) the `StreamReassembler` for that direction and calls `push(seq, payload)`.

`StreamReassembler::push` (in `pipeline/flow.rs`) is the careful part. It places the payload at its sequence offset, merges it with the contiguous run if it fills the gap, parks it if it arrives early, and resolves any overlap with bytes already held. It returns a `PushOutcome` telling the caller whether new contiguous bytes became available. The contiguous bytes are reachable through `data()`. This is what makes a ClientHello split across reordered segments parse: the parser only ever sees the clean, in-order stream.

### 4. The protocol layer recognizes a handshake

With fresh contiguous bytes available, `StreamProtocol` (in `pipeline/tls.rs`) inspects the head of the stream. It reads the TLS record header, and when a complete handshake message is present it dispatches: a ClientHello to `parse_client_hello`, a ServerHello to `parse_server_hello`, a Certificate to the certificate reader. For a cleartext stream that looks like HTTP instead, it parses the request head for JA4H.

### 5. The parser reads the ClientHello without copying

`parse_client_hello` (in `parse/hello.rs`) walks the message with a `Reader` (in `parse/reader.rs`), a cursor that does bounds-checked reads over the borrowed bytes. Every field, the legacy version, the cipher suites, the extensions, is returned as a slice or a small vector that borrows the original buffer (`ClientHello<'pkt>` carries the lifetime). A length that overruns the buffer returns `Err(ParseError)`; the parser never reads past the end. Convenience accessors like `server_name`, `alpn_protocol`, and `supported_groups` decode individual extensions on demand.

### 6. The fingerprint is computed

The parsed `ClientHello` goes to `ja3` (in `ja3.rs`) and `ja4` (in `ja4.rs`). Each strips GREASE, assembles its string, and hashes it, JA3 with MD5, JA4 with truncated SHA-256. [ALGORITHMS.md](./ALGORITHMS.md) gives the exact construction. The results, plus the SNI, ALPN, and any User-Agent, become a `StreamEvent::ClientHello`, which `event.rs` wraps with the addresses and timestamp into a `FingerprintEvent`. That is the value that leaves the engine.

### 7. The store judges and detects

Back in the binary, the `FingerprintEvent` goes to `tlsfp-intel`. `IntelStore::match_event` runs the matcher (`matcher.rs`) over every fingerprint the event carries and returns a `MatchReport` for each that hit. `IntelStore::detect` opens a transaction and calls `detect::run` (in `detect.rs`), which:

1. records the event as a row in `observation`,
2. runs the six rules, correlating the new fingerprint against what this IP and this fingerprint have done inside the time window,
3. persists any `Alert` it raises into the `alert` table,
4. commits, so the observation and its alerts land atomically.

### 8. The writer prints

The binary serializes the event and any reports and alerts, as a readable line or as JSON, and writes it to stdout. For `--report` it instead feeds the event to the `ReportBuilder`, which accumulates and prints one summary at the end. The frame is done.

```
RawFrame ─decode─> DecodedSegment ─push─> contiguous bytes ─parse─> ClientHello
   │                                                                     │
   │                                                              ja3()/ja4()
   │                                                                     ▼
   └──────────────────────────────────────────────────────> FingerprintEvent
                                                                         │
                                          match_event + detect (one txn) │
                                                                         ▼
                                                       MatchReport + Alert ─> stdout
```

## Pattern one: zero-copy, bounds-checked parsing

The engine parses hostile binary input, so the parsing strategy is the security strategy. Two choices carry the weight.

**Everything borrows.** `parse_client_hello` returns a `ClientHello<'pkt>` that holds slices into the original packet buffer. No field is copied out during parsing. This keeps the hot path allocation-free (the benchmarks in `benches/fingerprint.rs` show why that matters) and means a ClientHello with a hundred extensions costs no more memory than the packet it came in.

**Every read is bounds-checked, and overruns are errors, not panics.** The `Reader` is the only thing that advances through the bytes, and each of its reads checks the remaining length first. A truncated length field, an extension that claims more bytes than the record holds, a certificate that ends mid-OID: every one returns `Err(ParseError)`. The `parse/` tests feed exactly these malformed inputs and assert errors. Because the whole crate sets `unsafe_code = "forbid"` in `Cargo.toml`, there is no escape hatch by which a parser bug could become an out-of-bounds read. This is the structural answer to the Heartbleed class of bug discussed in [01-CONCEPTS.md](./01-CONCEPTS.md): in C the bug is a memory disclosure, here it is a `Result::Err`.

## Pattern two: bounded reassembly

`StreamReassembler` is where an adversary's input could grow without limit, so every dimension is capped by `ReassemblyLimits`:

- a ceiling on **contiguous bytes** kept per direction, so a single huge stream cannot grow forever,
- a ceiling on **parked out-of-order bytes**, so an attacker who sends segment 2 but never segment 1 cannot make the reassembler hold the gap open indefinitely,
- a cap on **parked segments**, so many tiny out-of-order segments cannot blow up the bookkeeping.

When a stream hits a cap it is marked `capped()` and stops accepting more, rather than growing. At the pipeline level a flow cap and an idle timeout bound the *number* of flows, evicting the oldest and stalest when the table is full. The counters (`Counters`, reported with `-v`) expose `segments_dropped` and `unfinished_tls_streams` so an operator can see when bounds bit. The design principle: an adversarial capture must cost a *fixed, known* amount of memory, never an unbounded one. [02-ARCHITECTURE.md](./02-ARCHITECTURE.md) frames this as the threat model; this is where it is enforced.

## Pattern three: passive QUIC decryption

`quic.rs` is the most cryptographically involved part of the engine, and the comments in it are worth reading in full. The flow:

1. **Locate the Initial.** `InitialPacket::parse` finds an Initial packet inside a UDP datagram and reads the cleartext header fields: the version, the Destination Connection ID, the token. A connection ID longer than twenty bytes marks the packet as not the version we handle, and is rejected rather than misparsed.
2. **Derive the keys.** `InitialPacket::client_keys` calls `InitialKeys::client(dcid, version)`. The derivation is straight from RFC 9001 (v1) and RFC 9369 (v2): `HKDF-Extract` the connection ID under the version's `INITIAL_SALT`, `HKDF-Expand-Label` to the `"client in"` secret, then expand that to the AEAD key, the IV, and the header-protection key. The salt is the only thing that differs between v1 and v2, and it is exactly what makes keys derived under the wrong version fail the tag.
3. **Open the packet.** `InitialPacket::open` removes header protection, then runs the AEAD open. The tag check here is load-bearing: a passive observer cannot tell a client Initial from a server one by any cleartext field, so the fact that *only a packet the client actually protected under these keys will verify* is what identifies the direction. A forged or server packet fails the tag and is dropped, never released to the parser.
4. **Reassemble the CRYPTO frames.** `walk_crypto_frames` iterates the decrypted frames, and a `CryptoAssembler` stitches them, by offset, into the TLS ClientHello (a QUIC ClientHello can span several Initial packets). `client_hello()` yields the assembled bytes.
5. **Fingerprint.** The assembled ClientHello goes through the same `ja4()` as the TCP path, with `Transport::Quic`, producing a `q`-prefixed fingerprint.

The key-derivation code is pinned to the RFC test vectors: `client_initial_keys_match_rfc9001_appendix_a1` and `client_initial_keys_match_rfc9369_appendix_a` derive the keys and assert them byte-for-byte against the published Appendix A values. [CONFORMANCE.md](./CONFORMANCE.md) records the boundaries of the QUIC support.

## How to read the codebase yourself

A productive order, given the journey above:

1. `parse/reader.rs`, then `parse/hello.rs`. The `Reader` is the whole safety story in one small file; `hello.rs` is the most important parse.
2. `ja4.rs`, then `ja3.rs`. The headline fingerprint, then the legacy one it replaced. Read them side by side to see the sort.
3. `pipeline/flow.rs`. The reassembler. The bounds are the interesting part.
4. `pipeline/mod.rs`. The loop that ties the stages together, where `PipelineConfig` sets the bounds.
5. `quic.rs`. Save it for last; it is self-contained and the comments carry it.

Then cross to `tlsfp-intel`: `matcher.rs` for scoring, `detect.rs` for the rules. Finally `tlsfp/src/cli.rs` to see it all wired.

## Where to go next

- [ALGORITHMS.md](./ALGORITHMS.md) opens up step 6 (and the QUIC key schedule of pattern three) in byte-level detail.
- [CONFORMANCE.md](./CONFORMANCE.md) records what every stage accepts, rejects, and is pinned to.
- [04-CHALLENGES.md](./04-CHALLENGES.md) suggests changes that will force you to understand these patterns by modifying them.
