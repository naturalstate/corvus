<!-- ©AngelaMos | 2026 -->
<!-- 04-CHALLENGES.md -->

# JA3/JA4 TLS Fingerprinting: Challenges

The fastest way to understand this codebase is to change it. These challenges are ordered roughly by difficulty, each names the files it touches, and each ends with how you would prove it works the way the rest of the project proves things: a known-answer test, an integration capture, or a real run of the binary. Read [03-IMPLEMENTATION.md](./03-IMPLEMENTATION.md) and [ALGORITHMS.md](./ALGORITHMS.md) first.

## Beginner

These build familiarity with the pipeline without touching the cryptography.

### 1. Add a fingerprint kind to `intel lookup`

The CLI's `intel lookup` accepts a fixed set of fingerprint kinds. Trace `FpKind::from_token` in `model.rs` and the error message in `cli.rs`, and make sure every kind the engine emits is accepted (and that the help text lists them).

*Prove it:* run `tlsfp intel lookup ja4t 64240_2-1-3-1-1-4_1460_8` and get a verdict instead of an "unknown kind" error.

### 2. A new readable output column

The streaming output prints the JA4 and JA3 per line. Add the SNI's registered domain (the eTLD+1) as a column, or a one-character flag when the fingerprint had an intelligence hit. The formatting lives in `write_event` in `cli.rs`.

*Prove it:* run `tlsfp pcap testdata/pcap/tls-handshake.pcapng` and read the new column.

### 3. Seed a fourth feed

`seed.rs` compiles three CSV feeds into the binary. Add a fourth (find a public JA4 or JA3 feed, record its license in `NOTICE.md` and the `intel_source` table). Follow the existing `load_*` functions and the `NewFingerprint` shape.

*Prove it:* `tlsfp intel seed` then `tlsfp intel stats` shows the new feed and its row count.

## Intermediate

These require understanding a parser or the detection engine.

### 4. A new detection rule

`detect.rs` runs six rules over a time window, reading the `observation` table for memory. Add a seventh. A good candidate: **`port_anomaly`**, a TLS handshake whose JA4 says HTTP/2 (`h2` ALPN) arriving on a port that is not 443 or 8443, which is a common C2 trait. The rule reads the event's destination port and the ALPN already in the prefix; it needs no new table.

*Prove it:* add a unit test in `tests/detect.rs` that feeds a crafted `FingerprintEvent` and asserts the alert, the way the existing rule tests do.

### 5. Decode DTLS handshakes

The JA4 code already has a `d` transport marker and a DTLS version word, but the pipeline never feeds it a DTLS handshake. DTLS rides UDP and frames its handshake differently from TLS (it adds message sequence numbers and fragment offsets). Wire a DTLS path in `pipeline/decode.rs` and a DTLS record reader alongside the TLS one in `parse/record.rs`, then route to the existing `ja4` with `Transport::Dtls`.

*Prove it:* capture a WebRTC or OpenVPN-DTLS handshake, add it to `testdata/pcap/`, and add an integration test asserting a `d`-transport JA4.

### 6. Tune and measure the bounds

The reassembler's `ReassemblyLimits` and the pipeline's `PipelineConfig` set the memory ceilings. Build a deliberately adversarial capture (thousands of flows, segments with permanent gaps) with a small script, and watch the counters (`-v`) show `segments_dropped` and flow eviction. Then find the smallest bounds that still fingerprint the vendored captures cleanly.

*Prove it:* a `cargo bench` run before and after, plus the counters from `-v` on your adversarial capture, showing bounded memory.

## Advanced

These reach into the cryptography or the architecture.

### 7. Pin a full QUIC v2 protected-packet vector

[CONFORMANCE.md](./CONFORMANCE.md) notes that the v2 *key schedule* is pinned to RFC 9369 Appendix A but the full v2 *protected packet* is not, because the only transcription available was byte-corrupted. Obtain the v2 protected packet bytes from a byte-exact source (a raw capture or a trusted hex dump, not a copy-paste through a summarizer), add it to the `quic.rs` tests, and assert the decrypted ClientHello.

*Prove it:* a new KAT in `quic.rs` that decrypts the v2 packet and matches the expected ClientHello, alongside the existing v1 full-packet test.

### 8. Active fingerprint scanning (a separate tool)

This sensor is strictly passive. Build a *separate* binary (a new crate, so the passive guarantee in `tlsfp-core` is never violated) that actively connects to a host, completes a handshake, and fingerprints the *server's* JA4S, the way `tlsd`-style scanners do. This is a different threat model (you are now sending packets and are detectable), so it must be a clearly separate tool.

*Prove it:* fingerprint a known server (for example a Cloudflare host) and confirm its JA4S is stable across runs.

### 9. A clustering view of the catalogue

The dashboard shows individual fingerprints. Add a view that **clusters** them: group JA4s by shared prefix (same TLS version, cipher count, extension count, ALPN), so an analyst sees "these forty fingerprints are all variations of one TLS stack." The data is already in the `part_a` column the JA4 fuzzy matcher uses.

*Prove it:* a dashboard view, plus a `matcher.rs` query that returns prefix groups with their member counts.

## Expert

These are research-grade and open-ended.

### 10. Detect impersonation by cross-layer disagreement, statistically

The `ua_mismatch` and `os_mismatch` rules are heuristic and binary. Replace them with a model: for each `(JA4, JA4T, User-Agent)` triple seen on the network, learn the *normal* joint distribution, then score new triples by how surprising they are. A real Chrome on Windows is common; a forged-Chrome JA4 with a Linux JA4T is rare and should score high. This is the principled version of the evasion detection in [01-CONCEPTS.md](./01-CONCEPTS.md).

*Prove it:* feed a capture containing `curl-impersonate` traffic (generate it yourself) and show the model flags it while leaving real browsers alone.

### 11. Survive an adversary who fingerprints your sensor

A sophisticated attacker on the monitored network may try to *detect* or *evade* the sensor by crafting traffic that exploits the bounds: flows tuned to ride just under the eviction timeout, ClientHellos fragmented to defeat reassembly, GREASE in unexpected positions. Threat-model the sensor itself, build the adversarial captures, and harden the pipeline against each. This is the passive-sensor analogue of evading an IDS.

*Prove it:* a documented set of adversarial captures in `testdata/`, each with a test asserting the sensor either fingerprints correctly or fails safe (bounded, no crash, no missed handshake that fit within the bounds).

### 12. Encrypted Client Hello (ECH)

The whole project rests on the ClientHello being plaintext. **ECH** (Encrypted Client Hello) is the IETF effort to change that, encrypting the sensitive parts of the ClientHello under a key published in DNS. Study the ECH draft, determine exactly what a passive observer can and cannot still see (the outer ClientHello is still visible, and it is itself fingerprintable), and write up how JA4 degrades under ECH adoption and what signal survives.

*Prove it:* a written analysis grounded in the ECH specification, plus a capture of an ECH handshake showing what the tool can still fingerprint from the outer hello.

## A note on contributing back

If you build something here that is genuinely useful, the JA4+ ecosystem is young and the public feeds are thin. A well-licensed feed, a clustering view, or a rigorous ECH analysis would be welcome upstream at [FoxIO-LLC/ja4](https://github.com/FoxIO-LLC/ja4) and in the broader community. The point of the project is to learn how this works; the bonus is that the field still has open problems an afternoon of work can move.
