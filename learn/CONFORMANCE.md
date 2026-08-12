<!-- ©AngelaMos | 2026 -->
<!-- CONFORMANCE.md -->

# JA3/JA4 TLS Fingerprinting: Conformance

A fingerprint is only useful if it agrees with everyone else's. A JA4 this tool computes must equal the JA4 FoxIO's reference implementation computes for the same handshake, or a hash on a shared feed means nothing. This document states exactly what each fingerprint conforms to, the published vector it is pinned to in the test suite, and every place the tool deliberately narrows its scope. Where it says "pinned," there is a known-answer test that fails if the output drifts.

## Reference specifications

| Fingerprint | Authority | Document |
|-------------|-----------|----------|
| JA3 / JA3S | Salesforce (2017) | the original [TLS Fingerprinting with JA3 and JA3S](https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967/) |
| JA4 / JA4S | FoxIO (2023) | [JA4](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md), [JA4S](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4S.md) |
| JA4H | FoxIO | [JA4H](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4H.md) |
| JA4X | FoxIO | [JA4X](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4X.md) |
| JA4T / JA4TS | FoxIO | [JA4T](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4T.md) |
| GREASE handling | IETF | [RFC 8701](https://www.rfc-editor.org/rfc/rfc8701.html) |
| QUIC v1 keys | IETF | [RFC 9001](https://www.rfc-editor.org/rfc/rfc9001.html) Section 5.2, Appendix A |
| QUIC v2 keys | IETF | [RFC 9369](https://www.rfc-editor.org/rfc/rfc9369.html) Section 3.3.1, Appendix A |

The FoxIO JA4+ specifications carry their own license (FoxIO License 1.1), which governs the *specification*, not this independent implementation of it. This tool ships under AGPL 3.0.

## Per-fingerprint conformance

### JA3 / JA3S

- **Conforms to** the original Salesforce field order and the MD5 of the comma-joined decimal fields.
- **Pinned to** the two client vectors from the Salesforce post and a server vector, in `ja3.rs` (`salesforce_client_vector_one` produces `ada70206e40642a3e4461f35503241d5`; `salesforce_client_vector_two_empty_fields` covers the empty-field case; `server_vector_round_trips_through_md5` covers JA3S).
- **Scope.** Computed from the ClientHello and ServerHello. GREASE is stripped per RFC 8701. JA3 is retained despite being unstable on modern browsers because the public malware feeds are expressed in it; see [01-CONCEPTS.md](./01-CONCEPTS.md).

### JA4 / JA4S

- **Conforms to** the FoxIO JA4 construction: a 10-character readable prefix, a truncated-SHA-256 of the sorted cipher list, and a truncated-SHA-256 of the sorted extension list with SNI and ALPN removed and the signature algorithms appended in original order.
- **Pinned to** the FoxIO section vectors in `ja4.rs`: the cipher section `8daaf6152771` and the extension section `e5627efa2ab1`, which together with the prefix form the canonical `t13d1516h2_8daaf6152771_e5627efa2ab1`. An all-empty ClientHello produces the zero hash `000000000000` (`empty_input_is_the_zero_hash`), and the truncation is asserted to be exactly 12 hex characters (`truncation_is_twelve_hex_chars`).
- **Scope.** Both the hashed and the raw form are produced; the CLI prints the hashed form and exposes the raw form under `--json`. The version word is taken from `supported_versions`, not the frozen legacy field. JA4S hashes server extensions in wire order, not sorted.

### JA4H

- **Conforms to** the FoxIO JA4H construction over a single cleartext HTTP request.
- **Pinned to** the request-line and header parse in `ja4h.rs` (`parses_request_line_and_headers`, `version_codes`).
- **Scope.** Cleartext HTTP/1.x only. HTTPS requests are encrypted and HTTP/2 headers are HPACK-compressed, so neither is fingerprinted passively. This is a property of passive observation, not a limitation of the implementation.

### JA4X

- **Conforms to** the FoxIO JA4X construction: three truncated-SHA-256 hashes over the issuer OIDs, the subject OIDs, and the extension OIDs, each in DER order.
- **Pinned to** the OID-extraction tests in `ja4x.rs` (`extracts_issuer_oids_in_order`, `extracts_extension_oids`) and hardened by the property-test fuzz harness in `tests/ja4x.rs`.
- **Scope.** Passive JA4X works on **TLS 1.2 and earlier**, where the Certificate message is in the clear; TLS 1.3 encrypts it. The DER reader (`der.rs`) is bounded: a certificate that ends mid-field returns an error or an empty section, never a panic (`certificate_ending_after_subject_is_handled_without_panic`). An out-of-bounds slice on a crafted certificate is a security bug, not a cosmetic one, which is why this path is fuzzed.

### JA4T / JA4TS

- **Conforms to** the FoxIO JA4T format: window size, option kinds, MSS, and window scale, joined with underscores.
- **Pinned to** the FoxIO vectors in `ja4t.rs` (`foxio_windows_default_vector` produces `64240_2-1-3-1-1-4_1460_8`; `foxio_windowed_vector`; `missing_mss_and_scale_report_zero`) and to the decoder that walks SYN options in `pipeline/decode.rs` (`ja4t_walk_reproduces_the_windows_default_vector`, `ja4t_walk_counts_trailing_end_of_list_padding`, `ja4t_walk_survives_truncated_options`).
- **Scope.** Read from a SYN (JA4T) or SYN-ACK (JA4TS). A missing MSS or window scale option is reported as `0`, per the spec. The option walker tolerates truncated and padded option lists.

## QUIC conformance

- **Conforms to** RFC 9001 (QUIC v1) and RFC 9369 (QUIC v2) for client Initial key derivation and packet protection removal.
- **Pinned to** the RFC Appendix A key vectors in `quic.rs`: `client_initial_keys_match_rfc9001_appendix_a1` and `client_initial_keys_match_rfc9369_appendix_a` derive the key, IV, and header-protection key from the appendix connection ID and assert them byte-for-byte. The integration capture `quic-with-several-tls-frames.pcapng` yields the stable `q13d0310h3_55b375c5d22e_cd85d2d88918`.
- **Scope and a deliberate boundary.** The tool decrypts **client Initial** packets only, deriving keys from each packet's own Destination Connection ID with no server secret and no direction detection. It does not track connection migration, does not decrypt 0-RTT or Handshake packets, and does not reassemble across a connection ID change. A version field other than v1 or v2 increments `quic_version_unsupported` and is skipped rather than guessed. The full v2 *protected-packet* decrypt is not pinned to a published full-packet vector (the only available transcription was byte-corrupted in transit); the v2 **key schedule** is pinned to RFC 9369 Appendix A, and the decrypt path is the same AEAD the v1 full-packet test exercises.

## Parsing and robustness boundaries

The engine forbids `unsafe`, so the following are guarantees, not aspirations:

- **A malformed length is an error, never an out-of-bounds read.** Every parser reads through the bounds-checked `Reader`; a field that claims more bytes than remain returns `ParseError`. The `parse` and `reassembly` test suites feed truncated and overlapping input and assert clean errors.
- **An adversarial capture costs bounded memory.** The flow table caps the number of tracked flows, evicts on an idle timeout, and ceilings both contiguous and parked-out-of-order bytes per direction. A stream that hits a cap is marked `capped` and stops growing. The counters expose `segments_dropped` and `unfinished_tls_streams`.
- **A QUIC packet that fails its AEAD tag is dropped.** Unverified plaintext is never released to the TLS parser.

## Deliberate non-goals

These are choices, recorded so they are not mistaken for gaps:

- **No application-data decryption.** The tool reads only what is plaintext on the wire. It has no private key and never sees TLS 1.3 certificates or HTTP/2 headers.
- **No active probing.** The tool sends nothing. It cannot be detected by watching for scans.
- **No attribution.** A fingerprint identifies a toolchain, not an actor. The shared `72a589da586844d7f0818ce684948eea` JA3 across some Emotet and Cobalt Strike samples is the standing example: same TLS library, different malware. A `known_bad` verdict means "known-suspicious toolchain," nothing more.
- **No DTLS fingerprinting yet.** The transport marker `d` exists in the JA4 code, but DTLS handshake capture is not wired into the pipeline. This is the most natural extension; see [04-CHALLENGES.md](./04-CHALLENGES.md).

## How to re-verify

```bash
cargo test --workspace        # every pinned vector above runs here
cargo test -p tlsfp-core quic  # just the QUIC key-schedule vectors
```

Against a second implementation, capture a handshake and compare:

```bash
tlsfp pcap capture.pcapng --json | jq '.ja4.hash, .ja4.raw'
tshark -r capture.pcapng -T fields -e tls.handshake.ja4   # Wireshark's JA4
```

If the two disagree on a real capture, that is a bug worth a report, and the raw form in the JSON is where to start reading.
