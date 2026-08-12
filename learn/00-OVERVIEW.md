<!-- ©AngelaMos | 2026 -->
<!-- 00-OVERVIEW.md -->

# JA3/JA4 TLS Fingerprinting: Overview

## What This Is

A passive TLS fingerprinting sensor written in Rust. You give it a packet capture or a live network interface, and it computes the JA3, JA4, JA4S, JA4H, JA4X, and JA4T fingerprints of every handshake it sees, looks each one up in a local threat-intelligence database, and raises alerts when something looks wrong. It never sends a packet, never decrypts application data, and never needs a private key. Everything it knows, it learns by watching the parts of a connection that are visible before encryption begins.

The point of the project is to understand, by building it, how network defenders identify *what software* is talking on their network when they cannot see *what it is saying*. You get a working sensor you can run against real captures, a threat database seeded from real public feeds, and a codebase small enough to read in a weekend.

## Why This Matters

Encryption hid the contents of network traffic, and the industry largely treats that as solved. What encryption did not hide is the *negotiation* of encryption. Before a TLS client and server agree on a key, they exchange a handshake in plaintext, and that handshake is shaped by the client's software in a way the client cannot easily disguise. A defender who cannot read the traffic can still recognize the talker.

This matters because attackers reuse tooling. A command-and-control framework, a credential stealer, a botnet implant: each is built on a specific TLS library, configured a specific way, and that configuration produces the same fingerprint on every victim. Block the fingerprint and you block the family, regardless of which IP or domain it hides behind this week.

The cost of *not* having this visibility is not hypothetical.

- **SolarWinds / SUNBURST, 2020.** A nation-state actor distributed a backdoor through a trusted software update, and the implant beaconed out over HTTPS that looked, at the network layer, like ordinary traffic. Defenders who only watched IPs and domains had nothing; the malicious infrastructure was new and clean. The traffic that *carried* the beacon, though, had a consistent TLS shape. Fingerprinting is one of the few passive signals that survives an attacker who controls their own certificates and rotates their own infrastructure.
- **Cobalt Strike, everywhere.** The single most common post-exploitation framework in real intrusions ships with default TLS profiles whose JA3 hashes are public knowledge. Its default fingerprint, `72a589da586844d7f0818ce684948eea`, is so well known that mature teams alert on it directly. The same hash also appears for some Emotet samples, because they share an underlying TLS library, which is itself a useful lesson: a fingerprint identifies a *toolchain*, not a *threat actor*.
- **The browser-impersonation arms race.** Tools like `curl-impersonate` and `utls` exist specifically to make a script's ClientHello identical to a real Chrome's, so that a fingerprint-based filter waves it through. This is why a single fingerprint is never enough, and why this tool computes several and cross-checks them against each other and against the User-Agent.

**Real world scenarios where this applies:**
- **Network security monitoring.** A sensor on a span port or a tap fingerprints every outbound TLS connection and flags the ones that match malware feeds or disagree with their own User-Agent.
- **Bot and fraud detection.** A web service fingerprints incoming TLS to tell a real browser from an automated client claiming to be one, without a CAPTCHA.
- **Threat hunting and forensics.** An analyst feeds a captured `.pcap` from an incident through the tool and gets a ranked inventory of every client that spoke on the wire, with verdicts.

## What You'll Learn

This project teaches how passive identification on an encrypted network actually works. By building it yourself, you will understand:

**Security concepts:**
- **What a TLS handshake reveals.** Why the ClientHello is a fingerprint at all: the cipher suites, extensions, and curves a client offers are a stable signature of the software that built it.
- **Why JA4 replaced JA3.** How a single design choice, sorting the lists before hashing, made JA4 survive the extension-order shuffling that made JA3 useless for modern browsers.
- **GREASE and deliberate noise.** Why clients inject random values into their own handshakes (RFC 8701), and why a fingerprint must strip them or it changes on every connection.
- **Evasion and cross-checking.** How a tool impersonates a browser's TLS, and how pairing the TLS fingerprint with the TCP-stack fingerprint and the User-Agent exposes the lie.
- **Passive QUIC.** Why a QUIC initial packet, which is "encrypted," can still be read by anyone, because its key is derived from a value sent in the clear.

**Technical skills:**
- **Parsing adversarial binary input safely.** Walking TLS records and X.509 DER in a language that forbids `unsafe`, so a malformed length is a typed error and never a buffer overrun.
- **TCP stream reassembly.** Rebuilding a byte stream from out-of-order, retransmitted, and overlapping segments, the way every real capture arrives.
- **Bounding untrusted work.** Putting hard caps on the flow table and per-stream buffers so an attacker cannot make the sensor exhaust memory.
- **Designing a workspace.** Splitting an engine that forbids I/O from a store that owns a database from a binary that wires them together, so the engine can be fuzzed and benchmarked in isolation.

**Tools and techniques:**
- **`libpcap`** for live capture, and the Linux capability model (`cap_net_raw`) that lets an unprivileged binary open a raw socket.
- **`tshark` / Wireshark** as an oracle: Wireshark computes JA3 and JA4 too, so you can confirm this tool agrees with it on a real capture.
- **SQLite** as an embedded, zero-configuration intelligence store, with WAL mode so a dashboard can read while a sensor writes.

## Prerequisites

You do not need prior fingerprinting experience. You do need some comfort with the following.

**Required knowledge:**
- **The TLS handshake at a high level.** That a client sends a ClientHello, a server replies with a ServerHello and a certificate, and a key is agreed. You do not need the cryptography; you need to know what messages exist and which travel in the clear.
- **TCP/IP basics.** What a segment is, what a SYN is, why packets arrive out of order. The reassembly layer is the heart of the capture path.
- **Basic Rust or a willingness to read it.** The code uses enums, pattern matching, iterators, and `Result`. If you know Go, C++, or Python with type hints, you can follow it.

**Tools you'll need:**
- **A Rust toolchain**, edition 2024 (rustc 1.85 or newer). The `install.sh` script checks for it.
- **`libpcap` development headers** for live capture (`libpcap-dev` on Debian or Ubuntu). File-only use does not need them.
- **A capture to feed it.** The repository vendors several under `testdata/pcap/`, or capture your own with `tcpdump -w out.pcap`.

**Helpful but not required:**
- **Wireshark**, to compare fingerprints against a second implementation.
- A reading of the [FoxIO JA4+ specification](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md) and the [original Salesforce JA3 post](https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967/). You can also read [`01-CONCEPTS.md`](./01-CONCEPTS.md) and pick up the specs when something is unclear.

## Quick Start

```bash
cd PROJECTS/intermediate/ja3-ja4-tls-fingerprinting

# Build the binary and seed the threat feeds
cargo build --release
./target/release/tlsfp intel seed

# Fingerprint a vendored capture, one line per handshake
./target/release/tlsfp pcap testdata/pcap/tls-handshake.pcapng

# Read the whole capture and print one ranked forensic summary
./target/release/tlsfp pcap testdata/pcap/tls-handshake.pcapng --report
```

Expected output: the plain `pcap` command prints one line per handshake, each with a JA4 and a JA3 and, for a ClientHello, the SNI and ALPN. You will see both `t`-transport fingerprints (TLS over TCP) and `q`-transport fingerprints (TLS inside QUIC) in the same capture, because the vendored file contains both. The `--report` command instead prints a single summary: the busiest endpoints, the most common fingerprints, any intelligence hits, and any alerts.

To watch a live interface, grant the binary the two capabilities it needs and point it at an interface:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip "$(command -v ./target/release/tlsfp)"
./target/release/tlsfp live eth0 --intel --detect
```

Stop it with ctrl-c: the first one drains the capture and prints trustworthy final counters, a second exits immediately.

## Project Structure

```
ja3-ja4-tls-fingerprinting/
├── crates/
│   ├── tlsfp-core/    # the engine: parses TLS, reassembles TCP, computes the fingerprints
│   ├── tlsfp-intel/   # the store: a bundled SQLite database, matching, and the detection rules
│   └── tlsfp/         # the binary: the CLI and the web dashboard
├── testdata/pcap/     # vendored captures used as integration fixtures
├── frontend/          # the dashboard (Vite + React 19)
└── install.sh         # the one-shot installer
```

The single most important file to understand first is `crates/tlsfp-core/src/ja4.rs`. Everything in the engine exists to feed it a parsed ClientHello; everything in the rest of the tool exists to act on what it returns.

## Next Steps

1. **Understand the ideas.** Read [01-CONCEPTS.md](./01-CONCEPTS.md) for the ClientHello, JA3 versus JA4, GREASE, evasion, and passive QUIC, each grounded in a real intrusion.
2. **See the design.** Read [02-ARCHITECTURE.md](./02-ARCHITECTURE.md) for the three-crate split, the capture pipeline, the intelligence store, and the threat model.
3. **Walk the code.** Read [03-IMPLEMENTATION.md](./03-IMPLEMENTATION.md) to trace a raw frame all the way to a scored alert.
4. **Learn the algorithms.** Read [ALGORITHMS.md](./ALGORITHMS.md) for how each fingerprint is built byte by byte and how a QUIC initial is decrypted.
5. **Check the contract.** Read [CONFORMANCE.md](./CONFORMANCE.md) for the published vector each fingerprint is pinned to and every deliberate scope boundary.
6. **Extend it.** Read [04-CHALLENGES.md](./04-CHALLENGES.md) for projects from "add a fingerprint" to "build a clustering model".

## Common Issues

**`tlsfp live` fails with a permission error**
```
Error: opening interface eth0: you don't have permission to capture
```
Solution: live capture opens a raw socket, which an unprivileged user cannot do. Grant the binary the capabilities once with `sudo setcap cap_net_raw,cap_net_admin=eip "$(command -v tlsfp)"`. File capabilities live on the binary, so repeat the grant after every rebuild.

**`intel lookup` says no database exists**
```
no intelligence database at ...; run 'tlsfp intel seed' first
```
Solution: the lookup, stats, and alerts commands read an existing database but never create one. Run `tlsfp intel seed` to build it from the three bundled feeds, which needs no network.

**A capture shows fewer handshakes than I expected**
Solution: a handshake split across many out-of-order segments, or one whose ClientHello arrives after the per-stream byte cap, may not fingerprint. Run with `-v` to see the counters, including `tls_miss_rate` and `segments_dropped`. On a live interface, kernel drops under load do the same; the tool warns when the kernel reports any.

**The fingerprint disagrees with Wireshark**
Solution: check that you are comparing the same handshake and the same fingerprint version. JA4 has a raw form and a hashed form; this tool prints the hashed form by default. The raw form is available in the JSON output (`--json`) for exactly this kind of debugging.

## Related Projects

If you found this interesting, look at:
- **hsm-emulator**: an advanced project that builds the *other* side of TLS, the key custody an HSM provides, with the same discipline of pinning every output to a published vector.
- **bug-bounty-platform**: a full application that handles the kind of traffic this sensor would watch, and shows where a fingerprinting signal would feed into a larger detection pipeline.
