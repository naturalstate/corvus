```
 ▄▄·       ▄▄▄   ▌ ▐·▄• ▄▌.▄▄ ·
▐█ ▌▪▪     ▀▄ █·▪█·█▌█▪██▌▐█ ▀.
██ ▄▄ ▄█▀▄ ▐▀▀▄ ▐█▐█•█▌▐█▌▄▀▀▀█▄
▐███▌▐█▌.▐▌▐█•█▌ ███ ▐█▄█▌▐█▄▪▐█
·▀▀▀  ▀█▄▀▪.▀  ▀. ▀   ▀▀▀  ▀▀▀▀
```

[![Rust](https://img.shields.io/badge/Rust-edition%202024-CE412B?style=flat&logo=rust&logoColor=white)](https://www.rust-lang.org)
[![JA4+](https://img.shields.io/badge/JA4%2B-JA3%20%C2%B7%20JA4%20%C2%B7%20JA4H%20%C2%B7%20JA4X%20%C2%B7%20JA4T-4B7BEC?style=flat)](https://github.com/FoxIO-LLC/ja4)
[![License: AGPLv3](https://img.shields.io/badge/License-AGPL_v3-purple.svg)](https://www.gnu.org/licenses/agpl-3.0)

---

> **Corvus** is a passive TLS fingerprinting sensor in Rust that identifies client software from the handshake alone — no decryption, no packets sent. It computes JA3, JA4, JA4S, JA4H, JA4X, and JA4T for every handshake it sees, reads the TLS hidden inside QUIC Initial packets, matches against a bundled intelligence database, and flags what a fingerprint cannot hide: a TLS stack that disagrees with its own User-Agent, a client rotating identities to dodge a blocklist, a fingerprint never seen before.
>
> Where the sensor only listens, Corvus is growing a transmitter. A **mirror server** that terminates real connections and reports what the client looks like. A **ClientHello forger** that impersonates a browser to attack the detector — and gets caught anyway, because a spoofed TLS stack still has the wrong TCP accent. **JARM** active server fingerprinting. An **interception mode** proving that TLS inspection is itself fingerprintable. Plus HTTP/2 fingerprinting, `SSLKEYLOGFILE` decryption, and field-level decode of how each fingerprint is assembled.
>
> Observe, reproduce, then break your own detector.

## How it works

A ClientHello is sent in the clear, before encryption is negotiated. It enumerates the client's TLS versions, cipher suites, extensions, and elliptic curves, and every TLS stack assembles that list differently. Hash the list and you get a stable identifier for the *software* — one that survives a change of IP, domain, and certificate.

JA3 (Salesforce, 2017) hashes the fields in wire order. Chrome now shuffles its extension order on every connection, so JA3 emits a fresh hash per connection for browser traffic and is effectively dead there. JA4 (FoxIO, 2023) sorts before hashing and is unaffected. Corvus computes both: JA3 because public threat feeds still index on it, JA4 because it still works.

The engine forbids `unsafe`, so a malformed packet is a parse error and nothing worse. The capture path is bounded by a flow cap, an idle timeout, and per-stream byte ceilings, so a hostile capture cannot turn the flow table into a memory bomb.

## What works today

**Fingerprints**
- **JA3 / JA3S** — MD5 over the ClientHello / ServerHello field list. Retained because public malware feeds still speak it
- **JA4 / JA4S** — the FoxIO client and server fingerprint, sorted cipher and extension lists, stable under extension shuffling
- **JA4H** — HTTP client fingerprint from a cleartext request's method, version, header order, cookies, and accept-language
- **JA4X** — X.509 fingerprint from certificate issuer, subject, and extension OIDs, clustering certificates minted by one toolchain
- **JA4T / JA4TS** — TCP-stack fingerprint from the SYN's window size, options, MSS, and window scale. Catches a tool wearing a browser's TLS clothing while its OS speaks with a different accent
- GREASE stripped from every list, so a modern client's deliberate noise never moves its fingerprint

**Capture**
- `pcap` and `pcapng` files, plus live capture from an interface via `libpcap`, with raw-socket capabilities dropped to exactly the two the kernel needs
- Per-direction TCP reassembly that survives reordering, retransmission, and overlap, so a ClientHello split across segments still fingerprints
- Bounded by construction: flow cap, idle timeout, per-stream byte ceilings

**QUIC**
- Decrypts QUIC Initial packets to reach the ClientHello inside, deriving the client initial keys from the packet's own Destination Connection ID per RFC 9001 (v1) and RFC 9369 (v2). No server-side secret required
- Reassembles CRYPTO frames across packets, so a QUIC ClientHello spread over several Initials still yields a `q`-transport JA4

**Intelligence**
- Bundled SQLite store seeded from three vendored feeds with no network call: abuse.ch SSLBL, the Salesforce `osx-nix` JA3 list, and a curated C2 set — **271 fingerprints**
- Optional install-time pull of ja4db.com, validated record by record on import
- Exact lookup plus JA4 fuzzy matching on the capability-and-cipher prefix, scored into a verdict with a threat score and confidence

**Detection**
- Six rules evaluated as a capture streams: `known_bad`, `ua_mismatch` (a JA4 that disagrees with its own User-Agent), `os_mismatch` (a JA4T that disagrees with the OS the User-Agent claims), `first_seen`, `fp_rotation`, `monoculture`
- `--report` mode reads a whole capture and prints one ranked summary, folding in intelligence and detection automatically when the database is present
- Web dashboard streaming events and alerts over Server-Sent Events, fed by a replayed capture, a live interface, or an external sensor tailing the same database

Published conformance vectors and scope boundaries: [`learn/CONFORMANCE.md`](learn/CONFORMANCE.md).

## Quick start

```bash
./install.sh
```

Builds the release binary, puts `corvus` on your PATH, and seeds the intelligence database. Pass `--live` to also grant the raw-socket capabilities live capture needs.

```bash
# Fingerprint every handshake in a capture, one line each
corvus pcap testdata/pcap/tls-handshake.pcapng

# Match against intel and run the detection rules
corvus intel seed
corvus pcap testdata/pcap/tls-handshake.pcapng --report

# Watch an interface in real time
sudo setcap cap_net_raw,cap_net_admin=eip "$(command -v corvus)"
corvus live eth0 --intel --detect

# Dashboard, fed by a replayed capture
corvus serve --replay testdata/pcap/tls-handshake.pcapng --loop 127.0.0.1:8080
```

One fingerprint line, a Chrome handshake to a Google host:

```
1675707151.805 192.168.1.168:50112 -> 142.251.16.94:443 client_hello ja4=t13d1516h2_8daaf6152771_e5627efa2ab1 ja3=1c258ebef8eee2dfa3df6d8d07285af9 sni=clientservices.googleapis.com alpn=h2
```

> [!TIP]
> [`just`](https://github.com/casey/just) is the command runner. Type `just` to list every recipe. `just bench` runs the throughput benchmarks; `just dev-up` brings up the dockerized dashboard with hot reload.

## Roadmap

Everything below is **planned, not built**. A sensor is half a loop — observe a fingerprint, reproduce it, then attack your own detector and see what still catches you.

### Active mode

| | What | Why |
|---|---|---|
| **`probe`** | TLS listener that terminates real connections and reports the client's own fingerprint, reading the ClientHello via `rustls::server::Acceptor` before completing the handshake | Runs `ua_mismatch` against a live visitor instead of a capture |
| **`forge`** | Emit an arbitrary ClientHello from a JA4 string or a named profile (`--as chrome-131`). No full TLS client needed — one message is enough to be fingerprinted | Spoof the TLS layer, then watch `os_mismatch` catch it because the TCP stack still reads Linux. The argument for layered fingerprinting, demonstrated |
| **`jarm`** | Active server fingerprinting — ten deliberately malformed ClientHellos, hashed by how the server responds | Completes the matrix: passive/active × client/server. How C2 infrastructure gets located on Shodan. Ships as a separate crate so the passive guarantee in `corvus-core` is never violated |
| **`intercept`** | Transparent MITM proxy with its own CA | Not for the decryption — for the finding that a TLS inspection appliance *changes the client fingerprint*, making corporate interception, and an attacker doing the same, passively detectable |
| **`--keylog`** | Decrypt TLS 1.2/1.3 application data from an `SSLKEYLOGFILE` | Correlate a ClientHello with the decrypted HTTP/2 inside the same flow. The QUIC crypto plumbing already exists |

### Analysis and output

- **Field-level ClientHello decode** — raw hex with every field annotated; hover a byte to highlight which character of the JA4 string it produced, and step the cipher list through sort and hash
- **JA3/JA4 stability comparison** — replay repeated connections from one client side by side: JA3 emits a new hash each time, JA4 holds
- **Fingerprint diff** — field-by-field. Chrome against Edge, Chrome against curl, Chrome against a forged Chrome

### Deeper

- **HTTP/2 fingerprinting (Akamai)** — `SETTINGS` values and order, window update, pseudo-header order, priority tree. What Cloudflare and Akamai run alongside JA3/JA4, and thin on the ground in open source. Also the counter to `forge`: spoofing a ClientHello is easy, spoofing all of Chrome's HTTP/2 behavior is not
- **ECH detection** — Encrypted Client Hello encrypts the ClientHello itself. Detect it, report it, and document what survives: JA4T, HTTP/2, traffic shape
- **HASSH** — the same technique for SSH

> [!IMPORTANT]
> `forge` and `intercept` are dual-use. They default to loopback and lab targets, require an explicit
> flag for anything else, and exist to test this project's own detector.

## Architecture

Three crates in a strict dependency line. The engine knows nothing about databases or networks; the intelligence store knows nothing about capture; the binary wires them together.

```
   pcap / pcapng file        live interface (libpcap)       QUIC initial
            │                         │                          │
            └─────────────┬───────────┴──────────────────────────┘
                          │  raw link-layer frames
                          ▼
   ┌────────────────────────────────────────────────────┐
   │  corvus-core   the engine, no I/O, forbids unsafe   │
   │  decode → flow reassembly → TLS/HTTP/QUIC → hash    │
   │  ja3 · ja4 · ja4h · ja4x · ja4t · parse · quic      │
   └───────────────────────┬────────────────────────────┘
                           │  FingerprintEvent
   ┌───────────────────────┴────────────────────────────┐
   │  corvus-intel   the judgement, a bundled SQLite DB  │
   │  match (exact + JA4 fuzzy) → score → detection rules │
   │  matcher · seed · import · detect · signal · schema  │
   └───────────────────────┬────────────────────────────┘
                           │  MatchReport + Alert
   ┌───────────────────────┴────────────────────────────┐
   │  corvus   the binary: CLI + web dashboard           │
   │  pcap · live · serve (axum + SSE) · intel · report   │
   └────────────────────────────────────────────────────┘
```

**Design decisions.** The engine forbids `unsafe` outright, so a malformed packet can never be more than a parse error. The store is deliberately synchronous — a lookup is one indexed query and a capture is a plain loop; the async runtime lives only in the web server, where concurrent readers actually need it. JA3 uses MD5 because that is what the original definition and every public JA3 feed use, and reproducing those hashes is the entire reason to keep it. QUIC decryption needs no server secret because the client initial keys derive from a Connection ID that travels in the clear.

## Build and test

```bash
cargo build --release            # → target/release/corvus
cargo test --workspace           # 204 unit + integration tests, 1 ignored
cargo bench -p corvus-core       # criterion throughput benchmarks
just clippy                      # clippy::pedantic, warnings as errors
just fmt-check                   # rustfmt
```

Every fingerprint is pinned to a published vector. The JA3 tests reproduce the original Salesforce vectors through MD5; the JA4 tests reproduce the FoxIO cipher, extension, and TCP section vectors; the QUIC tests derive client initial keys and match RFC 9001 Appendix A (v1) and RFC 9369 Appendix A (v2) byte for byte. The reassembly tests rebuild a ClientHello from out-of-order and overlapping segments. The JA4X parser carries a property-test fuzz harness because it walks attacker-controlled certificate DER.

Benchmarks replay vendored captures frame by frame through the whole pipeline. On a modern laptop it sustains roughly **380,000 to 500,000 fingerprints per second**.

## Docker

```bash
just up                          # production: built dashboard + backend
just dev-up                      # development: vite hot reload
```

The production image is a multi-stage build that compiles the release binary in a Rust builder and ships only the binary plus built dashboard assets behind nginx. The development stack bind-mounts the frontend and runs `pnpm install` on startup.

## Layout

```
corvus/
├── Cargo.toml                    # 3-crate virtual workspace
├── crates/
│   ├── corvus-core/              # engine: no I/O, forbids unsafe
│   │   ├── src/
│   │   │   ├── parse/            # TLS record, ClientHello, ServerHello, certificate readers
│   │   │   ├── pipeline/         # decode → flow reassembly → TLS/HTTP → event
│   │   │   ├── ja3.rs            # JA3 / JA3S
│   │   │   ├── ja4.rs            # JA4 / JA4S
│   │   │   ├── ja4h.rs           # JA4H, HTTP request
│   │   │   ├── ja4x.rs           # JA4X, X.509 certificate
│   │   │   ├── ja4t.rs           # JA4T / JA4TS, TCP stack
│   │   │   ├── quic.rs           # QUIC initial decryption (RFC 9001 + 9369)
│   │   │   ├── grease.rs         # GREASE table and strip
│   │   │   ├── der.rs            # minimal DER reader for JA4X
│   │   │   └── registry.rs       # version codes and extension constants
│   │   ├── benches/fingerprint.rs
│   │   └── tests/                # KAT + integration: ja3, ja4, ja4x, parse, reassembly
│   ├── corvus-intel/             # judgement: bundled SQLite store
│   │   ├── src/
│   │   │   ├── schema.rs         # migrations
│   │   │   ├── seed.rs           # vendored feeds, compiled in
│   │   │   ├── import.rs         # validated ja4db.com importer
│   │   │   ├── matcher.rs        # exact + JA4 fuzzy lookup, scored
│   │   │   ├── detect.rs         # the six detection rules
│   │   │   ├── signal.rs         # User-Agent / OS heuristics the rules read
│   │   │   └── model.rs          # FpKind, Category, Verdict, report types
│   │   └── seeds/                # vendored CSV feeds
│   └── corvus/                   # the binary
│       └── src/
│           ├── cli.rs            # clap command tree
│           ├── live.rs           # libpcap capture thread and async bridge
│           ├── report.rs         # forensic --report builder
│           └── serve.rs          # axum dashboard + SSE stream
├── frontend/                     # dashboard (Vite + React 19)
├── testdata/pcap/                # vendored captures, integration fixtures
├── install.sh
└── justfile
```

## License

[AGPL-3.0](LICENSE). Modified derivative of an earlier TLS fingerprinting sensor by [Carter Perez](https://github.com/CarterPerez-dev).

JA3/JA3S and JA4 are BSD-3-Clause. JA4S, JA4H, JA4X, and JA4T are FoxIO License 1.1, patent pending, non-commercial use only — Corvus is free, non-commercial, and not offered as a hosted service. Vendored threat feeds keep their original licenses. Details in [`NOTICE.md`](NOTICE.md).
