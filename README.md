<!-- README.md -->

```json
 ██████╗ ██████╗ ██████╗ ██╗   ██╗██╗   ██╗███████╗
██╔════╝██╔═══██╗██╔══██╗██║   ██║██║   ██║██╔════╝
██║     ██║   ██║██████╔╝██║   ██║██║   ██║███████╗
██║     ██║   ██║██╔══██╗╚██╗ ██╔╝██║   ██║╚════██║
╚██████╗╚██████╔╝██║  ██║ ╚████╔╝ ╚██████╔╝███████║
 ╚═════╝ ╚═════╝ ╚═╝  ╚═╝  ╚═══╝   ╚═════╝ ╚══════╝
```

[![Rust](https://img.shields.io/badge/Rust-edition%202024-CE412B?style=flat&logo=rust&logoColor=white)](https://www.rust-lang.org)
[![JA4+](https://img.shields.io/badge/JA4%2B-JA3%20%C2%B7%20JA4%20%C2%B7%20JA4H%20%C2%B7%20JA4X%20%C2%B7%20JA4T-4B7BEC?style=flat)](https://github.com/FoxIO-LLC/ja4)
[![License: AGPLv3](https://img.shields.io/badge/License-AGPL_v3-purple.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Fork](https://img.shields.io/badge/fork%20of-tlsfp-lightgrey?style=flat&logo=github)](https://github.com/CarterPerez-dev/Cybersecurity-Projects/tree/main/PROJECTS/intermediate/ja3-ja4-tls-fingerprinting)

---

> **Corvus** is a passive TLS fingerprinting sensor in Rust that identifies client software from the handshake alone — no decryption, no packets sent. It computes JA3, JA4, JA4S, JA4H, JA4X, and JA4T for every handshake it sees, reads the TLS hidden inside QUIC Initial packets, matches against a bundled intelligence database, and flags what a fingerprint cannot hide: a TLS stack that disagrees with its own User-Agent, a client rotating identities to dodge a blocklist, a fingerprint never seen before.
>
> Where the sensor only listens, Corvus is growing a transmitter. A **mirror server** that terminates real connections and tells visitors exactly what they look like. A **ClientHello forger** that impersonates a browser to attack the detector — and gets caught anyway, because a spoofed TLS stack still has the wrong TCP accent. **JARM** active server fingerprinting. An **interception mode** proving that TLS inspection is itself fingerprintable. Plus HTTP/2 fingerprinting, `SSLKEYLOGFILE` decryption, and a dashboard that shows how a fingerprint is *assembled byte by byte* instead of just printing the hash.
>
> Observe, understand, reproduce, then break your own detector.

> [!NOTE]
> **Corvus is a fork.** The sensor described under [What Works Today](#what-works-today) is the work of
> [Carter Perez](https://github.com/CarterPerez-dev), from the `tlsfp` project in
> [Cybersecurity-Projects](https://github.com/CarterPerez-dev/Cybersecurity-Projects). Corvus starts from
> that baseline and extends it — see [Roadmap](#roadmap) for what is being added and
> [Credits](#credits) for the full attribution. This is a personal, non-commercial learning project.

## Why fingerprint TLS

When a client opens a TLS connection, the very first message it sends, the ClientHello, is a detailed self-description: which TLS versions it supports, which cipher suites in which order, which extensions, which elliptic curves. A browser, a Go program, a Python script, and a piece of malware each assemble that message differently, because each is built on a different TLS library configured a different way. The ClientHello travels in the clear, before any encryption is negotiated, so a passive observer who never decrypts anything can still read it.

A fingerprint is a hash of those choices. The same software produces the same fingerprint on every connection, so a fingerprint that is on a blocklist today catches the same malware family tomorrow even if its IP, its domain, and its certificate all changed. That is the idea behind JA3, published by Salesforce in 2017, and JA4, its 2023 successor from FoxIO that fixed the one weakness that eventually killed JA3 for browser traffic: when Chrome started shuffling its extension order on every connection, JA3, which hashes extensions in wire order, produced a fresh hash every time. JA4 sorts first, so the shuffle changes nothing.

This project builds the whole sensor around that idea, in a language where a parser bug is a memory-safety bug. The fingerprinting core forbids `unsafe`, the capture path is bounded so an adversarial packet cannot exhaust memory, and every fingerprint is checked byte for byte against the reference implementations.

## What Works Today

This is not a stub. The tool fingerprints real captures, decrypts real QUIC, matches against real public threat feeds, and raises real alerts, and every capability below is exercised by a known-answer test against a published vector, an integration test against a vendored capture, and a run of the actual `tlsfp` binary.

**Fingerprints**
- **JA3 / JA3S** (MD5 of the ClientHello / ServerHello field list), kept because public malware feeds still speak JA3 and because watching it collapse next to JA4 is the clearest way to see why JA4 exists
- **JA4 / JA4S** (the FoxIO TLS client and server fingerprint, sorted cipher and extension lists), the headline fingerprint, stable under extension shuffling
- **JA4H** the HTTP client fingerprint, from a cleartext request's method, version, header order, cookies, and accept-language
- **JA4X** the X.509 fingerprint, from the issuer, subject, and extension object identifiers of a certificate, which clusters certificates minted by one toolchain
- **JA4T / JA4TS** the TCP-stack fingerprint, from the SYN's window size, options, MSS, and window scale, which catches a tool wearing a browser's TLS clothing while its OS speaks with a different TCP accent
- GREASE values stripped from every list, so the deliberate noise a modern client inserts never changes its fingerprint

**Capture**
- Reads `pcap` and `pcapng` files, and captures live from an interface through `libpcap` with the raw-socket capabilities dropped to exactly the two the kernel needs
- A reassembly layer rebuilds each direction of each TCP conversation, surviving reordering, retransmission, and overlap, so a ClientHello split across segments still fingerprints
- Bounded by construction: a flow cap, an idle timeout, and per-stream byte ceilings keep an adversarial capture from turning the flow table into a memory bomb

**QUIC**
- Decrypts QUIC Initial packets to read the ClientHello inside, deriving the client initial keys from the packet's own Destination Connection ID per RFC 9001 (QUIC v1) and RFC 9369 (QUIC v2), with no server-side secret
- Reassembles CRYPTO frames across packets, so a QUIC ClientHello spread over several initials still yields a `q`-transport JA4

**Intelligence**
- A bundled SQLite database seeded from three vendored feeds with no network call: abuse.ch SSLBL, the Salesforce `osx-nix` JA3 list, and a small curated C2 set (**271 fingerprints**)
- An optional install-time pull of ja4db.com, validated record by record on the way in
- Exact lookups plus JA4 fuzzy matching on the capability-and-cipher prefix, scored into a verdict with a threat score and a confidence

**Detection**
- Six rules that run as a capture streams: `known_bad` (a feed hit), `ua_mismatch` (the headline: a JA4 that disagrees with its own User-Agent), `os_mismatch` (a JA4T that disagrees with the OS the User-Agent claims), `first_seen`, `fp_rotation`, and `monoculture`
- A forensic `--report` mode that reads a whole capture and prints one ranked summary, folding in intelligence and detection automatically whenever the database is present
- A web dashboard that streams events and alerts over Server-Sent Events, fed by a replayed capture, a live interface, or an external sensor tailing the same database

See [`learn/CONFORMANCE.md`](learn/CONFORMANCE.md) for the exact published vector each fingerprint is pinned to, and every deliberate scope boundary.

## Roadmap

Everything below is **planned, not built**. The organizing idea: a sensor is half a loop. Close it — observe a fingerprint, understand it, reproduce it, then attack your own detector and see what still catches you.

### Active mode — the transmitter

| | What | Why it matters |
|---|---|---|
| **`probe`** | A TLS listener that terminates real connections and tells the visitor what they look like, reading the ClientHello via `rustls::server::Acceptor` before completing the handshake | Instant feedback loop. Runs `ua_mismatch` against the visitor in real time — the flagship rule demoed on the person reading the page |
| **`forge`** | Hand-craft an arbitrary ClientHello from a JA4 string or a named profile (`--as chrome-131`) and send it. No full TLS client needed — one message is enough to be fingerprinted | Spoof the TLS layer, then watch `os_mismatch` catch you anyway because your TCP stack still says Linux. The single clearest argument for why layered fingerprinting exists |
| **`jarm`** | Salesforce's active server fingerprint — ten deliberately malformed ClientHellos, hashed by how the server responds | Completes the 2×2: passive/active × client/server. This is how C2 infrastructure gets found on Shodan |
| **`intercept`** | Transparent MITM proxy with its own CA | The point isn't decryption, it's the thesis: a TLS inspection appliance *changes the client fingerprint*, so corporate interception is passively detectable — and so is an attacker doing the same |
| **`--keylog`** | Decrypt TLS 1.2/1.3 application data from an `SSLKEYLOGFILE` | Show the ClientHello *and* the decrypted HTTP/2 inside the same flow. The QUIC crypto plumbing already exists, and `testdata/pcap/chrome-cloudflare-quic-with-secrets.pcapng` already ships with keys |

### Presentation — from log lines to a teaching instrument

- **ClientHello byte explorer** — raw hex, every field annotated, hover a byte to highlight which character of the JA4 string it produced. Click the cipher list and watch it sort, then hash. Turns a magic string into something you can see get built.
- **The JA3 collapse** — split screen, replay twenty Chrome connections. JA3 fills with twenty different hashes. JA4 shows one, twenty times. Ten seconds of animation replaces three paragraphs.
- **Fingerprint diff** — field-by-field. Chrome vs Edge (nearly identical, and that's a finding). Chrome vs curl (wildly different). Chrome vs *forged* Chrome (identical — the point).
- **Quiz mode** — here's a raw ClientHello. Browser, automation tool, or malware? Reveal and explain the tells.

### Going deeper

- **HTTP/2 fingerprinting (Akamai)** — `SETTINGS` frame values and order, window update, pseudo-header order, priority tree. What Cloudflare and Akamai actually use alongside JA3/JA4, and genuinely underserved in open source. Also the natural blue-team answer to `forge`: spoofing a ClientHello is easy, spoofing all of Chrome's HTTP/2 behavior is not.
- **ECH detection** — Encrypted Client Hello encrypts the ClientHello itself. When it deploys, SNI vanishes and passive fingerprinting degrades hard. Detect it, report it, and write the honest chapter on the expiration date of this entire technique — and what survives it (JA4T, HTTP/2, traffic shape).
- **HASSH** — the same idea for SSH. Cheap once the pipeline exists, and it proves the concept isn't TLS-specific.

> [!IMPORTANT]
> `forge` and `intercept` are dual-use. They will default to loopback and lab targets, require an
> explicit flag for anything else, and exist to test this project's own detector.

## Quick Start

Corvus is built from source. Clone it, then:

```bash
./install.sh
```

The installer builds the release binary, puts `tlsfp` on your PATH, and seeds the intelligence database. Pass `--live` to also grant the raw-socket capabilities that live capture needs. Then point it at a capture:

```bash
# Fingerprint every handshake in a capture, one line each
tlsfp pcap testdata/pcap/tls-handshake.pcapng

# Match against the intel database and run the detection rules
tlsfp intel seed
tlsfp pcap testdata/pcap/tls-handshake.pcapng --report

# Watch an interface in real time, matching and detecting as it goes
sudo setcap cap_net_raw,cap_net_admin=eip "$(command -v tlsfp)"
tlsfp live eth0 --intel --detect
```

A single fingerprint line looks like this, a Chrome handshake to a Google host:

```
1675707151.805 192.168.1.168:50112 -> 142.251.16.94:443 client_hello ja4=t13d1516h2_8daaf6152771_e5627efa2ab1 ja3=1c258ebef8eee2dfa3df6d8d07285af9 sni=clientservices.googleapis.com alpn=h2
```

> [!TIP]
> The binary and crates are still named `tlsfp` from upstream. Renaming them to `corvus` is a
> separate, purely mechanical commit — the baseline is being kept byte-identical first so the
> fork's real changes stay readable in the history.

> [!TIP]
> This project uses [`just`](https://github.com/casey/just) as a command runner. Type `just` to see every recipe. `just bench` runs the throughput benchmarks; `just dev-up` brings up the dockerized dashboard with hot reload.
>
> Install: `curl -sSf https://just.systems/install.sh | bash -s -- --to ~/.local/bin`

### Building on Windows

Develop in WSL2. The engine (`tlsfp-core`) and intel store (`tlsfp-intel`) are portable Rust and compile anywhere, but the binary's capture path is not: `pcap` links `libpcap`, `rustix`'s `event` feature is `eventfd`, and `setcap` has no Windows equivalent. On WSL2, install the build dependencies first:

```bash
sudo apt-get install -y libpcap-dev pkg-config build-essential libcap2-bin
```

Keep the repo on the Linux filesystem (`~/`), not `/mnt/c` — Cargo builds several times slower across the translation layer. For live capture to see host traffic rather than just WSL's virtual NIC, set `networkingMode=mirrored` under `[wsl2]` in `.wslconfig` (Windows 11 only).

## Learn

This project ships a full teaching track. Read it in order, or jump to what you need.

| Doc | What it covers |
|-----|----------------|
| [`learn/00-OVERVIEW.md`](learn/00-OVERVIEW.md) | What TLS fingerprinting is, why it works, and a 10-minute tour |
| [`learn/01-CONCEPTS.md`](learn/01-CONCEPTS.md) | The ClientHello, JA3 vs JA4, GREASE, evasion, QUIC, passive capture, grounded in real intrusions |
| [`learn/02-ARCHITECTURE.md`](learn/02-ARCHITECTURE.md) | The three-crate split, the capture pipeline, the intelligence store, the threat model |
| [`learn/03-IMPLEMENTATION.md`](learn/03-IMPLEMENTATION.md) | A code walkthrough from a raw frame to a scored alert, and the reassembly and bounding patterns |
| [`learn/ALGORITHMS.md`](learn/ALGORITHMS.md) | How each fingerprint is computed byte by byte, and how a QUIC initial is decrypted |
| [`learn/CONFORMANCE.md`](learn/CONFORMANCE.md) | The published vector each fingerprint is pinned to, and every deliberate scope boundary |
| [`learn/04-CHALLENGES.md`](learn/04-CHALLENGES.md) | Extension ideas from beginner to expert |

## Architecture

Three crates, in a strict dependency line. The engine knows nothing about databases or networks; the intelligence store knows nothing about capture; the binary wires them together.

```
   pcap / pcapng file        live interface (libpcap)       QUIC initial
            │                         │                          │
            └─────────────┬───────────┴──────────────────────────┘
                          │  raw link-layer frames
                          ▼
   ┌────────────────────────────────────────────────────┐
   │  tlsfp-core   the engine, no I/O, forbids unsafe    │
   │  decode → flow reassembly → TLS/HTTP/QUIC → hash    │
   │  ja3 · ja4 · ja4h · ja4x · ja4t · parse · quic      │
   └───────────────────────┬────────────────────────────┘
                           │  FingerprintEvent
   ┌───────────────────────┴────────────────────────────┐
   │  tlsfp-intel   the judgement, a bundled SQLite DB   │
   │  match (exact + JA4 fuzzy) → score → detection rules │
   │  matcher · seed · import · detect · signal · schema  │
   └───────────────────────┬────────────────────────────┘
                           │  MatchReport + Alert
   ┌───────────────────────┴────────────────────────────┐
   │  tlsfp   the binary: CLI + web dashboard            │
   │  pcap · live · serve (axum + SSE) · intel · report   │
   └────────────────────────────────────────────────────┘
```

**Design decisions:** the engine forbids `unsafe` outright, so a malformed packet can never be more than a parse error. The store is deliberately synchronous, because a lookup is one indexed query and a capture is a plain loop; the async runtime lives only in the web server, where concurrent readers actually need it. JA3 uses MD5 because that is what the original definition and every public JA3 feed use, and reproducing those feed hashes is the whole point of keeping it. The QUIC decryption uses no server secret because the client initial keys are derived from a Connection ID that travels in the clear.

## Build and Test

```bash
cargo build --release            # the shipped binary → target/release/tlsfp
cargo test --workspace           # 204 unit + integration tests, 1 ignored
cargo bench -p tlsfp-core        # criterion throughput benchmarks
just clippy                      # clippy::pedantic, warnings as errors
just fmt-check                   # rustfmt
```

Every fingerprint is pinned to a published vector. The JA3 tests reproduce the original Salesforce blog vectors through MD5; the JA4 tests reproduce the FoxIO cipher, extension, and TCP section vectors; the QUIC tests derive the client initial keys and match RFC 9001 Appendix A (v1) and RFC 9369 Appendix A (v2) byte for byte. The reassembly tests rebuild a ClientHello from out-of-order and overlapping segments. The JA4X parser has a property-test fuzz harness because it walks attacker-controlled certificate DER.

The benchmarks replay vendored captures frame by frame through the whole pipeline. On a modern laptop the pipeline sustains roughly **380,000 to 500,000 fingerprints per second**, comfortably past the project target of 10,000.

## Run in Docker

No Rust toolchain on the host? The dashboard runs entirely in containers.

```bash
just up                          # production stack: built dashboard + backend
just dev-up                      # development stack: vite hot reload
```

The production image is a multi-stage build that compiles the release binary in a Rust builder and ships only the binary plus the built dashboard assets behind nginx. The development stack bind-mounts the frontend and runs `pnpm install` on startup, so an added package is always present after a restart.

## Project Structure

```
corvus/
├── Cargo.toml                    # the 3-crate virtual workspace
├── crates/
│   ├── tlsfp-core/               # the engine: no I/O, forbids unsafe
│   │   ├── src/
│   │   │   ├── parse/            # TLS record, ClientHello, ServerHello, certificate readers
│   │   │   ├── pipeline/         # decode → flow reassembly → TLS/HTTP → event
│   │   │   ├── ja3.rs            # JA3 / JA3S (the dead-but-still-fed MD5 fingerprint)
│   │   │   ├── ja4.rs            # JA4 / JA4S (the headline sorted fingerprint)
│   │   │   ├── ja4h.rs           # JA4H (the HTTP request fingerprint)
│   │   │   ├── ja4x.rs           # JA4X (the X.509 certificate fingerprint)
│   │   │   ├── ja4t.rs           # JA4T / JA4TS (the TCP-stack fingerprint)
│   │   │   ├── quic.rs           # QUIC initial decryption (RFC 9001 + RFC 9369)
│   │   │   ├── grease.rs         # the GREASE value table and the strip
│   │   │   ├── der.rs            # the minimal DER reader JA4X needs
│   │   │   └── registry.rs       # version codes and extension constants
│   │   ├── benches/fingerprint.rs# criterion throughput benchmarks
│   │   └── tests/                # KAT + integration: ja3, ja4, ja4x, parse, reassembly
│   ├── tlsfp-intel/              # the judgement: a bundled SQLite store
│   │   ├── src/
│   │   │   ├── schema.rs         # the migrations
│   │   │   ├── seed.rs           # the three vendored feeds, compiled in
│   │   │   ├── import.rs         # the validated ja4db.com importer
│   │   │   ├── matcher.rs        # exact + JA4 fuzzy lookup, scored into a verdict
│   │   │   ├── detect.rs         # the six detection rules
│   │   │   ├── signal.rs         # the User-Agent / OS heuristics the rules read
│   │   │   └── model.rs          # FpKind, Category, Verdict, the report types
│   │   └── seeds/                # the vendored CSV feeds
│   └── tlsfp/                    # the binary
│       └── src/
│           ├── cli.rs            # the clap command tree
│           ├── live.rs          # the libpcap capture thread and the async bridge
│           ├── report.rs        # the forensic --report builder
│           └── serve.rs          # the axum dashboard + SSE stream
├── frontend/                     # the dashboard (Vite + React 19)
├── testdata/pcap/                # vendored captures, the integration fixtures
├── install.sh                    # the one-shot installer
└── justfile                      # every recipe
```

## Credits

Corvus is a fork of **`tlsfp`** by [Carter Perez](https://github.com/CarterPerez-dev), from the
[Cybersecurity-Projects](https://github.com/CarterPerez-dev/Cybersecurity-Projects) collection
(`PROJECTS/intermediate/ja3-ja4-tls-fingerprinting`). The entire sensor — the three-crate
architecture, the fingerprint implementations, the QUIC decryption, the intelligence store, the
detection rules, the dashboard, and the `learn/` track — is their work. Corvus keeps it under the
same license and builds on top of it.

The fingerprinting algorithms themselves are third-party published specifications with their own
terms, recorded in [`NOTICE.md`](NOTICE.md):

- **JA3 / JA3S** — John Althouse, Jeff Atkinson, Josh Atkins at Salesforce (BSD 3-Clause)
- **JA4** — [FoxIO](https://github.com/FoxIO-LLC/ja4) (BSD 3-Clause, no patents asserted)
- **JA4S / JA4H / JA4X / JA4T** — FoxIO (FoxIO License 1.1, patent pending, **non-commercial only**)

### Changes from upstream

- Renamed the project to Corvus; README rewritten with the fork's direction and roadmap
- Corrected the `license` field in `Cargo.toml` from `MIT` to `AGPL-3.0-only` to match the actual `LICENSE` file, and resolved the same contradiction in `NOTICE.md`
- Removed the upstream installer URL and hosted-demo links, which point at infrastructure this fork does not control
- Added WSL2 / Windows build notes

## License

[AGPL 3.0](LICENSE), inherited from upstream. The vendored threat feeds under
`crates/tlsfp-intel/seeds/` keep their original licenses, recorded per feed in
[`NOTICE.md`](NOTICE.md) and in the `intel_source` table.

Because JA4S, JA4H, JA4X, and JA4T are covered by the FoxIO License 1.1, this project is and stays
**free, non-commercial, and not offered as a hosted service**. Anyone forking it with intent to
monetize or to run it as a service must obtain an OEM license from FoxIO first.
