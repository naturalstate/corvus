<!-- ©AngelaMos | 2026 -->
<!-- 01-CONCEPTS.md -->

# JA3/JA4 TLS Fingerprinting: Concepts

This document explains the ideas the tool is built on, each grounded in something that actually happened. Read it before the code. Once these click, the implementation is just careful bookkeeping.

## 1. The ClientHello is a confession

A TLS connection opens with the client sending a `ClientHello`, the first real message on the wire. It travels in plaintext, because the two sides have not yet agreed on a key to encrypt with. Inside it, the client lists exactly how it is configured:

- the **TLS versions** it supports,
- the **cipher suites** it offers, in a specific order of preference,
- a list of **extensions** (SNI, ALPN, supported groups, signature algorithms, key share, and many more),
- the **elliptic curves** ("supported groups") it can do,
- the **EC point formats** it understands.

None of this is secret. All of it is chosen by the *software*, not the user. Chrome's TLS stack offers a different set, in a different order, than Firefox's, than Go's `crypto/tls`, than Python's `ssl`, than the bespoke library inside a piece of malware. Two installations of the same Chrome version produce nearly identical ClientHellos; Chrome and a Python script produce obviously different ones.

```
ClientHello
├── legacy_version:        0x0303  (TLS 1.2, frozen here even for TLS 1.3)
├── random:               32 bytes (ignored, it changes every time)
├── cipher_suites:        [0x1301, 0x1302, 0x1303, 0xc02b, ...]
├── compression_methods:  [0x00]
└── extensions:
    ├── 0x0000 server_name           "example.com"
    ├── 0x000a supported_groups      [0x001d, 0x0017, ...]
    ├── 0x000d signature_algorithms  [0x0403, 0x0804, ...]
    ├── 0x0010 alpn                  ["h2", "http/1.1"]
    ├── 0x002b supported_versions    [0x0304, 0x0303]
    └── ...
```

A **fingerprint** turns that structure into a short, stable string. The insight, due to Salesforce in 2017, is that the *shape* of the ClientHello identifies the software even when every other identifier is forged. An attacker can change their IP, their domain, and their certificate for free. Changing their TLS stack means rebuilding their tooling.

## 2. JA3: the original, and why it died

JA3 (named for its three authors, John Althouse, Jeff Atkinson, Josh Atkins) builds the fingerprint the obvious way. It takes five fields in order, version, ciphers, extensions, supported groups, point formats, writes each as decimal numbers, joins them, and takes the MD5:

```
769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0
                                  │
                                 MD5
                                  ▼
                  ada70206e40642a3e4461f35503241d5
```

For years this worked beautifully. Cobalt Strike's default profile, Trickbot, Emotet, each had a known JA3, and feeds like abuse.ch SSLBL published thousands of malware JA3 hashes that defenders could block directly.

Then it broke, for a specific and instructive reason. **JA3 hashes the extensions in the exact order the client sent them.** In 2021, Chrome (followed by others) started doing something the TLS spec explicitly permits: shuffling the order of its extensions on every single connection, as a deliberate anti-ossification measure. The cipher list stayed the same, the extensions present stayed the same, but their *order* changed every time. Since JA3 hashes order, every Chrome connection now produced a different JA3 hash. Overnight, JA3 became useless for fingerprinting browsers. A signature that changes every time identifies nothing.

JA3 is not dead for *malware*, though, which is why this tool still computes it. Malware tooling rarely shuffles extensions, public feeds are still expressed in JA3, and watching JA3 fragment next to a stable JA4 on real browser traffic is the single clearest demonstration of why the successor exists.

> The Emotet and Cobalt Strike collision is worth sitting with. Both have appeared under the JA3 hash `72a589da586844d7f0818ce684948eea`, not because they are the same malware, but because they were built on the same TLS library configured the same way. A fingerprint identifies a *toolchain*. Treating a fingerprint match as proof of a specific actor is a mistake; treating it as "this came from a known-suspicious toolchain" is correct.

## 3. JA4: sort first, and survive

JA4, published by FoxIO in 2023, fixes the order problem with one change: **it sorts the cipher and extension lists before hashing them.** If the set of extensions a client offers is stable but their order is random, then sorting throws the randomness away and keeps the signal. Chrome's shuffled extensions sort back to the same list every time, so JA4 is stable again.

JA4 also changed the format to be *partly human-readable*, which JA3's opaque MD5 was not. A JA4 fingerprint has three underscore-separated parts:

```
t13d1516h2_8daaf6152771_e5627efa2ab1
│            │            │
│            │            └── truncated SHA-256 of the sorted extensions (+ sig algs)
│            └── truncated SHA-256 of the sorted cipher suites
└── 10 readable characters:
    t   transport: t=TCP, q=QUIC, d=DTLS
    13  TLS version: 1.3
    d   SNI present (d=domain, i=no SNI)
    15  cipher count (15)
    16  extension count (16)
    h2  first ALPN value (h2 = HTTP/2)
```

You can read the prefix at a glance: "TLS 1.3 over TCP, with SNI, 15 ciphers, 16 extensions, speaking HTTP/2." Two clients with different prefixes are visibly different software before you even compare the hashes. The hashes then distinguish clients that share a prefix.

The two design choices, sorting and a readable prefix, are the entire reason JA4 succeeded where JA3 failed. [ALGORITHMS.md](./ALGORITHMS.md) walks the exact byte construction.

## 4. GREASE: clients lie on purpose

If you dump a real Chrome ClientHello, you will see cipher suites and extensions with values like `0x0a0a`, `0x1a1a`, `0x2a2a`. These are not real. They are **GREASE** (Generate Random Extensions And Sustain Extensibility, RFC 8701), random reserved values that a client deliberately injects to keep the ecosystem honest, so that middleboxes and servers cannot start assuming a fixed set of values and break future clients that add new ones.

GREASE is poison for fingerprinting if you ignore it. The whole point of GREASE is that the values are *random per connection*, so any fingerprint that includes them changes every time, exactly the JA3 order problem in a different costume. Both JA3 and JA4 therefore **strip every GREASE value** from every list before hashing. The set of GREASE values is fixed and known (the `0x?a?a` pattern, sixteen of them), so stripping is a simple filter.

```
offered:  [0x1a1a, 0x1301, 0x1302, 0x1303, 0xc02b]   <- 0x1a1a is GREASE
hashed:           [0x1301, 0x1302, 0x1303, 0xc02b]   <- stripped before hashing
```

This tool keeps the GREASE table in one place (`grease.rs`) and applies the same strip to every fingerprint, because a fingerprint that forgets to strip GREASE is not wrong occasionally, it is wrong on every modern client.

## 5. JA4+ is a family, and one fingerprint is never enough

JA4 is the TLS-client fingerprint, but the same idea applies to other layers, and the family (collectively "JA4+") cross-checks each other. This tool computes all of them:

| Fingerprint | What it identifies | Read from |
|-------------|-------------------|-----------|
| **JA4** | the TLS client software | the ClientHello |
| **JA4S** | the TLS server software | the ServerHello |
| **JA4H** | the HTTP client software | a cleartext HTTP request |
| **JA4X** | the certificate-issuing toolchain | an X.509 certificate |
| **JA4T** | the client's TCP/IP stack (the OS) | the SYN packet |

The reason to compute several is **evasion**. A growing class of tools (`curl-impersonate`, `utls`, and others) exists precisely to forge a browser's ClientHello. They make a script's JA4 identical to a real Chrome's, so a JA4-only filter waves them through. But forging one layer does not forge the others. A Python script running on Linux, impersonating Chrome's TLS, still emits a *Linux* TCP SYN, so its JA4T betrays it. It still sends HTTP headers in a script's order, so its JA4H betrays it. It still claims `User-Agent: ...Chrome...`, which now *disagrees* with its TCP stack.

That disagreement is the single most valuable signal this tool produces, and it is the headline detection rule. [02-ARCHITECTURE.md](./02-ARCHITECTURE.md) describes how the rules combine these, and [ALGORITHMS.md](./ALGORITHMS.md) gives each construction.

> This is the lesson of the browser-impersonation arms race. As long as defenders fingerprinted only TLS, attackers only had to forge TLS. The defense is not a better single fingerprint; it is *correlation across layers the attacker controls independently*. An attacker who forges all of them perfectly has, in effect, rebuilt a real browser, which is expensive and rare.

## 6. Passive QUIC: "encrypted" is not "secret"

QUIC, the transport under HTTP/3, carries its own TLS handshake inside its first packets, and those packets are encrypted. It would seem a passive observer is locked out. It is not, and the reason is a beautiful subtlety.

QUIC's *Initial* packets are encrypted, but with a key that is **derived from the connection's Destination Connection ID, which is sent in the clear in the packet header.** The encryption exists to defeat dumb middleboxes that would otherwise mangle the packets, not to keep the handshake secret. Anyone who reads the packet can derive the same key, decrypt the Initial, and read the ClientHello inside, exactly as if it were TCP.

```
QUIC Initial packet
├── header (cleartext):  ... Destination Connection ID = D ...
└── payload (encrypted under a key derived from D)
                          │
        HKDF(D) ──────────┘   anyone can compute this
                          ▼
                  decrypted CRYPTO frames
                          ▼
                  TLS ClientHello  ->  q-transport JA4
```

This tool derives the client initial keys from each packet's own Connection ID, following RFC 9001 for QUIC v1 and RFC 9369 for QUIC v2, with no server-side secret and no direction detection. It reassembles the CRYPTO frames (a QUIC ClientHello can span several Initial packets) and feeds the result to the same JA4 code the TCP path uses. The fingerprint comes out with a `q` transport marker. [ALGORITHMS.md](./ALGORITHMS.md) gives the full key schedule.

## 7. Passive capture and the reassembly problem

Everything above assumes you can see a clean ClientHello. In a real capture you cannot. TCP delivers a *stream* of bytes chopped into segments that arrive out of order, get retransmitted, and sometimes overlap. A ClientHello large enough to span two segments will not parse if you look at either segment alone.

So before any fingerprinting, the tool must do what TCP itself does at the endpoint: **reassemble each direction of each conversation into a contiguous byte stream.** It tracks every flow (a four-tuple of source and destination address and port), buffers out-of-order segments until the gap before them fills, and resolves overlaps. Only once a contiguous run of bytes contains a complete TLS record does the parser run.

This is also where the **security of the sensor itself** lives. A passive tool processes attacker-controlled bytes by definition: anyone on the monitored network can send it whatever they like. So the reassembly layer is bounded in every dimension, a maximum number of tracked flows, an idle timeout that evicts stale ones, a ceiling on buffered out-of-order bytes per direction. Without those bounds, an attacker could open millions of flows, or send segments with a permanent gap that never fills, and watch the sensor's memory climb until the host dies. The bounds turn an unbounded adversarial input into a fixed, survivable cost. [03-IMPLEMENTATION.md](./03-IMPLEMENTATION.md) shows the exact caps.

## 8. Memory safety is a security property here

This tool is written in Rust, and the fingerprinting engine forbids `unsafe` outright. That is not a stylistic preference; it is a direct response to what this code does.

Every parser in `tlsfp-core` reads **attacker-controlled binary input**: a TLS record from the wire, an X.509 certificate from a hostile server, a QUIC packet from anywhere. This is the exact category of code that produces the worst vulnerabilities in the C world. **Heartbleed (CVE-2014-0160)** was a TLS-parsing bug, a length field trusted without bounds-checking, that let an attacker read server memory. A fingerprinting sensor is *nothing but* TLS and certificate parsing, so in C it would be a Heartbleed factory.

In Rust, a length field that claims more bytes than exist produces a typed `ParseError`, not an out-of-bounds read. The JA4X certificate parser, which walks the most attacker-friendly format of all (X.509 DER), has a property-test fuzz harness that throws random and truncated certificates at it specifically to prove it returns errors instead of panicking. Safety is the feature that lets a passive sensor sit on a hostile network without itself becoming the vulnerability. [CONFORMANCE.md](./CONFORMANCE.md) records exactly what the parsers accept and reject.

## Further Reading

- [FoxIO JA4+ technical specifications](https://github.com/FoxIO-LLC/ja4/tree/main/technical_details): the authoritative JA4, JA4S, JA4H, JA4X, JA4T definitions.
- [Salesforce, "TLS Fingerprinting with JA3 and JA3S" (2017)](https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967/): the original.
- [RFC 8701](https://www.rfc-editor.org/rfc/rfc8701.html): GREASE.
- [RFC 9001](https://www.rfc-editor.org/rfc/rfc9001.html) and [RFC 9369](https://www.rfc-editor.org/rfc/rfc9369.html): QUIC's use of TLS, v1 and v2.
- [abuse.ch SSLBL](https://sslbl.abuse.ch/): one of the public feeds this tool seeds from.
