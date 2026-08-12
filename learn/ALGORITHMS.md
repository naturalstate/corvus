<!-- ©AngelaMos | 2026 -->
<!-- ALGORITHMS.md -->

# JA3/JA4 TLS Fingerprinting: Algorithms

This is the byte-level reference. For each fingerprint it gives the exact construction, a worked example pinned to a published vector, and the rules that bite at the edges. Every example here is also a test in the codebase, so if you doubt a step you can run it. Read [01-CONCEPTS.md](./01-CONCEPTS.md) for *why* these are shaped the way they are; this is the *how*.

A note on truncated hashes: JA4 and its relatives take a SHA-256 and keep only the **first 12 hex characters** (the first 6 bytes). JA3 takes a full MD5 (32 hex characters). Where this document writes "truncated SHA-256," it means those first 12 hex characters.

## JA3 and JA3S

JA3 concatenates five decimal fields from the ClientHello, joins values inside a field with `-` and the fields with `,`, and takes the MD5.

```
field 1: legacy_version          (one number)
field 2: cipher_suites           (GREASE stripped, wire order, joined with -)
field 3: extension_types         (GREASE stripped, wire order, joined with -)
field 4: supported_groups        (GREASE stripped, joined with -)
field 5: ec_point_formats        (joined with -)

joined with commas, then MD5
```

**Worked example** (the original Salesforce vector, `salesforce_client_vector_one` in `ja3.rs`):

```
769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0
                              │ MD5
                              ▼
              ada70206e40642a3e4461f35503241d5
```

The leading `769` is the `legacy_version` field in decimal: `769` is `0x0301`, TLS 1.0, which is what this old vector carried. A modern TLS 1.2 or 1.3 client puts `771` (`0x0303`) here, because TLS 1.3 freezes the legacy field at 1.2 and signals the real version in an extension. Whatever the client wrote, it is rendered as a plain decimal number. The list fields are kept in **wire order**, which is exactly why extension-order shuffling broke JA3.

**JA3S** is the server's answer: three fields from the ServerHello (version, the single selected cipher, the extensions), same comma join, same MD5. A server picks one cipher, so field two is one number, not a list.

The whole reason this tool still computes JA3 is that the public feeds (`abuse.ch SSLBL` and the curated C2 set) are expressed in JA3, and the detection engine looks the JA3 up alongside the JA4 so a feed hit is never missed.

## JA4 and JA4S

JA4 has three underscore-separated sections: a 10-character readable prefix `_` the cipher hash `_` the extension hash. The construction is in `ja4()` and `ja4_prefix()` in `ja4.rs`.

### The prefix (10 characters)

```
  t    13    d    15    16    h2
  │    │     │    │     │     │
  │    │     │    │     │     └── first ALPN value: first + last char (or "00")
  │    │     │    │     └──────── extension count, two digits, capped at 99
  │    │     │    └────────────── cipher count, two digits, capped at 99
  │    │     └─────────────────── SNI: 'd' if a server_name extension is present, else 'i'
  │    └───────────────────────── TLS version word: 13, 12, 11, 10, or d1/d2/d3 for DTLS
  └────────────────────────────── transport: t=TCP, q=QUIC, d=DTLS
```

Two subtleties the code handles. The **version** is the highest non-GREASE value in the `supported_versions` extension, not the `legacy_version` field, because a TLS 1.3 client freezes the legacy field at 1.2 (`select_version` in `ja4.rs`). The **ALPN characters** are the first and last byte of the first ALPN protocol if both are ASCII alphanumeric (so `h2` stays `h2`, `http/1.1` becomes `h1`); if not, the code falls back to the first and last hex nibble; an absent ALPN is `00` (`alpn_chars` in `ja4.rs`).

### The cipher hash

Take the cipher suites, strip GREASE, format each as four lowercase hex digits, **sort the strings**, join with `,`, and take the truncated SHA-256.

**Worked example** (`foxio_cipher_section_vector` in `ja4.rs`):

```
sorted cipher CSV:
002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9
                              │ SHA-256, first 12 hex
                              ▼
                        8daaf6152771
```

The **sort** is the entire JA4 innovation. The client may send these in any order, and a modern client shuffles them, but sorting throws the order away and keeps the set. That is why this hash is stable where JA3's field-three was not.

### The extension hash

Take the extension types, **remove SNI (`0x0000`) and ALPN (`0x0010`)** because those are already represented in the prefix, strip GREASE, format as four hex digits, sort, join with `,`. Then, if a `signature_algorithms` extension is present, append `_` and the signature algorithms **in their original order** (not sorted, because their order is itself meaningful and stable). Take the truncated SHA-256 of the whole thing (`ja4_extension_raw` in `ja4.rs`).

**Worked example** (`foxio_extension_section_vector` in `ja4.rs`):

```
sorted exts (SNI + ALPN removed)              sig algs (original order)
0005,000a,000b,000d,0012,0015,0017,001b,    _ 0403,0804,0401,0503,
0023,002b,002d,0033,4469,ff01                  0805,0501,0806,0601
                              │ SHA-256, first 12 hex
                              ▼
                        e5627efa2ab1
```

### Putting it together

```
t13d1516h2  _  8daaf6152771  _  e5627efa2ab1
```

That is a real Chrome JA4. JA4 also has a **raw** form, where the cipher and extension sections are the CSV strings themselves instead of their hashes, for debugging; the tool emits it under `--json`.

**JA4S** mirrors this for the server: the server picks one cipher (so the cipher section is that single value in hex, not a hash of a list) and its extensions are hashed in **wire order, not sorted**, because a server does not shuffle its own extensions (`ja4s` in `ja4.rs`).

## JA4H: the HTTP client

JA4H fingerprints one cleartext HTTP request (`ja4h.rs`). It reads the method, the HTTP version, whether the request carries cookies and a referer, the count and order of the other header names, the accept-language, and the cookie names and values. The signal it captures: a request that omits an accept-language and sends no cookies is far more likely to be a script than a person, and the prefix makes that visible in the first few characters.

This works on **cleartext HTTP only**. Over HTTPS the request is encrypted; over HTTP/2 the headers are HPACK-compressed and unreadable to a passive observer. So JA4H fires on plain `http://` traffic, which on a modern network is the automated and legacy clients, exactly the interesting population.

## JA4X: the certificate toolchain

JA4X fingerprints an X.509 certificate by *how it was built*, not what it says (`ja4x.rs`). It extracts three lists of object identifiers (OIDs): those in the issuer name, those in the subject name, and those among the extensions, each in the order they were written into the DER. Each list is joined with `,` and hashed (truncated SHA-256), giving three sections:

```
issuer_oids_hash  _  subject_oids_hash  _  extension_oids_hash
```

Two certificates minted by the same software with the same template share a JA4X even when every name, serial, and key differs, which clusters certificates from one malware family or one CA toolchain. Passively this only works on **TLS 1.2 and earlier**, where the Certificate message travels in the clear; TLS 1.3 encrypts it. The OID extraction walks attacker-controlled DER through the minimal reader in `der.rs`, which is why `tests/ja4x.rs` includes a property-test fuzz harness: a crafted certificate must produce an error or a fingerprint, never a panic.

## JA4T: the TCP stack

JA4T fingerprints the TCP/IP stack (the operating system) from a single SYN (`ja4t.rs`). The format is four parts joined with `_`:

```
window_size _ option_kinds(joined with -) _ MSS _ window_scale
```

The option kinds are the TCP option *kind numbers* in the order they appear in the SYN; a missing MSS or window scale option is reported as `0`.

**Worked examples** (`foxio_windows_default_vector` and `foxio_windowed_vector` in `ja4t.rs`):

```
Windows default:  64240_2-1-3-1-1-4_1460_8
Windowed:         65535_2-1-3-1-1-8-4-0-0_1346_6
```

JA4T is the layer an evasion tool forgets. A script impersonating Chrome's TLS still rides its host OS's TCP stack, so its JA4T says "Linux" while its forged JA4 and its `User-Agent` say "Windows Chrome." That three-way disagreement is what the `os_mismatch` and `ua_mismatch` detection rules turn into an alert.

## GREASE stripping

Every list-based fingerprint above strips GREASE first (`grease.rs`). The GREASE values are the sixteen reserved code points of the form `0x?a?a` (`0x0a0a`, `0x1a1a`, ... `0xfafa`), defined by RFC 8701. A client injects them at random to keep the ecosystem extensible, so including them would make the fingerprint change on every connection. `is_grease` is a single check against that pattern, applied in every CSV builder before sorting or hashing.

## QUIC Initial key derivation

To read the ClientHello inside a QUIC Initial packet, the tool derives the packet's protection keys from its Destination Connection ID, which is in the clear (`quic.rs`, `InitialKeys::client`). The schedule is HKDF (RFC 5869) with the labels and salt from RFC 9001 (v1) and RFC 9369 (v2):

```
initial_secret = HKDF-Extract(salt = INITIAL_SALT[version], ikm = DCID)
client_secret  = HKDF-Expand-Label(initial_secret, "client in", 32)
  key          = HKDF-Expand-Label(client_secret, <version key label>, 16)
  iv           = HKDF-Expand-Label(client_secret, <version iv label>, 12)
  hp           = HKDF-Expand-Label(client_secret, <version hp label>, 16)
```

The **only** thing that differs between v1 and v2 is the salt (and the expand labels), and that is deliberate: keys derived under the wrong version's salt fail the AEAD tag, which is how the tool tells a v1 packet from a v2 one without trusting a version field it has not yet authenticated. With the keys in hand, `InitialPacket::open` removes header protection and runs the AEAD open. The tag check is what identifies the *client* direction: a passive observer cannot distinguish a client Initial from a server one by any cleartext field, but only a packet the client actually protected under these keys verifies, so a successful open *is* the proof it was a client Initial.

The derivation is pinned byte-for-byte to the RFCs: `client_initial_keys_match_rfc9001_appendix_a1` and `client_initial_keys_match_rfc9369_appendix_a` in `quic.rs` derive the keys from the appendix's connection ID and assert the appendix's key, IV, and header-protection values.

## Hash choices, summarized

| Fingerprint | Hash | Why |
|-------------|------|-----|
| JA3 / JA3S | MD5, full | matches the original definition and every public JA3 feed |
| JA4 / JA4S | SHA-256, first 12 hex | the FoxIO definition; collision-resistant, shorter to read |
| JA4H / JA4X / JA4T | SHA-256, first 12 hex (sections) | same family, same truncation |

MD5 for JA3 is not a security choice and not a weakness here: a fingerprint is an identifier, not a authenticator, and reproducing the feeds' exact hashes is the requirement. JA4 moved to SHA-256 because it was a clean break and there was no installed base to stay compatible with.

## Where to go next

- [CONFORMANCE.md](./CONFORMANCE.md) lists every published vector each of these is pinned to, and the exact scope each fingerprint does and does not cover.
- [03-IMPLEMENTATION.md](./03-IMPLEMENTATION.md) shows where in the pipeline these functions are called.
