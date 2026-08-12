<!-- ©AngelaMos | 2026 -->
<!-- PROVENANCE.md -->

# Test capture provenance

Every capture file in this directory is vendored, bit for bit, from the
FoxIO JA4 reference repository. None of them were created or modified here,
and the SHA-256 digests below let anyone verify that claim offline.

## Source

- Repository: <https://github.com/FoxIO-LLC/ja4>
- Commit: `4ab8e3f18f4b27e0b896c4ec2c251e20506eb87e` (fetched 2026-06-10)
- Path within the repository: `pcap/`
- Fetch URL pattern: `https://raw.githubusercontent.com/FoxIO-LLC/ja4/<commit>/pcap/<file>`

## Licensing

The FoxIO repository carries two licenses at the commit above: `LICENSE-JA4`
(BSD 3-Clause, covering the JA4 TLS client fingerprint) and `LICENSE`
(FoxIO License 1.1, covering the JA4+ suite). These capture files are the
repository's own test fixtures and are redistributed here unmodified, with
attribution, solely as test inputs for this non-commercial educational
project. See `NOTICE.md` at the project root for how the licensing split
applies to this project as a whole.

## Files

| File | SHA-256 | Why it is here |
| --- | --- | --- |
| `tls-handshake.pcapng` | `5a0c9f3d0f437e16fc68c3ce0d87998edf4f229b335c391361ed301bd22a513e` | TLS 1.3 handshake; anchors the published JA4S vector `t130200_1301_234ea6891581` |
| `tls-alpn-h2.pcap` | `8c00fd3e6c370b39dac61ad3a15c693088f74f3dbc836ee4e8f57105b1e84a91` | TLS 1.2 with ALPN h2; anchors the published JA4 vector `t12d4605h2_85626a9a5f7f_aaf95bb78ec9` and the JA4X DigiCert chain vectors |
| `tls12.pcap` | `d8c9ae8781c9bbba3a1bf5a95d7a6f309a3edd14c64a7c8adbc673d337fd5af4` | Minimal TLS 1.2 ClientHello |
| `tls-non-ascii-alpn.pcapng` | `cf1dd939619b8d65904dfd23b4f21c3255b6f513dc2e12117d5de2633d063f71` | ALPN value with non-ASCII bytes; exercises the spec-vs-reference divergence (FoxIO issue 178) |
| `chrome-cloudflare-quic-with-secrets.pcapng` | `b7c9de1238aef44d53dbe1add125a7b9e344e9063b98850c78dec23632b83942` | Chrome to Cloudflare; TCP stream anchors the published JA4 vector `t13d1516h2_8daaf6152771_e5627efa2ab1`, QUIC stream reserved for the QUIC milestone |
| `browsers-x509.pcapng` | `e05937fe5f3659f1b94b46305e419b878ba309ebcba8308750acaac704112906` | Browser certificate chains for JA4X over real captures |
| `http1-with-cookies.pcapng` | `7083ca41bcd09b21cb92e7f2d5bd09d73f25703be8555bb82642c2495eb15ef9` | Cleartext HTTP/1.1 request with cookies for JA4H over a reassembled stream |
| `gre-erspan-vxlan.pcap` | `5bbdb30a0707e21070ece3cd26068f72c34a0750d97c1e7720166cb4d0baf6d6` | Tunneled traffic; proves the decoder skips what it does not understand instead of crashing |
| `CVE-2018-6794.pcap` | `d1aa18b493bc68bf7cb367ce5fc1ee493262b47baff886bbe42533e7495d8b1d` | TCP stream evasion capture; torture input for the reassembler |
| `quic-with-several-tls-frames.pcapng` | `8d2c8a6787b942091aa63e33bde9f28c214b306dc024a66c552077ad30640e71` | QUIC initial with CRYPTO frames split across packets, reserved for the QUIC milestone |

## Verifying

```sh
cd testdata/pcap && sha256sum *.pcap *.pcapng
```

Compare the output against the table above. Any mismatch means a file no
longer matches what FoxIO published at the pinned commit.
