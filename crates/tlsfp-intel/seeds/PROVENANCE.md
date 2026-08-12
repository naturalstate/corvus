<!-- ©AngelaMos | 2026 -->
<!-- PROVENANCE.md -->

# Seed provenance

These three files are the intelligence the tool ships with. They are compiled
into the binary with `include_str!`, so a freshly built `tlsfp` can seed its
database with no network access. The large external source, ja4db.com, is
fetched at install time instead of bundled, because its license is unspecified
and its records are known to contain dirty entries that the importer validates
and rejects on the way in.

Each row is a fingerprint plus a label. None of these files is edited after
import beyond skipping comment lines and rows whose first field is not a
fingerprint, so the sha256 below is the exact bundled content.

## sslbl-ja3.csv

- Source: https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv
- Retrieved: 2026-06-14
- Snapshot date in the file header: 2021-08-03 (abuse.ch froze the JA3 list)
- License: CC0 1.0 (public domain dedication), so the snapshot is committable
- Records: 97 malicious JA3 hashes with a family label and first and last seen dates
- sha256: 6974182489b6e5f5f64079454b81a7219a2d82ae950f108567fa371220eb09e9

The abuse.ch SSL Blacklist carries a false positive disclaimer: a JA3 is a hash
of a TLS client library, so a benign program that links the same library lands
on the same hash. That disclaimer is the reason the matching engine scores
prevalence across sources instead of treating any single feed hit as proof.

## salesforce-osx-nix-ja3.csv

- Source: https://raw.githubusercontent.com/salesforce/ja3/master/lists/osx-nix-ja3.csv
- Retrieved: 2026-06-14
- License: BSD 3-Clause, recorded verbatim in the first record of the file
- Records: 157 benign JA3 hashes for common macOS and nix applications
- sha256: 2865b3f73a68e603dd3fa7fb56565dca70a269cda70f460ed5db03f5d724c4e1

The upstream salesforce/ja3 repository was archived on 2025-05-01. The file is
the benign half of the picture: it is what makes a collision visible. Several
hashes in this list also appear in sslbl-ja3.csv under a malware label, which
is the cleanest real demonstration that a JA3 alone cannot decide intent. The
field that names the application is quoted and can hold several comma separated
names, so the loader parses it as RFC 4180 CSV rather than splitting on commas.

Note on licensing: the research notes that seeded this project called this list
MIT. The file header itself says BSD 3-Clause, and the file is the ground truth,
so it is attributed as BSD 3-Clause here.

## curated-c2-intel.csv

- Source: hand curated for this project from named primary sources
- License: same as this repository
- Records: 17 rows covering C2 frameworks, malware families, dual-use tooling,
  and two benign browser baselines, each with a primary source in the reference
  column
- sha256: 202c0a1edc495a5149d7f6161d21adc152b1b71efdde2f5052d4767ebb0f7b66

This file fills the gaps the public feeds leave: server side JA3S for Cobalt
Strike, TrickBot, and Emotet, a JA4 for RedLine Stealer, and JA4 baselines for
Chrome over TCP and QUIC that let the engine recognise a tool that copies a
browser cipher list but not its full extension order. Where a public feed labels
one of these hashes with a different family, the divergence is written into the
reference column rather than silently reconciled.
