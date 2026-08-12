# Third-party fingerprint algorithm licensing

This project implements several published TLS fingerprinting algorithms. They do
not all carry the same license, and the split matters. This notice records what
applies to what.

## Upstream

Corvus is a fork of `tlsfp` by Carter Perez, from the Cybersecurity-Projects
collection at `https://github.com/CarterPerez-dev/Cybersecurity-Projects`
(`PROJECTS/intermediate/ja3-ja4-tls-fingerprinting`). All code under `crates/`
originates there and remains their copyright. Corvus is a derivative work
distributed under the same license.

## The code

Everything under `crates/` is licensed under the GNU AGPL 3.0 (see `LICENSE`).
No source code from any reference implementation was copied. The algorithms were
implemented from their published specifications.

## JA3 and JA3S

JA3 and JA3S were created by John Althouse, Jeff Atkinson, and Josh Atkins at
Salesforce and released under the BSD 3-Clause license at
`https://github.com/salesforce/ja3`. The algorithm is free to implement and use.
That repository was archived in May 2025 and is no longer maintained.

## JA4 (TLS client fingerprint)

JA4, the TLS client fingerprint, is licensed by FoxIO under the BSD 3-Clause
license, separately from the rest of the JA4+ suite. FoxIO has stated it holds
no patents on JA4 TLS client fingerprinting. The canonical license text is at
`https://github.com/FoxIO-LLC/ja4/blob/main/LICENSE-JA4`. JA4 may be implemented
and used without restriction.

## JA4S, JA4H, JA4X, JA4T (the rest of the JA4+ suite)

The remaining JA4+ fingerprints implemented here are licensed under the FoxIO
License 1.1, and the methods are patent pending. The canonical license text is
at `https://github.com/FoxIO-LLC/ja4/blob/main/LICENSE`.

The FoxIO License 1.1 grants the right to use and modify these methods for non
commercial purposes, which it defines to include personal use, academic research
and development, and internal evaluation. It excludes any use for which a fee is
charged and excludes providing the methods as a hosted or managed service to
others.

This project is a free, open source, educational tool. It is not sold, not
monetized, and not offered as a service. It therefore falls within the non
commercial grant of the FoxIO License 1.1. Anyone who forks this project and
intends to monetize it, or to offer it as a hosted service, must obtain an OEM
license from FoxIO for the JA4+ methods first.

This is the same boundary that led the Suricata project to ship only JA4 and not
the rest of the JA4+ suite: their GPL licensing is incompatible with the FoxIO
License 1.1. Corvus ships the full suite under the non commercial grant. It is a
personal, non commercial learning project: not sold, not monetized, and not
offered as a hosted service.

## Seeded fingerprint data

The intelligence database is seeded from public sources with their own terms:

- abuse.ch SSLBL JA3 feed is released under CC0 and a snapshot may be
  redistributed. Its known limitation, that the fingerprints have not been
  tested against benign traffic and may produce false positives, is surfaced in
  the tool output.
- The salesforce/ja3 application lists are MIT licensed.
- The ja4db.com database has no stated redistribution license, so it is fetched
  at install time rather than bundled, and entries are validated on import.
