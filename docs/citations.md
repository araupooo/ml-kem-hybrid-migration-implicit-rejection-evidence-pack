# Primary sources

Every spec-derived claim in this assessment cites one of the sources
below. Secondary sources (blog posts, vendor pages) were not used for
any claim.

## Standards

- NIST FIPS 203, "Module-Lattice-Based Key-Encapsulation Mechanism
  Standard", DOI 10.6028/NIST.FIPS.203, August 2024.
  https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf
  Used for: ML-KEM parameters (Table 2), key/ciphertext sizes (Table 3),
  security categories, implicit rejection (Section 6, Algorithm 18),
  input checks (Sections 7.2, 7.3), the secrecy of the implicit-rejection
  flag (Section 3.3), and the ML-KEM-768 recommended default.
- RFC 10024, "Post-Quantum Traditional (PQ/T) Hybrid Key Agreement
  Mechanisms for TLS 1.3", Standards Track, August 2026.
  https://www.rfc-editor.org/rfc/rfc10024.txt
  Used for: the three hybrid groups and their code points (Section 7),
  client/server share sizes and orderings (Sections 4.1–4.3), the
  certification consequence of the ordering (Section 5), the RNG
  disclosure consideration (Section 6), the protocol checks
  (Section 4.2), and the obsoleted draft groups (Section 7.4).
- RFC 9954, "Hybrid Key Exchange in TLS 1.3", July 2026.
  https://www.rfc-editor.org/rfc/rfc9954.txt
  Used for: the hybrid key-exchange framework that RFC 10024 applies.
- RFC 9846, "The Transport Layer Security (TLS) Protocol Version 1.3",
  July 2026. https://www.rfc-editor.org/rfc/rfc9846.txt
  Used for: TLS 1.3 as the protocol context (successor to RFC 8446).
- RFC 7748, "Elliptic Curves for Security", January 2016.
  https://www.rfc-editor.org/rfc/rfc7748.txt
  Used for: X25519 32-byte keys and shared secrets.
- RFC 9794, "Terminology for Post-Quantum Traditional Hybrid Schemes",
  June 2025. https://www.rfc-editor.org/rfc/rfc9794.txt
  Used for: hybrid-scheme terminology.
- NIST SP 800-227, "Recommendations for Key-Encapsulation Mechanisms",
  DOI 10.6028/nist.sp.800-227, September 2025.
  Referenced by RFC 10024 Section 5 for hybrid KEM design guidance; not
  independently relied on for any measured claim.
- RFC 8937, "Randomness Improvements for Security Protocols", October
  2020. Referenced by RFC 10024 Section 6; cited in finding F-10's
  remediation.

## Implementation sources (in-tarball, pinned)

- liboqs 0.16.0, `docs/algorithms/kem/ml_kem.md` (inside
  `fixtures/liboqs-0.16.0.tar.gz`): ML-KEM sizes, IND-CCA2 claim, NIST
  levels, mlkem-native commit `0ba906cb14b1c241476134d7403a811b382ca498`.
- oqs-provider 0.12.0, `ALGORITHMS.md` (inside
  `fixtures/oqs-provider-0.12.0.tar.gz`): the TLS group table, including
  the absence of an X25519MLKEM1024 group.

## How the sources were used

- Sizes were taken from FIPS 203 Table 3 and RFC 7748, then asserted at
  runtime by `src/bench_kem.c`; the logs show `OK` for every size.
- Hybrid share sizes were taken from RFC 10024 Section 4, then measured
  from live `-msg` traces; the measured key_exchange_len values match
  the RFC exactly.
- Implicit-rejection expectations were taken from FIPS 203 Algorithm 18
  and Section 7.3, then tested by `src/implicit_reject.c`.
- No claim in this assessment rests on a source that was not fetched and
  read during the build. Where a finding rests on standards text rather
  than a measurement, the finding says so.
