# ML-KEM parameters (pinned)

Source: NIST FIPS 203, "Module-Lattice-Based Key-Encapsulation Mechanism
Standard", DOI 10.6028/NIST.FIPS.203, August 2024.
Table 2 (parameters) and Table 3 (key and ciphertext sizes).
PDF: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf

## Parameters (FIPS 203 Table 2)

| Parameter | ML-KEM-512 | ML-KEM-768 | ML-KEM-1024 |
|---|---|---|---|
| n (polynomial degree) | 256 | 256 | 256 |
| q (modulus) | 3329 | 3329 | 3329 |
| k (module dimension) | 2 | 3 | 4 |
| eta1 (noise, keygen) | 3 | 2 | 2 |
| eta2 (noise, encaps) | 2 | 2 | 2 |
| du (ciphertext compression, u) | 10 | 10 | 11 |
| dv (ciphertext compression, v) | 4 | 4 | 5 |
| Random bits for key generation | 128 | 192 | 256 |
| NIST security category | 1 | 3 | 5 |

## Sizes in bytes (FIPS 203 Table 3)

| Field | ML-KEM-512 | ML-KEM-768 | ML-KEM-1024 |
|---|---|---|---|
| Encapsulation key (ek) | 800 | 1184 | 1568 |
| Decapsulation key (dk) | 1632 | 2400 | 3168 |
| Ciphertext (ct) | 768 | 1088 | 1568 |
| Shared secret (K) | 32 | 32 | 32 |

## Notes

- ML-KEM-768 is the recommended default (FIPS 203, Section 1 and the
  parameter-set discussion): category 3, equivalent in strength to AES-192.
- All three parameter sets are IND-CCA2 secure (FIPS 203, Section 1).
- liboqs 0.16.0 reports the same sizes (docs/algorithms/kem/ml_kem.md) and
  the same claimed NIST levels; the harness asserts every size at runtime
  (see `src/bench_kem.c`, SIZE lines in the bench logs).

## Classical baselines (measured, asserted at runtime)

| Scheme | Public key | Secret key | Shared secret | Source |
|---|---|---|---|---|
| X25519 | 32 | 32 | 32 | RFC 7748, Section 5 |
| P-256 (secp256r1) | 65 (uncompressed point) | 32 (scalar, not printed) | 32 | SEC 1 / RFC 8446 |
| P-384 (secp384r1) | 97 (uncompressed point) | 48 (scalar, not printed) | 48 | SEC 1 / RFC 8446 |

## Pinned implementation versions

| Component | Version | Source |
|---|---|---|
| liboqs | 0.16.0 | `fixtures/liboqs-0.16.0.tar.gz`, SHA256 `162d5b510518ee5f285f82fa1f16402a885176e818bf1b1a4c3c91c9a2f01eae` |
| oqs-provider | 0.12.0 | `fixtures/oqs-provider-0.12.0.tar.gz`, SHA256 `81b1362af4276cb44afc98213cf0d8caeed8b966130844847163ad3a3b54b18f` |
| mlkem-native (inside liboqs) | commit `0ba906cb14b1c241476134d7403a811b382ca498` | liboqs 0.16.0 `docs/algorithms/kem/ml_kem.md` |
| OpenSSL (system) | 3.0.13 | measured at runtime (`openssl version`) |
| C compiler | gcc 13.3 | measured at runtime |
