# Hybrid TLS 1.3 groups (pinned)

Source: RFC 10024, "Post-Quantum Traditional (PQ/T) Hybrid Key Agreement
Mechanisms for TLS 1.3", Standards Track, August 2026.
https://www.rfc-editor.org/rfc/rfc10024.txt
Framework: RFC 9954, "Hybrid Key Exchange in TLS 1.3", July 2026.
Terminology: RFC 9794. TLS 1.3: RFC 9846 (July 2026).

## Registered groups (RFC 10024, Section 7)

| Group | Value | Recommended | Client share | Server share | Shared secret |
|---|---|---|---|---|---|
| X25519MLKEM768 | 4588 (0x11EC) | Y | 1216 B (1184 ML-KEM ek + 32 X25519) | 1120 B (1088 ct + 32 X25519) | 64 B (ML-KEM first, then X25519) |
| SecP256r1MLKEM768 | 4587 (0x11EB) | N | 1249 B (65 P-256 + 1184 ML-KEM ek) | 1153 B (65 P-256 + 1088 ct) | 64 B (ECDHE first, then ML-KEM) |
| SecP384r1MLKEM1024 | 4589 (0x11ED) | N | 1665 B (97 P-384 + 1568 ML-KEM ek) | 1665 B (97 P-384 + 1568 ct) | 80 B (ECDHE first, then ML-KEM) |

## Share ordering (RFC 10024, Sections 4.1–4.3, 5)

- X25519MLKEM768: client share = ML-KEM-768 encapsulation key, then the
  X25519 ephemeral share; shared secret = ML-KEM secret, then X25519 secret.
  The group name does not follow the RFC 9954 naming convention (the share
  order is reversed) for historical reasons.
- SecP256r1MLKEM768 / SecP384r1MLKEM1024: client share = ECDHE share, then
  the ML-KEM encapsulation key; shared secret = ECDHE secret, then the
  ML-KEM secret.
- The ordering carries a certification consequence (RFC 10024, Section 5):
  for X25519MLKEM768 the ML-KEM implementation must be certified, whereas
  for the SecP groups the ECDHE implementation must be certified.

## Obsoleted groups (RFC 10024, Section 7.4)

- X25519Kyber768Draft00 (25497) and SecP256r1Kyber768Draft00 (25498) are
  obsoleted by RFC 10024. Pre-standard Kyber768 code points must not be
  offered to a standards-conformant peer.

## Provider mapping (oqs-provider 0.12.0, ALGORITHMS.md)

| oqs-provider group name | TLS code point | Notes |
|---|---|---|
| `SecP256r1MLKEM512` | 0x11E9 | ML-KEM-512 + P-256 (not in RFC 10024) |
| `x25519_mlkem512` | 0x11EA | Pre-standard naming; ML-KEM-512 + X25519 (not in RFC 10024) |
| `bp256_mlkem512` | 65056 | ML-KEM-512 + Brainpool P-256 (not in RFC 10024) |
| `p384_mlkem768` | 0x2F4C | ML-KEM-768 + P-384 (not in RFC 10024) |
| `x448_mlkem768` | 0x2FB7 | ML-KEM-768 + X448 (not in RFC 10024) |
| `bp384_mlkem768` | 65057 | ML-KEM-768 + Brainpool P-384 (not in RFC 10024) |
| `X25519MLKEM768` | 0x11EC | RFC 10024, Recommended |
| `SecP256r1MLKEM768` | 0x11EB | RFC 10024 |
| `p521_mlkem1024` | 0x2F4D | ML-KEM-1024 + P-521 (not in RFC 10024) |
| `SecP384r1MLKEM1024` | 0x11ED | RFC 10024 |
| `bp512_mlkem1024` | 65058 | ML-KEM-1024 + Brainpool P-512 (not in RFC 10024) |

## Key finding: no X25519 hybrid group for ML-KEM-1024

oqs-provider 0.12.0 defines **no `X25519MLKEM1024` group**. The X25519
hybrid ladder stops at ML-KEM-768; the only ML-KEM-1024 hybrid group in
both RFC 10024 and this provider version pairs with P-384
(SecP384r1MLKEM1024). A migration plan that assumes a uniform X25519
ladder across all three parameter sets is wrong for category 5. See
finding F-01.

## Protocol checks (RFC 10024, Section 4.2)

- The server MUST perform the encapsulation-key check of FIPS 203
  Section 7.2 on the client's encapsulation key and abort with an
  `illegal_parameter` alert if it fails.
- The client MUST check the ciphertext length against the selected group
  and abort with an `illegal_parameter` alert if it fails.
- If ML-KEM decapsulation fails for any other reason, the connection MUST
  be aborted with an `internal_error` alert.
- Both peers MUST process the ECDHE part including all validity checks
  (including the all-zero shared-secret check for X25519) and abort with
  an `illegal_parameter` alert if any fails.
