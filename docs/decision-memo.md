# Decision memo — ML-KEM hybrid migration

## Recommendation

1. **Default hybrid group: X25519MLKEM768 (0x11EC).** It is the only
   RFC 10024 group marked Recommended, it is the only X25519 hybrid at
   category 3, and it measured the lowest hybrid handshake cost:
   19.3 ms mean vs 16.83 ms for plain X25519 (14.7% overhead, 30
   handshakes each, loopback, s_client spawn included), with a 1216-byte
   client key_share.
2. **Default parameter set: ML-KEM-768.** FIPS 203 names it the
   recommended default (category 3). Measured: keygen 20.92 us, encaps
   20.13 us, decaps 25.71 us (means of two 200-iteration runs);
   ek 1184 / ct 1088 bytes.
3. **Decide category 5 explicitly before writing migration code.**
   There is no X25519 hybrid group for ML-KEM-1024 in RFC 10024 or in
   oqs-provider 0.12.0 (finding F-01). The only ML-KEM-1024 hybrid is
   SecP384r1MLKEM1024 (39.47 ms mean handshake, 1665-byte shares, P-384
   keygen 1131.31 us / derive 1113.70 us dominate the cost). Either
   adopt SecP384r1MLKEM1024 (and confirm P-384 certification coverage —
   for the SecP groups the ECDHE implementation must be certified,
   RFC 10024 section 5) or document ML-KEM-768 as the ceiling for
   X25519 hybrids.
4. **Do not treat decapsulation success as authentication.**
   Implicit rejection is silent by design (FIPS 203, Algorithm 18):
   across 2100 tampered-ciphertext trials (all three parameter sets),
   decapsulation returned success 2100/2100 times with a pseudorandom
   secret that never equalled the valid secret (0 accepted) and was
   deterministic for a fixed (key, ciphertext) pair (2100/2100).
   Authenticate at the protocol layer (e.g. TLS 1.3 Finished).
5. **Check the ciphertext length before calling decaps.** The liboqs
   decapsulation API takes no length argument, so the FIPS 203
   section 7.3 length check is the caller's job (finding F-05); RFC 10024
   section 4.2 requires the TLS client to perform it.
6. **Remove pre-standard draft code points** (X25519Kyber768Draft00,
   25497) from all configurations; they are obsoleted by RFC 10024
   (finding F-06).
7. **Budget ~1.2–1.7 KB of client key_share per hybrid handshake**
   (X25519MLKEM768: 1216 bytes; SecP384r1MLKEM1024: 1665 bytes; vs 32
   bytes for X25519) and verify middlebox handling of large ClientHello
   messages before rollout (finding F-02).

## What was measured

- KEM sizes: all match FIPS 203 Table 3 (ML-KEM) and RFC 7748 (X25519)
  exactly, asserted at runtime in both runs.
- KEM timings (mean of two 200-iteration runs, microseconds):

  | Operation | ML-KEM-512 | ML-KEM-768 | ML-KEM-1024 | X25519 | P-256 | P-384 |
  |---|---|---|---|---|---|---|
  | keygen | 13.10 | 20.92 | 25.52 | 52.49 | 19.20 | 1131.31 |
  | encaps | 14.34 | 20.13 | 26.30 | — | — | — |
  | decaps | 17.19 | 25.71 | 34.75 | — | — | — |
  | derive | — | — | — | 54.02 | 73.66 | 1113.70 |

  (X25519 / P-256 / P-384 use keygen + derive; ML-KEM uses
  keygen + encaps + decaps. P-384 key generation dominates its cost.)
- Hybrid TLS 1.3 handshakes (30 each, mean ms): X25519MLKEM768 19.3,
  x25519_mlkem512 18.8, SecP256r1MLKEM768 30.53, SecP384r1MLKEM1024
  39.47, X25519 16.83, P-256 17.3, P-384 22.7. Zero handshake failures
  in all 210 group handshakes.
- Downgrade behaviour (10 handshakes each, 4/4 PASS): both peers hybrid
  negotiates X25519MLKEM768; server classical-only with a client
  offering hybrid+classical negotiates X25519; client classical-only
  with a server offering hybrid+classical negotiates X25519; no common
  group fails every handshake (negative control, as expected).
- Server CPU per handshake: X25519MLKEM768 3.0 ms vs X25519 2.667 ms;
  SecP384r1MLKEM1024 7.667 ms.

## Risks and open items

- Timings are host-dependent (4-CPU shared VM, loopback, test ECDSA
  P-384 certificate). Re-measure on production-class hardware before
  committing to a latency or CPU budget.
- The assessment does not test side-channel resistance, constant-time
  behaviour, or the random-bit generator. Finding F-10 (encapsulation
  randomness is recoverable by the decapsulator) rests on the standards
  text: use a cryptographically secure RBG and do not share a generator
  instance between the ML-KEM and ECDHE components without the
  protections in RFC 8937.
- Only the seven groups listed above were measured. `p521_mlkem1024`
  and `SecP256r1MLKEM512` exist in oqs-provider 0.12.0 but are not in
  RFC 10024 and were not measured.

## Sources

FIPS 203 (DOI 10.6028/NIST.FIPS.203), RFC 10024, RFC 9954, RFC 9846,
RFC 7748, RFC 9794. Full citations: `docs/citations.md`.
Reproduction: `scripts/run_all.sh`; fresh-environment reproduction:
`scripts/clean_reproduce.sh` (see `run-manifest.md`).
