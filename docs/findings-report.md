# Findings report

10 findings: 4 Medium, 4 Low, 2 Info. Scored under configs/rubric.md (severity = impact x likelihood). Every finding lists its evidence; measured numbers are quoted from the outputs and can be re-derived by running the pack.

## F-01 — No X25519 hybrid group exists for ML-KEM-1024 in oqs-provider 0.12.0

**Severity: Medium** (score 12 = impact 3 x likelihood 4)

**Rationale.** A migration plan that assumes a uniform X25519 hybrid ladder across all three ML-KEM parameter sets breaks at the highest security category: the only ML-KEM-1024 hybrid group pairs with P-384 (SecP384r1MLKEM1024, 0x11ED). An operator that standardises on X25519 hybrids must either accept ML-KEM-768 (category 3) or switch elliptic curve at category 5, which changes the FIPS-certification story (RFC 10024 section 5: for the SecP groups the ECDHE implementation must be certified, whereas for X25519MLKEM768 the ML-KEM implementation must be certified).

**Remediation.** Decide the category-5 hybrid explicitly in the migration plan: either adopt SecP384r1MLKEM1024 (and confirm P-384 certification coverage) or document ML-KEM-768 as the ceiling for X25519 hybrids. Do not write migration code that assumes an X25519MLKEM1024 group name exists.

**Evidence.** oqs-provider 0.12.0 ALGORITHMS.md lists TLS groups x25519_mlkem512 (0x11EA) and X25519MLKEM768 (0x11EC) but no X25519MLKEM1024; RFC 10024 section 7 registers exactly three hybrid groups and pairs ML-KEM-1024 only with secp384r1. Measured hybrid handshake for SecP384r1MLKEM1024: mean 39.47 ms, negotiated group SecP384r1MLKEM1024, key_exchange_len 1665 bytes (see outputs/hybrid-summary.csv).

## F-04 — Implicit rejection is silent: tampered ciphertexts return success with a pseudorandom secret

**Severity: Medium** (score 9 = impact 3 x likelihood 3)

**Rationale.** ML-KEM decapsulation never signals that a ciphertext was rejected: per FIPS 203 section 6 (Algorithm 18) a failed re-encryption check yields K' = J(z || c) and the API still returns success. A caller that treats decapsulation success as evidence the peer is authentic is misled; the mismatch only surfaces later (e.g. a TLS Finished verification failure). The behaviour is by design, but it is a sharp edge for anyone integrating the KEM directly.

**Remediation.** Never treat decapsulation success as authentication. Integrate ML-KEM through a protocol that verifies the derived secret (e.g. TLS 1.3 Finished), and test that path with tampered ciphertexts, not with the KEM return code alone.

**Evidence.** Measured across all three parameter sets, 2100 tampered-ciphertext trials (flip_first_bit, flip_mid_bit, flip_last_bit, flip_byte, all_zero_ct, random_ct, wrong_sk): rc_success 2100/2100, ss_eq_valid 0 (zero tampered ciphertexts accepted as valid), deterministic 2100/2100. Control: 600/600 valid encaps/decaps secret matches (see outputs/rejection-summary.json).

## F-05 — The decapsulation API takes no ciphertext length, so the FIPS 203 length check is the caller's job

**Severity: Medium** (score 9 = impact 3 x likelihood 3)

**Rationale.** Two distinct failure modes share the same API, and only one of them is visible to the caller: a ciphertext of the wrong length is rejected by an explicit check that lives in the calling protocol (FIPS 203 section 7.3, RFC 10024 section 4.2), while a well-formed but invalid ciphertext returns success with an implicit-rejection secret. A caller that forwards an unchecked buffer to decaps violates the API contract, and a caller that treats decapsulation success as authentication is misled by the silent case.

**Remediation.** Check the ciphertext length against the parameter set before calling decaps, and treat a decapsulation success as unauthenticated until the protocol verifies the secret. Do not pass caller-controlled buffers to decaps without a length check.

**Evidence.** liboqs 0.16.0 API (oqs/kem.h): OQS_KEM_decaps(kem, shared_secret, ciphertext, secret_key) takes no length argument and reads exactly kem->length_ciphertext bytes, so the FIPS 203 section 7.3 ciphertext-length check is the caller's responsibility, not the library's. RFC 10024 section 4.2 places the check one layer up: the TLS client MUST check the ciphertext length and abort with illegal_parameter. Measured in the same harness: well-formed tampered ciphertexts returned success in 2100/2100 trials with zero secrets equal to the valid secret (see outputs/rejection-summary.json). This finding rests on the API signature and the standards text for the length check, and on measurement for the silent-rejection half.

## F-10 — Encapsulation randomness is recoverable by the decapsulator, so a weak random-bit generator compromises both algorithms

**Severity: Medium** (score 8 = impact 4 x likelihood 2)

**Rationale.** During encapsulation the randomness m is encrypted and recovered exactly by the decapsulator (FIPS 203 Algorithms 17 and 20, Algorithm 18). Information m carries about the generator's other outputs is therefore exposed to the peer, and if the same insecure generator feeds both algorithms, a disclosure by one affects the other. Modern operating-system CSPRNGs make this unlikely in practice, which is why likelihood is low — but the consequence is total, so the finding is Medium.

**Remediation.** Generate encapsulation randomness and ephemeral scalars only from a cryptographically secure random-bit generator (FIPS 203 RBG guidance, RFC 9846 Appendix C.1); do not share a generator instance between the ML-KEM and ECDHE components without the protections in RFC 8937.

**Evidence.** RFC 10024 section 6 (security considerations) and FIPS 203 Algorithms 17, 18, 20. This finding rests on the standards text and the structure of the KEM, not on a measurement; no weak-generator condition was tested.

## F-02 — Hybrid ClientHello key_share is an order of magnitude larger than X25519

**Severity: Low** (score 6 = impact 2 x likelihood 3)

**Rationale.** Larger ClientHello messages increase handshake bytes on the wire and can interact with middleboxes, MTU limits, and UDP-based transports. The cost is measurable and predictable, not a security failure.

**Remediation.** Budget ~1.2-1.7 KB of client key_share per hybrid handshake in capacity planning; verify middlebox and load-balancer handling of large ClientHello messages before rollout.

**Evidence.** Measured ClientHello key_share key_exchange_len: X25519MLKEM768 1216 bytes vs X25519 32 bytes (38x); SecP384r1MLKEM1024 1665 bytes. ClientHello total bytes: X25519MLKEM768 1378 vs X25519 202 (see outputs/hybrid-summary.csv). Sizes match RFC 10024 section 4.1 exactly (1216 = 1184 + 32; 1665 = 97 + 1568).

## F-03 — Hybrid handshake latency overhead over X25519 is measurable but small in absolute terms

**Severity: Low** (score 6 = impact 2 x likelihood 3)

**Rationale.** The hybrid handshake costs more wall-clock time than the classical fallback, mostly from ML-KEM key generation/encapsulation and larger messages. The absolute overhead is a few milliseconds on this host, so it is a capacity-planning item, not a blocker.

**Remediation.** Use the measured means as the latency budget for hybrid handshakes; re-measure on production-class hardware before committing to a service-level target.

**Evidence.** Measured mean handshake latency (30 handshakes each, s_client spawn included): X25519MLKEM768 19.3 ms vs X25519 16.83 ms (14.7% overhead); SecP384r1MLKEM1024 39.47 ms; x25519_mlkem512 18.8 ms (see outputs/hybrid-summary.csv). KEM-level timings: ML-KEM-768 encaps mean 20.13 us, decaps 25.71 us; X25519 derive 54.02 us (see outputs/bench-kem.csv).

## F-06 — Only X25519MLKEM768 is RFC 10024 Recommended; pre-standard draft groups are obsolete

**Severity: Low** (score 6 = impact 2 x likelihood 3)

**Rationale.** Interoperability risk: peers or configurations that offer the pre-standard X25519Kyber768Draft00 code point (25497) or the non-Recommended SecP groups will fail or be refused by a standards-conformant peer. The Recommended flag is the practical default for deployment.

**Remediation.** Offer X25519MLKEM768 by default; remove draft Kyber768 code points from client and server configurations.

**Evidence.** RFC 10024 section 7: X25519MLKEM768 value 4588 (0x11EC), Recommended Y; SecP256r1MLKEM768 4587 (0x11EB) and SecP384r1MLKEM1024 4589 (0x11ED), Recommended N; X25519Kyber768Draft00 (25497) and SecP256r1Kyber768Draft00 (25498) are obsoleted by RFC 10024. Measured handshake for X25519MLKEM768 negotiated successfully (see outputs/hybrid-summary.csv). This finding rests on the standards text, not on a measurement.

## F-09 — Server CPU per hybrid handshake is higher than classical, dominated by ML-KEM operations

**Severity: Low** (score 6 = impact 2 x likelihood 3)

**Rationale.** Server-side CPU is the scaling cost of a hybrid rollout: every handshake pays ML-KEM key generation, encapsulation, and decapsulation on top of the classical exchange. On this host the cost is a fraction of a millisecond per handshake, so it matters for high-connection-rate servers, not for typical ones.

**Remediation.** Provision server CPU using the measured per-handshake figures; re-measure under production load before setting connection-rate limits.

**Evidence.** Measured server CPU per handshake (procstat utime+stime delta over 30 handshakes): X25519MLKEM768 3.0 ms vs X25519 2.667 ms; SecP384r1MLKEM1024 7.667 ms (see outputs/hybrid-summary.csv). KEM-level: ML-KEM-768 keygen mean 20.92 us, encaps 20.13 us, decaps 25.71 us (see outputs/bench-kem.csv).

## F-07 — ML-KEM-768 is the FIPS 203 recommended default; parameter-set choice is a security-category choice

**Severity: Info** (score 2 = impact 1 x likelihood 2)

**Rationale.** The three parameter sets are NIST security categories 1, 3, and 5. Choosing 512 where category 3 is required under-provisions the exchange; choosing 1024 where 768 suffices pays the larger key/ciphertext and latency cost for no required benefit. FIPS 203 names ML-KEM-768 as the recommended default.

**Remediation.** Default to ML-KEM-768 unless a written requirement demands category 1 (constrained) or category 5 (high-security); record the category decision in the migration plan.

**Evidence.** FIPS 203 Table 2 (parameters) and Table 3 (sizes): ML-KEM-512 ek 800 / ct 768 (category 1), ML-KEM-768 ek 1184 / ct 1088 (category 3, recommended default), ML-KEM-1024 ek 1568 / ct 1568 (category 5). All sizes verified by measurement: see outputs/bench-kem.csv (SIZE lines, all OK).

## F-08 — Hybrid share ordering differs by group: ML-KEM secret first for X25519, ECDHE first for SecP groups

**Severity: Info** (score 3 = impact 1 x likelihood 3)

**Rationale.** The ordering is not uniform, and it carries a certification consequence (RFC 10024 section 5): for X25519MLKEM768 the ML-KEM implementation must be certified, while for the SecP groups the ECDHE implementation must be certified. An implementer who assumes one ordering will produce an incompatible or non-compliant combiner.

**Remediation.** Implement the shared-secret concatenation per group from RFC 10024 section 4.3, not from a single assumed template; verify the ordering against a known-answer test for each group before deployment.

**Evidence.** RFC 10024 sections 4.3 and 5: X25519MLKEM768 shared secret is ML-KEM secret followed by X25519 secret (64 bytes); SecP256r1MLKEM768 and SecP384r1MLKEM1024 are ECDHE secret followed by ML-KEM secret (64 and 80 bytes). Measured key_exchange sizes are consistent with the specified orderings (see outputs/hybrid-summary.csv). This finding rests on the standards text, not on a measurement.
