# Methodology

## Goal

Measure, on one pinned and reproducible stack, the cost and behaviour of
migrating TLS 1.3 key exchange to ML-KEM hybrids: key and ciphertext
sizes, operation timings, handshake latency and message sizes, downgrade
behaviour when a peer lacks ML-KEM, and the observable behaviour of ML-KEM
implicit rejection under tampered ciphertexts. Every claim in this
assessment is produced by a script in `scripts/` or `src/` and recorded
in an unedited output file under `outputs/`.

## Stack (pinned)

- liboqs 0.16.0 (optimized build, `OQS_OPT_TARGET=auto`), built from
  `fixtures/liboqs-0.16.0.tar.gz` (SHA256 verified before extraction).
- oqs-provider 0.12.0, built against that liboqs from
  `fixtures/oqs-provider-0.12.0.tar.gz` (SHA256 verified before extraction).
- System OpenSSL 3.0.13, gcc 13.3, Python 3.12.3, on a 4-CPU Linux VM.
- Test certificates: ECDSA P-384 CA + server certificate, generated fresh
  by `scripts/make_certs.sh` (2-day validity, CN=localhost). The
  post-quantum part of this assessment is the hybrid key exchange, not the
  signature: OpenSSL 3.0.13 cannot serve an ML-DSA certificate, which was
  established in the earlier lattice-integration assessment and is not
  re-tested here.

## Measurements

1. **KEM sizes and timings** (`src/bench_kem.c`, N=200 per operation,
   two independent runs). Sizes are asserted against FIPS 203 Table 3
   (ML-KEM), RFC 7748 (X25519), and SEC 1 uncompressed-point sizes (P-256
   65, P-384 97); any mismatch fails the run. Timing reports mean/min/max
   microseconds and operations per second for keygen, encaps, and decaps
   (ML-KEM) and keygen and derive (X25519, P-256/P-384 via
   OpenSSL EVP). A control of 100 encaps/decaps round trips per scheme
   verifies shared-secret equality.
2. **Implicit rejection** (`src/implicit_reject.c`, N=50 per case, two
   independent runs). For each of ML-KEM-512/768/1024: a control (valid
   encaps/decaps), seven tamper cases (one bit flipped at the first,
   middle, and last ciphertext byte; one whole byte flipped; all-zero
   ciphertext; fresh random ciphertext; decapsulation with a different
   keypair's key). For each trial the harness records the decapsulation return
   code, whether the resulting secret equals the valid secret, and whether
   decapsulating the same tampered ciphertext twice yields the same
   secret. The expected outcome for well-formed tampered ciphertexts is
   success with a pseudorandom secret that is never the valid secret and
   is deterministic for a fixed (decapsulation key, ciphertext) pair
   (FIPS 203, Algorithm 18). The control case (valid encaps/decaps) must
   reproduce the sender's secret in every trial. Note on the
   ciphertext-length check: the liboqs decapsulation API takes no length
   argument (OQS_KEM_decaps has no length parameter), so the FIPS 203
   Section 7.3 length check is the caller's responsibility; the check is
   enforced one layer up by the TLS client (RFC 10024, Section 4.2).
   Passing a short buffer to decaps would be an out-of-bounds read, so no
   truncated-ciphertext runtime case is included; the API-contract
   observation is documented as finding F-05 instead.
3. **Hybrid TLS 1.3 handshakes** (`scripts/run_hybrid.sh`, 30 timed full
   handshakes per group). Real `openssl s_server` / `s_client` sessions
   through the oqs-provider, with the negotiated group read from the
   `Server Temp Key` line and the ClientHello key_share size parsed from
   a `-msg` trace. Server CPU time and RSS are sampled from `/proc`
   before and after the handshake loop. Groups measured:
   X25519MLKEM768, x25519_mlkem512, SecP256r1MLKEM768,
   SecP384r1MLKEM1024, X25519, P-256, P-384. Handshake times include the
   `s_client` process spawn (~2–4 ms) and are comparable across groups
   run with the same harness.
4. **Downgrade scenarios** (10 handshakes each): both peers hybrid;
   server classical-only with client offering hybrid+classical; client
   classical-only with server offering hybrid; and a negative control
   with no common group (client X25519MLKEM768 only, server
   SecP384r1MLKEM1024 only), which must fail every handshake.
5. **Aggregation and scoring** (`scripts/aggregate.py`,
   `scripts/score_findings.py`, `scripts/make_index.py`). The aggregates
   are parsed from the unedited logs; the findings are scored under
   `configs/rubric.md`; the claim-to-evidence index is regenerated from
   the aggregates so its numbers always match the outputs.

## Fresh-environment reproduction

`scripts/clean_reproduce.sh` copies the pack (excluding `work/` and
`outputs/`) to a fresh temporary directory, runs the full suite there
with the `fresh-clone-` output prefix, copies the fresh outputs back into
`outputs/`, and compares them with `scripts/compare_reproduce.py`.
Comparison rules (fixed before the comparison): sizes, rejection counts,
negotiated groups, key_share lengths, downgrade verdicts, and finding
severities must match exactly; timings must agree within 50% (host-load
noise). The temporary directory is intentionally kept after the run; its
path is printed by the script and recorded in `run-manifest.md`.

## Limitations

- Timings are host-dependent (4-CPU VM, shared host). Absolute
  microsecond/millisecond figures are not portable; relative comparisons
  between groups measured with the same harness on the same host are.
- The handshake measurements use a loopback connection and a test
  ECDSA P-384 certificate; network latency and real certificate chains
  are not included.
- The implicit-rejection harness tests the liboqs implementation of
  FIPS 203, not the FIPS 203 reference implementation; the observable
  behaviour is the same by design, but the internal `z` value and the
  implicit-rejection flag are not observable (and per FIPS 203 Section 3.3
  must not be exposed), so the harness reports only return codes, secret
  equality, and determinism.
- Per-vote and per-connection timing distributions are not analysed
  beyond mean/median/min/max/stdev; no statistical significance testing
  is performed.
- The assessment does not test side-channel resistance, constant-time
  behaviour, or the random-bit generator: the RBG finding (F-10) rests on
  the standards text, not on a measurement, and is labelled as such.
- Only the TLS groups listed above were measured. `p521_mlkem1024` and
  `SecP256r1MLKEM512` exist in oqs-provider 0.12.0 but are not in
  RFC 10024 and were not measured.
