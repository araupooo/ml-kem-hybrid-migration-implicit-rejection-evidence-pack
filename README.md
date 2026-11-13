# ML-KEM Hybrid Migration and Implicit-Rejection Assessment

A public, third-party-rerunnable assessment of ML-KEM-512, ML-KEM-768,
and ML-KEM-1024 using pinned real implementations (liboqs 0.16.0,
oqs-provider 0.12.0, system OpenSSL 3.0.13), classical baselines
(X25519, P-256, P-384), and TLS 1.3-style hybrid key exchange
(RFC 10024). Every measured claim connects to a runnable script and its
unedited output; findings are severity-scored under `configs/rubric.md`.

## Headline results

- **Sizes verified exactly:** ML-KEM ek/ct match FIPS 203 Table 3
  (512: 800/768; 768: 1184/1088; 1024: 1568/1568); X25519 32 bytes
  (RFC 7748); P-256 65 / P-384 97-byte uncompressed points.
- **Implicit rejection verified:** 2100 tampered-ciphertext trials
  across all three parameter sets — decapsulation returned success
  2100/2100 times with a pseudorandom secret that never equalled the
  valid secret (0 accepted) and was deterministic (2100/2100). Control:
  600/600 valid encaps/decaps secret matches.
- **Hybrid handshakes:** X25519MLKEM768 19.3 ms mean vs X25519 16.83 ms
  (14.7% overhead); SecP384r1MLKEM1024 39.47 ms. Client key_share:
  1216 / 1665 bytes vs 32 for X25519. Zero failures in 210 group
  handshakes.
- **Downgrade:** 4/4 scenarios PASS — hybrid peers negotiate the
  hybrid group; a classical-only peer on either side negotiates X25519;
  no common group fails every handshake (negative control).
- **Headline finding (F-01, Medium):** there is no X25519 hybrid group
  for ML-KEM-1024 in RFC 10024 or oqs-provider 0.12.0 — category 5
  pairs with P-384 only.
- **Findings:** 10 total — 4 Medium, 4 Low, 2 Info
  (`docs/findings-report.md`, `findings.json`).

## Single reproduction entry point

```bash
./scripts/run_all.sh
```

That one command builds the pinned stack from `fixtures/`, runs the
KEM bench (2 runs), the implicit-rejection harness (2 runs), the hybrid
TLS handshakes (7 groups x 30 + 4 downgrade scenarios), and regenerates
all aggregates, findings, and the claim-to-evidence index. No API keys,
no private credentials, no network access beyond the vendored fixtures
(the build needs no downloads; the fixtures are in `fixtures/`).

## Fresh-environment reproduction

```bash
./scripts/clean_reproduce.sh 2>&1 | tee outputs/clean-reproduce.log
```

Copies the pack to a fresh temporary directory, runs the full suite
there, copies the fresh outputs back as `outputs/fresh-clone-*`, and
compares them against the shipped outputs (exact sizes/counts/groups;
timings within 50%). The temporary directory is intentionally kept;
its path is printed by the script and recorded in `run-manifest.md`.
See `outputs/clean-reproduce.log` for the shipped result.

## Layout

- `scripts/` — build, run, aggregate, score, reproduce, digest scripts.
- `src/` — `bench_kem.c` (KEM sizes/timings), `implicit_reject.c`
  (tampered-ciphertext harness).
- `configs/` — pinned parameters (`kem-params.md`), hybrid groups
  (`hybrid-groups.md`), severity rubric, finding definitions.
- `fixtures/` — liboqs 0.16.0 and oqs-provider 0.12.0 tarballs
  (SHA256-verified before extraction).
- `docs/` — methodology, citations, findings report, decision memo,
  claim-to-evidence index.
- `outputs/` — unedited run logs and machine-readable summaries,
  including the clean-reproduce log and fresh-clone outputs.
- `findings.json` — the scored findings (machine-readable).
- `SHA256SUMS` — digests of every file in the pack
  (`scripts/verify_digests.sh`).

## Verify integrity

```bash
./scripts/verify_digests.sh   # sha256sum -c SHA256SUMS
```

## Sources

FIPS 203, RFC 10024, RFC 9954, RFC 9846, RFC 7748, RFC 9794 — see
`docs/citations.md`. No claim rests on a source that was not fetched
and read during the build.
