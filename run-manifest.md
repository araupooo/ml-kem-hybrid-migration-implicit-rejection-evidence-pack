# Run manifest

## Environment (shipped run and clean reproduction)

- Host: Linux VM, 4 CPUs, ~6 GB RAM (run_all reported 551–804 MB free at
  start). Build uses `-j2` to stay within the memory budget.
- OpenSSL 3.0.13 (system), gcc 13.3, Python 3.12.3, cmake, make, git,
  curl, rsync.
- Test certificates: ECDSA P-384 CA + server certificate, generated
  fresh per run by `scripts/make_certs.sh` (2-day validity,
  CN=localhost, test artifacts only).

## Pinned versions

| Component | Version | SHA256 / commit |
|---|---|---|
| liboqs | 0.16.0 | `162d5b510518ee5f285f82fa1f16402a885176e818bf1b1a4c3c91c9a2f01eae` (fixtures/liboqs-0.16.0.tar.gz) |
| oqs-provider | 0.12.0 | `81b1362af4276cb44afc98213cf0d8caeed8b966130844847163ad3a3b54b18f` (fixtures/oqs-provider-0.12.0.tar.gz) |
| mlkem-native (inside liboqs) | commit `0ba906cb14b1c241476134d7403a811b382ca498` | liboqs 0.16.0 docs/algorithms/kem/ml_kem.md |
| oqsprovider.so (built) | — | `35697374ad440b46a9a26281b9d53ea67c8625d51a24bc0c677a8547dfed468b` (recorded in every hybrid log) |

## Shipped run (2026-11-13 ~06:25–06:35 WIB)

`scripts/run_all.sh` (11 steps), console log
`../logs/run_all-shipped.log`. The shipped run was interrupted once by a
runtime restart during the first liboqs build (resumed incrementally),
and the harness code was fixed twice before the shipped run passed
(see `../PROGRESS.md` for the full history, including the failed
first attempts, which are preserved in `../logs/`).

- KEM bench, run 1 and run 2: `failures=0 ALL CHECKS PASSED` in both.
  All sizes match FIPS 203 Table 3 / RFC 7748 / SEC 1; controls
  100/100 per scheme per run.
- Implicit rejection, run 1 and run 2: `failures=0 ALL CHECKS PASSED`
  in both. 2100 tampered-ciphertext trials total: rc_success 2100/2100,
  ss_eq_valid 0, deterministic 2100/2100. Control 600/600.
- Hybrid TLS handshakes: 7 groups x 30, 0 failures. Means (ms):
  X25519MLKEM768 19.30, x25519_mlkem512 18.80, SecP256r1MLKEM768 30.53,
  SecP384r1MLKEM1024 39.47, X25519 16.83, P-256 17.30, P-384 22.70.
- Downgrade scenarios: 4/4 PASS (D3 re-run after a scenario-design fix;
  the failed first attempt is preserved in
  `../logs/hybrid-downgrade-client-classical-FAILED-FIRST-ATTEMPT.log`).

## Fresh-environment reproduction (clean reproduce)

`scripts/clean_reproduce.sh`, shipped log
`outputs/clean-reproduce.log`.

- **Attempt 3 (shipped): exit code 0, 0 comparison failures, 176 OK
  checks.** Fresh temporary directory `/tmp/mlkem-hybrid-repro.6kqbP3`
  — KEPT, do not delete before verification. Fresh outputs shipped as
  `outputs/fresh-clone-*` (44 files) plus
  `outputs/fresh-clone-claim-evidence-index.md`.
- Attempt 1: fresh run completed, but the comparison reported 3 false
  failures (compare script applied the tamper expectation to the
  control cases). Log preserved at
  `../logs/clean-reproduce-FAILED-FIRST-ATTEMPT.log`; the attempt-1
  temp dir was moved (not deleted) to
  `../logs/mlkem-hybrid-repro.W9PUIy/`.
- Attempt 2: fresh run aborted in step 1 — `/tmp` (512 MB tmpfs) ran
  out of space at the liboqs link step (attempt 1's 324 MB temp dir
  plus the partial build filled it). Log preserved at
  `../logs/clean-reproduce-FAILED-ATTEMPT2-NOSPACE.log`; the partial
  build dir was deleted. Limitation: a clean reproduction needs ~330 MB
  free in /tmp; ensure /tmp is clear before re-running.

## Comparison rules (fixed before the comparison)

- Exact: all key/ciphertext/secret sizes; rejection counts (tampered
  ciphertexts accepted must be 0; control secrets must equal the valid
  secret; implicit-rejection secrets deterministic); negotiated groups;
  ClientHello key_share lengths and totals; downgrade verdicts;
  finding severities.
- Tolerant (timing only, host-load noise): bench means and handshake
  means/medians within 50% relative difference.

## Limitations

See `docs/methodology.md` (host-dependent timings; loopback + test
certificate; liboqs implementation, not the FIPS reference; no
side-channel or RBG testing; only the seven listed groups measured).
