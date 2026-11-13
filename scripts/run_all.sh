#!/bin/bash
# run_all.sh — run the full ML-KEM hybrid migration assessment end to end.
# Usage: run_all.sh [prefix]
#   prefix: "" (shipped run) or "fresh-clone-" (clean reproduction inside a
#   fresh copy of the pack). Output files are written to
#   <pack>/outputs/<prefix>* so a reproduction never overwrites the shipped
#   outputs.
# Steps: build pinned stack -> generate test certs -> bench KEMs (2 runs)
# -> implicit-rejection harness (2 runs) -> hybrid TLS handshakes
# (7 groups x 30 + 4 downgrade scenarios) -> aggregate -> score findings
# -> claim-to-evidence index.
# Exit code is non-zero if any step fails; each step's unedited console
# output is captured in outputs/<prefix>*.log.
set -eu
set -o pipefail
PACK="$(cd "$(dirname "$0")/.." && pwd)"
PREFIX="${1:-}"
OUT="$PACK/outputs"
WORK="$PACK/../work"
mkdir -p "$OUT" "$WORK"

echo "run_all: pack=$PACK prefix='$PREFIX' date=$(date -u '+%Y-%m-%d %H:%M:%S UTC')"
echo "run_all: nproc=$(nproc) free=$(free -m | awk '/^Mem:/ {print $7}') MB available"

echo "=== step 1: build pinned stack ==="
"$PACK/scripts/build_all.sh" "$WORK"

echo "=== step 2: test certificates ==="
TLS_CERTDIR="$WORK/certs" "$PACK/scripts/make_certs.sh"

echo "=== step 3: KEM bench, run 1 ==="
"$WORK/bench_kem" 200 | tee "$OUT/${PREFIX}bench-kem-run1.log"
echo "=== step 4: KEM bench, run 2 ==="
"$WORK/bench_kem" 200 | tee "$OUT/${PREFIX}bench-kem-run2.log"

echo "=== step 5: implicit rejection, run 1 ==="
"$WORK/implicit_reject" 50 | tee "$OUT/${PREFIX}rejection-run1.log"
echo "=== step 6: implicit rejection, run 2 ==="
"$WORK/implicit_reject" 50 | tee "$OUT/${PREFIX}rejection-run2.log"

echo "=== step 7: hybrid TLS handshakes (30 each) ==="
PROV="$WORK/oqs-opt-mod"
"$PACK/scripts/run_hybrid.sh" "$PROV" "X25519MLKEM768" "X25519MLKEM768" 30 "$OUT/${PREFIX}hybrid-X25519MLKEM768.log"
"$PACK/scripts/run_hybrid.sh" "$PROV" "x25519_mlkem512" "x25519_mlkem512" 30 "$OUT/${PREFIX}hybrid-x25519_mlkem512.log"
"$PACK/scripts/run_hybrid.sh" "$PROV" "SecP256r1MLKEM768" "SecP256r1MLKEM768" 30 "$OUT/${PREFIX}hybrid-SecP256r1MLKEM768.log"
"$PACK/scripts/run_hybrid.sh" "$PROV" "SecP384r1MLKEM1024" "SecP384r1MLKEM1024" 30 "$OUT/${PREFIX}hybrid-SecP384r1MLKEM1024.log"
"$PACK/scripts/run_hybrid.sh" "$PROV" "X25519" "X25519" 30 "$OUT/${PREFIX}hybrid-X25519.log"
"$PACK/scripts/run_hybrid.sh" "$PROV" "P-256" "P-256" 30 "$OUT/${PREFIX}hybrid-P-256.log"
"$PACK/scripts/run_hybrid.sh" "$PROV" "P-384" "P-384" 30 "$OUT/${PREFIX}hybrid-P-384.log"

echo "=== step 8: downgrade scenarios ==="
# D1: both hybrid-capable -> hybrid negotiated.
"$PACK/scripts/run_hybrid.sh" "$PROV" "X25519MLKEM768" "downgrade-hybrid-both" 10 "$OUT/${PREFIX}hybrid-downgrade-hybrid-both.log" "X25519MLKEM768"
# D2: server offers classical only, client offers hybrid+classical -> X25519.
"$PACK/scripts/run_hybrid.sh" "$PROV" "X25519" "downgrade-server-classical" 10 "$OUT/${PREFIX}hybrid-downgrade-server-classical.log" "X25519MLKEM768:X25519"
# D3: client offers classical only, server offers hybrid+classical -> X25519.
# NOTE: the server MUST offer X25519 as well as the hybrid group; if the
# server offers only X25519MLKEM768, a classical-only client shares no
# group with it and the handshake fails (that is correct TLS behaviour,
# not a downgrade — the first version of this scenario made exactly that
# mistake and failed 10/10, see PROGRESS.md).
"$PACK/scripts/run_hybrid.sh" "$PROV" "X25519MLKEM768:X25519" "downgrade-client-classical" 10 "$OUT/${PREFIX}hybrid-downgrade-client-classical.log" "X25519"
# D4: no common group (client X25519MLKEM768 only, server SecP384r1MLKEM1024
# only) -> handshake must fail; this is the negative control.
EXPECT_FAIL=1 "$PACK/scripts/run_hybrid.sh" "$PROV" "SecP384r1MLKEM1024" "downgrade-no-common-group" 10 "$OUT/${PREFIX}hybrid-downgrade-no-common-group.log" "X25519MLKEM768"

echo "=== step 9: aggregate ==="
python3 "$PACK/scripts/aggregate.py" "$OUT" "$PREFIX"

echo "=== step 10: score findings ==="
python3 "$PACK/scripts/score_findings.py" "$PACK" "$PREFIX"

echo "=== step 11: claim-to-evidence index ==="
python3 "$PACK/scripts/make_index.py" "$PACK" "$PREFIX"

echo "run_all: DONE prefix='$PREFIX'"
