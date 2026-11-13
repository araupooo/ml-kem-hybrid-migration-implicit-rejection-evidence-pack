#!/bin/bash
# clean_reproduce.sh — fresh-environment reproduction of the whole pack.
# Usage: clean_reproduce.sh
# Copies the pack (excluding work/ and outputs/) to a fresh temporary
# directory, runs run_all.sh there with the "fresh-clone-" prefix, copies
# the fresh outputs back into this pack's outputs/ (prefixed fresh-clone-*),
# and compares them against the shipped outputs with compare_reproduce.py.
#
# THE TEMPORARY DIRECTORY IS INTENTIONALLY KEPT after the run (no cleanup
# trap): it is evidence of the fresh-environment reproduction. Its path is
# printed at the end and recorded in run-manifest.md. Do not delete it
# before the assessment is verified.
#
# Exit code: 0 only if the fresh run completed AND the comparison found
# 0 failures. The console log of this script is the reproduction log and
# is written to outputs/clean-reproduce.log by the caller (see README).
set -u
PACK="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$PACK/outputs"
mkdir -p "$OUT"

TMP="$(mktemp -d /tmp/mlkem-hybrid-repro.XXXXXX)"
echo "clean_reproduce: fresh copy at $TMP"
echo "clean_reproduce: date=$(date -u '+%Y-%m-%d %H:%M:%S UTC')"
echo "clean_reproduce: source pack=$PACK"

# Copy the pack, excluding the build work dir and the outputs (the fresh
# run regenerates its own outputs).
rsync -a --exclude work --exclude outputs "$PACK/" "$TMP/pack/"
echo "clean_reproduce: copied pack to $TMP/pack (work/ and outputs/ excluded)"

echo "=== fresh run ==="
set +e
(cd "$TMP/pack" && ./scripts/run_all.sh fresh-clone-)
RUN_RC=$?
set -e
echo "clean_reproduce: run_all exit code=$RUN_RC"

if [ "$RUN_RC" -ne 0 ]; then
  echo "clean_reproduce: FATAL — fresh run failed (exit $RUN_RC); see $TMP/pack/outputs/fresh-clone-*.log"
  echo "clean_reproduce: temp dir kept at $TMP"
  exit 1
fi

echo "=== copy fresh outputs back ==="
for f in "$TMP/pack/outputs"/fresh-clone-*; do
  cp "$f" "$OUT/"
  echo "  copied $(basename "$f")"
done
# Also copy the fresh claim-to-evidence index for reference (it is
# generated from the fresh aggregates; the shipped index stays canonical).
cp "$TMP/pack/docs/claim-evidence-index.md" "$OUT/fresh-clone-claim-evidence-index.md"
echo "  copied fresh-clone-claim-evidence-index.md"

echo "=== compare fresh outputs against shipped outputs ==="
python3 "$PACK/scripts/compare_reproduce.py" "$OUT"
CMP_RC=$?
echo "clean_reproduce: compare exit code=$CMP_RC failures=$CMP_RC"
echo "clean_reproduce: temp dir KEPT at $TMP (do not delete before verification)"
echo "clean_reproduce: exit=$CMP_RC"
exit $CMP_RC
