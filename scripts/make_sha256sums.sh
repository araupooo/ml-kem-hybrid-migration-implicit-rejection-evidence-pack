#!/bin/bash
# make_sha256sums.sh — generate SHA256SUMS for every file in the pack.
# Usage: make_sha256sums.sh
# Run LAST, after the clean reproduction, so the digests cover the shipped
# outputs including the fresh-clone outputs and the clean-reproduce log.
# Excludes SHA256SUMS itself (it cannot contain its own digest) and the
# work/ directory (build artifacts, not pack content).
# The digest list is sorted and uses paths relative to the pack root.
set -eu
PACK="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PACK"
find . -type f ! -path './work/*' ! -name 'SHA256SUMS' -print0 \
  | sort -z | xargs -0 sha256sum > SHA256SUMS
echo "make_sha256sums: $(wc -l < SHA256SUMS) files digested"
