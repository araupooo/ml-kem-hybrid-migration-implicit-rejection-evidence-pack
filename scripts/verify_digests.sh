#!/bin/bash
# verify_digests.sh — verify every file in the pack against SHA256SUMS.
# Usage: verify_digests.sh
# Exit code 0 only if every digest matches.
set -eu
PACK="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PACK"
sha256sum -c SHA256SUMS
