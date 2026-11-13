#!/bin/bash
# run_hybrid.sh — measure real TLS 1.3 handshakes through the oqs-provider
# call path (openssl s_server / s_client, system OpenSSL 3.0.13) for ONE
# server-side group and one client-side group list, with server-side CPU
# and memory sampled from /proc.
#
# Usage:
#   run_hybrid.sh <provider_dir> <server_group> <label> <n_handshakes> <out_log> [client_group]
# provider_dir: directory containing oqsprovider.so (passed via OPENSSL_MODULES)
# server_group: group(s) the server offers (e.g. X25519MLKEM768)
# client_group: group(s) the client offers (default: same as server_group).
#   Use a colon-separated list to offer several groups, e.g.
#   "X25519MLKEM768:X25519" — this is how downgrade scenarios are built:
#   client offers hybrid+classical, server offers classical only, and the
#   negotiated group (Server Temp Key line) proves which one was picked.
# The script starts s_server, runs N timed full handshakes, captures one
# -msg trace to measure the ClientHello key_share size, and samples the
# server process CPU time (utime+stime) and VmRSS before/after the
# handshake loop so the per-handshake server cost can be derived. Times
# include the s_client process spawn (~2-4 ms) and are comparable across
# labels run with the same harness.
#
# Environment overrides:
#   TLS_CERT / TLS_KEY / TLS_CAFILE — server certificate, key, CA file
#     (default: ECDSA P-384 certs under <task>/work/certs)
#   TLS_OPENSSL_CONF — OpenSSL config file (default:
#     pack/configs/openssl-providers.cnf)
#   TLS_PORT — server port (default 18443)
#   EXPECT_FAIL=1 — the handshakes are EXPECTED to fail (negative control:
#     client and server share no group). The run passes when every
#     handshake fails without completing a TLS 1.3 session.
set -u
PROV_DIR="$1"; GROUP="$2"; LABEL="$3"; N="${4:-30}"; OUT="$5"
CLIENT_GROUP="${6:-$GROUP}"
EXPECT_FAIL="${EXPECT_FAIL:-0}"

HERE="$(cd "$(dirname "$0")" && pwd)"
PACK="$(cd "$HERE/.." && pwd)"
CERTDIR="${TLS_CERTDIR:-$PACK/../work/certs}"
TLS_CERT="${TLS_CERT:-$CERTDIR/ecdsa-server.crt}"
TLS_KEY="${TLS_KEY:-$CERTDIR/ecdsa-server.key}"
TLS_CAFILE="${TLS_CAFILE:-$CERTDIR/ecdsa-ca.crt}"
TLS_OPENSSL_CONF="${TLS_OPENSSL_CONF:-$PACK/configs/openssl-providers.cnf}"
export OPENSSL_CONF="$TLS_OPENSSL_CONF"
export OPENSSL_MODULES="$PROV_DIR"
PORT="${TLS_PORT:-18443}"

: > "$OUT"
{
echo "hybrid: label=$LABEL server_group=$GROUP client_group=$CLIENT_GROUP provider_dir=$PROV_DIR n=$N port=$PORT expect_fail=$EXPECT_FAIL"
echo "date: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
echo "openssl version: $(openssl version)"
echo "provider: $(ls -l "$PROV_DIR"/oqsprovider.so 2>/dev/null || echo MISSING)"
echo "provider sha256: $(sha256sum "$PROV_DIR"/oqsprovider.so 2>/dev/null | cut -d' ' -f1)"
echo "server cert: $TLS_CERT"
echo "server cert: $(openssl x509 -in "$TLS_CERT" -noout -text 2>/dev/null | grep -m1 'Signature Algorithm' || echo MISSING)"
} | tee -a "$OUT"

openssl s_server -accept "127.0.0.1:$PORT" \
  -cert "$TLS_CERT" -key "$TLS_KEY" \
  -groups "$GROUP" -tls1_3 \
  -provider default -provider oqsprovider \
  -naccept "$((N + 5))" -quiet >> "$OUT" 2>&1 &
SRV_PID=$!
sleep 2
if ! kill -0 "$SRV_PID" 2>/dev/null; then
  echo "FATAL: s_server failed to start (see log)" | tee -a "$OUT"
  exit 1
fi
echo "server pid=$SRV_PID procstat-before: $(python3 "$HERE/procstat.py" "$SRV_PID")" | tee -a "$OUT"

# One traced handshake to measure the ClientHello key_share size and the
# negotiated group (Server Temp Key line).
TRACE="$OUT.trace"
openssl s_client -connect "127.0.0.1:$PORT" -groups "$CLIENT_GROUP" -tls1_3 \
  -provider default -provider oqsprovider \
  -CAfile "$TLS_CAFILE" -verify_return_error -msg </dev/null > "$TRACE" 2>&1
grep -m1 'New, TLSv1.3' "$TRACE" >> "$OUT" || echo "trace: no New TLSv1.3 session (handshake did not complete)" >> "$OUT"
grep -m1 'Server Temp Key' "$TRACE" >> "$OUT" || echo "trace: no Server Temp Key line (handshake did not complete)" >> "$OUT"
python3 - "$TRACE" >> "$OUT" <<'PYEOF'
import re, sys
data = open(sys.argv[1], errors="ignore").read()
lines = data.splitlines()
hexlines = []
in_ch = False
for ln in lines:
    if "ClientHello" in ln and ">>>" in ln:
        in_ch = True
        continue
    if in_ch:
        if re.match(r"^\s+([0-9a-f]{2} )+[0-9a-f]{2}\s*$", ln):
            hexlines.append(ln)
        else:
            break
if not hexlines:
    print("trace: ClientHello hex block not found")
    sys.exit(0)
raw = bytes.fromhex(" ".join(" ".join(h.split()) for h in hexlines))
print("trace: ClientHello total bytes=%d (incl. 4-byte handshake header)" % len(raw))
p = 4 + 2 + 32
sid_len = raw[p]; p += 1 + sid_len
cs_len = int.from_bytes(raw[p:p+2], "big"); p += 2 + cs_len
comp_len = raw[p]; p += 1 + comp_len
ext_len = int.from_bytes(raw[p:p+2], "big"); p += 2
end = p + ext_len
while p + 4 <= end:
    etype = int.from_bytes(raw[p:p+2], "big")
    elen = int.from_bytes(raw[p+2:p+4], "big")
    if etype == 0x0033:  # key_share
        ks = raw[p+4:p+4+elen]
        list_len = int.from_bytes(ks[0:2], "big")
        group = int.from_bytes(ks[2:4], "big")
        klen = int.from_bytes(ks[4:6], "big")
        print("trace: key_share extension length=%d list_len=%d group=0x%04x key_exchange_len=%d" % (elen, list_len, group, klen))
    p += 4 + elen
PYEOF

TIMES="$OUT.times"
: > "$TIMES"
FAIL=0
for i in $(seq 1 "$N"); do
  START=$(date +%s%N)
  RES=$(openssl s_client -connect "127.0.0.1:$PORT" -groups "$CLIENT_GROUP" -tls1_3 \
    -provider default -provider oqsprovider \
    -CAfile "$TLS_CAFILE" -verify_return_error </dev/null 2>&1)
  END=$(date +%s%N)
  MS=$(( (END - START) / 1000000 ))
  echo "$MS" >> "$TIMES"
  if [ "$EXPECT_FAIL" = "1" ]; then
    # Negative control: the handshake must NOT complete.
    echo "$RES" | grep -q 'New, TLSv1.3' && { echo "handshake $i: UNEXPECTED SUCCESS (was expected to fail)" | tee -a "$OUT"; FAIL=$((FAIL+1)); }
  else
    if [ "$i" -eq 1 ]; then
      echo "$RES" | grep -E 'New, TLSv1.3|Cipher    :|Verify return code|Server Temp Key|Protocol  :' | tee -a "$OUT"
    fi
    echo "$RES" | grep -q 'Verify return code: 0 (ok)' || { echo "handshake $i: VERIFY NOT OK" | tee -a "$OUT"; FAIL=$((FAIL+1)); }
    echo "$RES" | grep -q 'New, TLSv1.3' || { echo "handshake $i: NOT A NEW TLS 1.3 HANDSHAKE" | tee -a "$OUT"; FAIL=$((FAIL+1)); }
  fi
done
echo "handshake failures: $FAIL / $N" | tee -a "$OUT"
echo "server pid=$SRV_PID procstat-after: $(python3 "$HERE/procstat.py" "$SRV_PID")" | tee -a "$OUT"

kill "$SRV_PID" 2>/dev/null; wait "$SRV_PID" 2>/dev/null || true

python3 - "$TIMES" "$LABEL" "$GROUP" "$CLIENT_GROUP" >> "$OUT" <<'PYEOF'
import statistics, sys
times = [int(x) for x in open(sys.argv[1]).read().split() if x.strip()]
label, group, cgroup = sys.argv[2], sys.argv[3], sys.argv[4]
print("handshake summary (%s, server=%s client=%s): n=%d mean=%.2f ms median=%.2f ms min=%d ms max=%d ms stdev=%.2f ms" % (
    label, group, cgroup, len(times), statistics.mean(times), statistics.median(times),
    min(times), max(times), statistics.stdev(times) if len(times) > 1 else 0.0))
print("handshake times ms: %s" % " ".join(map(str, times)))
PYEOF
echo "hybrid: DONE label=$LABEL server_group=$GROUP client_group=$CLIENT_GROUP" | tee -a "$OUT"
if [ "$EXPECT_FAIL" = "1" ]; then
  if [ "$FAIL" -eq 0 ]; then echo "hybrid: EXPECTED-FAILURE CONTROL PASSED (all $N handshakes failed as expected)" | tee -a "$OUT"; else echo "hybrid: EXPECTED-FAILURE CONTROL FAILED ($FAIL unexpected successes)" | tee -a "$OUT"; exit 1; fi
else
  if [ "$FAIL" -eq 0 ]; then echo "hybrid: ALL $N HANDSHAKES OK" | tee -a "$OUT"; else echo "hybrid: $FAIL handshake failures" | tee -a "$OUT"; exit 1; fi
fi
