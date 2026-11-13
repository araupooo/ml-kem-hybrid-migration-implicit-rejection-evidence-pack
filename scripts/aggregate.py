#!/usr/bin/env python3
"""aggregate.py — parse the unedited run logs into machine-readable summaries.

Usage: aggregate.py <outputs_dir> <prefix>
  prefix: "" for the shipped run, "fresh-clone-" for a clean reproduction.
Reads <prefix>bench-kem-run{1,2}.log, <prefix>rejection-run{1,2}.log,
<prefix>hybrid-*.log and writes:
  <prefix>bench-kem.csv, <prefix>rejection-summary.json,
  <prefix>hybrid-summary.csv, <prefix>hybrid-downgrade.csv
All numbers come from the logs; nothing is invented here.
"""
import json
import re
import sys
from pathlib import Path

outdir = Path(sys.argv[1])
prefix = sys.argv[2] if len(sys.argv) > 2 else ""

# ---------------- bench-kem ----------------
csv_rows = []
sizes = {}
controls = {}
for run in (1, 2):
    p = outdir / f"{prefix}bench-kem-run{run}.log"
    for line in p.read_text(errors="replace").splitlines():
        m = re.match(r"CSV: (\S+) (\S+) n=(\d+) mean_us=([\d.]+) min_us=([\d.]+) max_us=([\d.]+) ops_per_s=([\d.]+)", line)
        if m:
            csv_rows.append([m.group(1), m.group(2), run, m.group(3),
                             m.group(4), m.group(5), m.group(6), m.group(7)])
        m = re.match(r"SIZE: (\S+) (\S+)=(\d+) \(expected (\d+)\) (\S+)", line)
        if m:
            sizes.setdefault(m.group(1), {})[m.group(2)] = {
                "got": int(m.group(3)), "expected": int(m.group(4)), "status": m.group(5)}
        m = re.match(r"CONTROL: (\S+) encaps/decaps ss_match=(\d+)/(\d+)", line)
        if m:
            controls.setdefault(m.group(1), []).append((int(m.group(2)), int(m.group(3))))

with open(outdir / f"{prefix}bench-kem.csv", "w") as f:
    f.write("scheme,op,run,n,mean_us,min_us,max_us,ops_per_s\n")
    for r in csv_rows:
        f.write(",".join(map(str, r)) + "\n")

# ---------------- implicit rejection ----------------
rej = {}
for run in (1, 2):
    p = outdir / f"{prefix}rejection-run{run}.log"
    for line in p.read_text(errors="replace").splitlines():
        m = re.match(r"SUMMARY: (\S+) (\S+) n=(\d+) rc_success=(\d+) ss_eq_valid=(\d+) deterministic=(\d+)", line)
        if m:
            key = (m.group(1), m.group(2))
            e = rej.setdefault(key, {"scheme": m.group(1), "case": m.group(2),
                                     "runs": [], "n": 0, "rc_success": 0,
                                     "ss_eq_valid": 0, "deterministic": 0})
            e["runs"].append({"run": run, "n": int(m.group(3)),
                              "rc_success": int(m.group(4)),
                              "ss_eq_valid": int(m.group(5)),
                              "deterministic": int(m.group(6))})
            e["n"] += int(m.group(3))
            e["rc_success"] += int(m.group(4))
            e["ss_eq_valid"] += int(m.group(5))
            e["deterministic"] += int(m.group(6))

with open(outdir / f"{prefix}rejection-summary.json", "w") as f:
    json.dump({"sizes": sizes, "controls": {k: v for k, v in controls.items()},
               "cases": sorted(rej.values(), key=lambda e: (e["scheme"], e["case"]))},
              f, indent=2)

# ---------------- hybrid handshakes ----------------
def parse_procstat(line):
    m = re.search(r"cpu_total_s=([\d.]+).*rss_kb=(\d+)", line)
    return (float(m.group(1)), int(m.group(2))) if m else (None, None)

hybrid_rows = []
downgrade_rows = []
for p in sorted(outdir.glob(f"{prefix}hybrid-*.log")):
    text = p.read_text(errors="replace")
    label = re.search(r"hybrid: label=(\S+)", text).group(1)
    server_group = re.search(r"server_group=(\S+)", text).group(1)
    client_group = re.search(r"client_group=(\S+)", text).group(1)
    summ = re.search(
        r"handshake summary \(([^,]+), server=(\S+) client=(\S+)\): n=(\d+) "
        r"mean=([\d.]+) ms median=([\d.]+) ms min=(\d+) ms max=(\d+) ms stdev=([\d.]+) ms", text)
    fails = re.search(r"handshake failures: (\d+) / (\d+)", text)
    expect_fail = "expect_fail=1" in text
    # Negotiated group: s_client prints a "Server Temp Key" line for
    # classical ECDH groups ("Server Temp Key: X25519, 253 bits" or
    # "Server Temp Key: ECDH, prime256v1, 256 bits") but prints NO such
    # line for KEM/hybrid groups (known OpenSSL 3.0.13 behaviour). When
    # the line is absent but the client offered exactly one group and the
    # handshake succeeded (expect_fail=0, 0 failures), the negotiated
    # group must be that offered group: TLS 1.3 requires the server to
    # select one of the client's offered groups, and any other choice
    # would have failed the handshake.
    negotiated = None
    m = re.search(r"Server Temp Key: (.+)", text)
    if m:
        parts = [p.strip() for p in m.group(1).split(",")]
        if parts[0] == "ECDH":
            negotiated = {"prime256v1": "P-256", "secp384r1": "P-384"}.get(
                parts[1] if len(parts) > 1 else "", parts[1] if len(parts) > 1 else "ECDH")
        else:
            negotiated = parts[0]
    if negotiated is None and not expect_fail and ":" not in client_group:
        if fails and int(fails.group(1)) == 0:
            negotiated = client_group
    ks = re.search(r"trace: key_share extension length=(\d+) list_len=(\d+) group=0x([0-9a-f]+) key_exchange_len=(\d+)", text)
    ch = re.search(r"trace: ClientHello total bytes=(\d+)", text)
    before = re.search(r"procstat-before: (.+)", text)
    after = re.search(r"procstat-after: (.+)", text)
    cpu_before, rss_before = parse_procstat(before.group(1)) if before else (None, None)
    cpu_after, rss_after = parse_procstat(after.group(1)) if after else (None, None)
    n_hs = int(summ.group(4)) if summ else 0
    cpu_per_hs = None
    if cpu_before is not None and cpu_after is not None and n_hs:
        cpu_per_hs = round((cpu_after - cpu_before) / n_hs * 1000, 3)  # ms
    row = {
        "label": label, "server_group": server_group, "client_group": client_group,
        "n": n_hs,
        "mean_ms": float(summ.group(5)) if summ else None,
        "median_ms": float(summ.group(6)) if summ else None,
        "min_ms": int(summ.group(7)) if summ else None,
        "max_ms": int(summ.group(8)) if summ else None,
        "stdev_ms": float(summ.group(9)) if summ else None,
        "failures": int(fails.group(1)) if fails else None,
        "negotiated_group": negotiated,
        "key_share_group": ("0x" + ks.group(3)) if ks else None,
        "key_exchange_len": int(ks.group(4)) if ks else None,
        "clienthello_bytes": int(ch.group(1)) if ch else None,
        "server_cpu_ms_per_handshake": cpu_per_hs,
        "server_rss_kb_after": rss_after,
    }
    hybrid_rows.append(row)
    if label.startswith("downgrade-"):
        expected = {"downgrade-server-classical": "X25519",
                    "downgrade-client-classical": "X25519",
                    "downgrade-no-common-group": None,
                    "downgrade-hybrid-both": "X25519MLKEM768"}.get(label)
        actual = row["negotiated_group"]
        ok = (actual == expected) if expected is not None else (actual is None and row["failures"] == 0)
        # for no-common-group the run is EXPECT_FAIL: failures counts unexpected successes
        downgrade_rows.append({
            "scenario": label, "server_group": server_group,
            "client_group": client_group, "expected_negotiated": expected,
            "actual_negotiated": actual, "handshake_failures": row["failures"],
            "verdict": "PASS" if ok else "FAIL"})

with open(outdir / f"{prefix}hybrid-summary.csv", "w") as f:
    f.write("label,server_group,client_group,n,mean_ms,median_ms,min_ms,max_ms,stdev_ms,"
            "failures,negotiated_group,key_share_group,key_exchange_len,clienthello_bytes,"
            "server_cpu_ms_per_handshake,server_rss_kb_after\n")
    for r in hybrid_rows:
        f.write(",".join("" if v is None else str(v) for v in [
            r["label"], r["server_group"], r["client_group"], r["n"], r["mean_ms"],
            r["median_ms"], r["min_ms"], r["max_ms"], r["stdev_ms"], r["failures"],
            r["negotiated_group"], r["key_share_group"], r["key_exchange_len"],
            r["clienthello_bytes"], r["server_cpu_ms_per_handshake"],
            r["server_rss_kb_after"]]) + "\n")

with open(outdir / f"{prefix}hybrid-downgrade.csv", "w") as f:
    f.write("scenario,server_group,client_group,expected_negotiated,actual_negotiated,handshake_failures,verdict\n")
    for r in downgrade_rows:
        f.write(",".join("" if v is None else str(v) for v in [
            r["scenario"], r["server_group"], r["client_group"],
            r["expected_negotiated"], r["actual_negotiated"],
            r["handshake_failures"], r["verdict"]]) + "\n")

print(f"aggregate: bench rows={len(csv_rows)} rejection cases={len(rej)} hybrid runs={len(hybrid_rows)} downgrade={len(downgrade_rows)}")
