#!/usr/bin/env python3
"""compare_reproduce.py — compare the fresh-clone outputs against the shipped
outputs and report every mismatch.

Usage: compare_reproduce.py <outputs_dir>

Rules (chosen before the comparison, recorded here):
- EXACT: all key/ciphertext/secret sizes; rejection counts (tampered
  ciphertexts accepted must be 0 in both runs; implicit-rejection secrets
  deterministic in both runs; control secret matches); negotiated groups;
  ClientHello key_share lengths and total sizes; downgrade verdicts; number
  of handshake failures (0 in both runs; for the no-common-group negative
  control, 0 unexpected successes in both runs); finding severities.
- TOLERANT (timing only, host-load noise): bench means within 50% relative
  difference, handshake means and medians within 50% relative difference.
  Timing is a measurement, not a specification; sizes and rejection
  behaviour are specifications.

Exit code: number of comparison failures (0 = reproduction confirmed).
"""
import csv
import json
import sys
from pathlib import Path

outdir = Path(sys.argv[1])
failures = []


def check(cond, msg):
    if cond:
        print(f"  OK   {msg}")
    else:
        print(f"  FAIL {msg}")
        failures.append(msg)


def rel(a, b):
    if a == 0 and b == 0:
        return 0.0
    return abs(a - b) / max(abs(a), abs(b))


def load_csv(name):
    with open(outdir / name) as f:
        return list(csv.DictReader(f))


def load_json(name):
    with open(outdir / name) as f:
        return json.load(f)


print("compare_reproduce: shipped vs fresh-clone")
print("== bench sizes (exact) ==")
shipped_rej = load_json("rejection-summary.json")
fresh_rej = load_json("fresh-clone-rejection-summary.json")
for scheme in sorted(shipped_rej["sizes"]):
    for field, v in sorted(shipped_rej["sizes"][scheme].items()):
        fv = fresh_rej["sizes"][scheme][field]
        check(v["got"] == fv["got"] and v["status"] == fv["status"] == "OK",
              f"{scheme} {field}: shipped {v['got']} ({v['status']}) vs fresh {fv['got']} ({fv['status']})")

print("== bench timings (within 50%) ==")
shipped_bench = load_csv("bench-kem.csv")
fresh_bench = load_csv("fresh-clone-bench-kem.csv")
sb = {(r["scheme"], r["op"], r["run"]): float(r["mean_us"]) for r in shipped_bench}
fb = {(r["scheme"], r["op"], r["run"]): float(r["mean_us"]) for r in fresh_bench}
for key in sorted(sb):
    check(key in fb and rel(sb[key], fb[key]) <= 0.50,
          f"bench {key[0]} {key[1]} run{key[2]}: shipped {sb[key]:.2f} us vs fresh {fb.get(key, float('nan')):.2f} us (rel diff {rel(sb[key], fb[key]):.1%})")

print("== implicit rejection (exact counts) ==")
sc = {(c["scheme"], c["case"]): c for c in shipped_rej["cases"]}
fc = {(c["scheme"], c["case"]): c for c in fresh_rej["cases"]}
for key in sorted(sc):
    s, f = sc[key], fc[key]
    if key[1] == "control":
        # control: the decapsulated secret MUST equal the valid secret
        check(f["ss_eq_valid"] == f["n"] and s["ss_eq_valid"] == s["n"],
              f"rejection {key[0]} control: ss_eq_valid shipped {s['ss_eq_valid']}/{s['n']} fresh {f['ss_eq_valid']}/{f['n']} (must equal n)")
    else:
        # tamper: the decapsulated secret must NEVER equal the valid secret
        check(f["ss_eq_valid"] == 0 and s["ss_eq_valid"] == 0,
              f"rejection {key[0]} {key[1]}: ss_eq_valid shipped {s['ss_eq_valid']} fresh {f['ss_eq_valid']} (must be 0)")
        check(f["rc_success"] == f["n"] and f["deterministic"] == f["n"],
              f"rejection {key[0]} {key[1]}: fresh rc_success {f['rc_success']}/{f['n']} deterministic {f['deterministic']}/{f['n']}")
for scheme in sorted(shipped_rej["controls"]):
    sm = sum(m for m, _ in shipped_rej["controls"][scheme])
    st = sum(t for _, t in shipped_rej["controls"][scheme])
    fm = sum(m for m, _ in fresh_rej["controls"][scheme])
    ft = sum(t for _, t in fresh_rej["controls"][scheme])
    check(sm == st and fm == ft and sm == fm,
          f"control {scheme}: ss_match shipped {sm}/{st} fresh {fm}/{ft}")

print("== hybrid handshakes (exact groups/sizes, timing within 50%) ==")
shipped_h = {r["label"]: r for r in load_csv("hybrid-summary.csv")}
fresh_h = {r["label"]: r for r in load_csv("fresh-clone-hybrid-summary.csv")}
for label in sorted(shipped_h):
    s, f = shipped_h[label], fresh_h[label]
    check(s["negotiated_group"] == f["negotiated_group"],
          f"hybrid {label}: negotiated shipped {s['negotiated_group']} fresh {f['negotiated_group']}")
    check(s["key_exchange_len"] == f["key_exchange_len"],
          f"hybrid {label}: key_exchange_len shipped {s['key_exchange_len']} fresh {f['key_exchange_len']}")
    check(s["clienthello_bytes"] == f["clienthello_bytes"],
          f"hybrid {label}: clienthello_bytes shipped {s['clienthello_bytes']} fresh {f['clienthello_bytes']}")
    check(s["failures"] == "0" and f["failures"] == "0",
          f"hybrid {label}: handshake failures shipped {s['failures']} fresh {f['failures']} (must be 0)")
    check(rel(float(s["mean_ms"]), float(f["mean_ms"])) <= 0.50,
          f"hybrid {label}: mean shipped {s['mean_ms']} ms fresh {f['mean_ms']} ms (rel diff {rel(float(s['mean_ms']), float(f['mean_ms'])):.1%})")
    check(rel(float(s["median_ms"]), float(f["median_ms"])) <= 0.50,
          f"hybrid {label}: median shipped {s['median_ms']} ms fresh {f['median_ms']} ms")

print("== downgrade scenarios (exact verdicts) ==")
shipped_d = {r["scenario"]: r for r in load_csv("hybrid-downgrade.csv")}
fresh_d = {r["scenario"]: r for r in load_csv("fresh-clone-hybrid-downgrade.csv")}
for sc in sorted(shipped_d):
    s, f = shipped_d[sc], fresh_d[sc]
    check(s["verdict"] == "PASS" and f["verdict"] == "PASS",
          f"downgrade {sc}: shipped {s['verdict']} (actual {s['actual_negotiated']}) fresh {f['verdict']} (actual {f['actual_negotiated']})")

print("== finding severities (exact) ==")
shipped_f = {x["id"]: x["severity"] for x in load_json("findings-scored.json")["findings"]}
fresh_f = {x["id"]: x["severity"] for x in load_json("fresh-clone-findings-scored.json")["findings"]}
for fid in sorted(shipped_f):
    check(shipped_f[fid] == fresh_f.get(fid),
          f"finding {fid}: severity shipped {shipped_f[fid]} fresh {fresh_f.get(fid)}")

print(f"compare_reproduce: {len(failures)} failure(s)")
sys.exit(len(failures))
