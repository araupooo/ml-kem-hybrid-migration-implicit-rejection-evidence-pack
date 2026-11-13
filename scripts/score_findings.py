#!/usr/bin/env python3
"""score_findings.py — fill measured values into the finding definitions and
score them under the rubric.

Usage: score_findings.py <pack_dir> <prefix>
  prefix: "" for the shipped run, "fresh-clone-" for a clean reproduction.
Reads outputs/<prefix>bench-kem.csv, <prefix>hybrid-summary.csv,
<prefix>rejection-summary.json and configs/findings-definitions.json.
Writes outputs/<prefix>findings-scored.json, <prefix>findings-scored.csv
and (only for prefix "") the canonical findings.json at the pack root.

Severity = impact x likelihood per configs/rubric.md:
  20-25 Critical, 15-19 High, 8-14 Medium, 4-7 Low, 1-3 Info.
"""
import csv
import json
import re
import sys
from pathlib import Path

pack = Path(sys.argv[1])
prefix = sys.argv[2] if len(sys.argv) > 2 else ""
outdir = pack / "outputs"

# ---- measured values ----
vals = {}

with open(outdir / f"{prefix}bench-kem.csv") as f:
    rows = list(csv.DictReader(f))
bench = {}
for r in rows:
    bench.setdefault((r["scheme"], r["op"]), []).append(float(r["mean_us"]))
for (scheme, op), ms in bench.items():
    vals[f"bench:{scheme}:{op}:mean_us"] = f"{sum(ms) / len(ms):.2f}"

with open(outdir / f"{prefix}hybrid-summary.csv") as f:
    hrows = {r["label"]: r for r in csv.DictReader(f)}
for label, r in hrows.items():
    vals[f"hybrid:{label}:mean_ms"] = r["mean_ms"]
    vals[f"hybrid:{label}:key_exchange_len"] = r["key_exchange_len"]
    vals[f"hybrid:{label}:clienthello_bytes"] = r["clienthello_bytes"]
    vals[f"hybrid:{label}:server_cpu_ms"] = r["server_cpu_ms_per_handshake"]
h768 = float(hrows["X25519MLKEM768"]["mean_ms"])
hx = float(hrows["X25519"]["mean_ms"])
vals["hybrid:overhead_768_pct"] = f"{(h768 - hx) / hx * 100:.1f}"
vals["hybrid:key_share_ratio"] = f"{int(hrows['X25519MLKEM768']['key_exchange_len']) / int(hrows['X25519']['key_exchange_len']):.0f}"

with open(outdir / f"{prefix}rejection-summary.json") as f:
    rej = json.load(f)
TAMPER = {"flip_first_bit", "flip_mid_bit", "flip_last_bit", "flip_byte",
          "all_zero_ct", "random_ct", "wrong_sk"}
tot = {"tamper_total_trials": 0, "tamper_rc_success": 0,
       "tamper_ss_eq_valid": 0, "tamper_deterministic": 0,
       "control_ss_match": 0, "control_total": 0,
       }
for c in rej["cases"]:
    if c["case"] in TAMPER:
        tot["tamper_total_trials"] += c["n"]
        tot["tamper_rc_success"] += c["rc_success"]
        tot["tamper_ss_eq_valid"] += c["ss_eq_valid"]
        tot["tamper_deterministic"] += c["deterministic"]
    elif c["case"] == "control":
        tot["control_ss_match"] += c["rc_success"]  # control: rc_success == ss match count
        tot["control_total"] += c["n"]
for k, v in tot.items():
    vals[f"rej:{k}"] = str(v)

# control ss_match: the harness counts rc_success as decaps success; the
# control case also requires ss equality (checked inside the harness and
# reported in the log's CONTROL line). Verify from the JSON controls field.
ctrl_match = sum(m for pairs in rej["controls"].values() for m, _ in pairs)
ctrl_total = sum(t for pairs in rej["controls"].values() for _, t in pairs)
vals["rej:control_ss_match"] = str(ctrl_match)
vals["rej:control_total"] = str(ctrl_total)

# ---- fill and score ----
defs = json.loads((pack / "configs" / "findings-definitions.json").read_text())


def fill(text):
    def repl(m):
        key = m.group(1)
        if key not in vals:
            raise KeyError(f"unresolved placeholder {{{key}}}")
        return vals[key]
    return re.sub(r"\{([A-Za-z0-9:_\-]+)\}", repl, text)


def severity(score):
    if score >= 20:
        return "Critical"
    if score >= 15:
        return "High"
    if score >= 8:
        return "Medium"
    if score >= 4:
        return "Low"
    return "Info"


scored = []
for f in defs["findings"]:
    score = f["impact"] * f["likelihood"]
    scored.append({
        "id": f["id"],
        "title": f["title"],
        "severity": severity(score),
        "score": score,
        "impact": f["impact"],
        "likelihood": f["likelihood"],
        "rationale": f["rationale"],
        "remediation": f["remediation"],
        "evidence": fill(f["evidence"]),
    })

with open(outdir / f"{prefix}findings-scored.json", "w") as f:
    json.dump({"rubric": "configs/rubric.md", "findings": scored}, f, indent=2)

with open(outdir / f"{prefix}findings-scored.csv", "w") as f:
    w = csv.writer(f)
    w.writerow(["id", "title", "severity", "score", "impact", "likelihood"])
    for s in scored:
        w.writerow([s["id"], s["title"], s["severity"], s["score"],
                    s["impact"], s["likelihood"]])

if prefix == "":
    with open(pack / "findings.json", "w") as f:
        json.dump({"rubric": "configs/rubric.md", "findings": scored}, f, indent=2)

from collections import Counter
print(f"score_findings: {len(scored)} findings: {dict(Counter(s['severity'] for s in scored))}")
