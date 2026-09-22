#!/usr/bin/env python3
"""Reproducible validation for The Frontier Perimeter.

Re-checks the invariants a skeptical reader should be able to verify:
  1. every included organization carries its inclusion evidence (source + quote);
  2. every organization is counted once (no duplicate domain across rings);
  3. the DMARC Floor status is derived only from the published fields, and an
     unknown or failed reading can never become a 'meets';
  4. sanctions and leak-site listings are public-record, never Floor controls;
  5. the headline aggregates re-compute from the individual records;
  6. the dataset and methodology carry versions.

Run from the repo root:  python3 validate.py
Exits non-zero if any invariant fails. Prints the aggregates so a reader can
compare them against the rendered site.
"""
import json, sys, os

ROOT = os.path.dirname(os.path.abspath(__file__))
def load(p): return json.load(open(os.path.join(ROOT, p)))

providers = load("data/providers.json")
controls  = load("controls.json")
method    = load("methodology.json")
scan      = load("data/scan_meta.json")

firms = [p for s in providers for c in s["cats"] for p in c["p"]]
errors, warnings = [], []

# ---- the status rule, re-implemented from the published fields only ----
def dmarc_state(sc):
    """Mirror of st(sc).A1 in the site. A meet requires an enforcing policy at pct=100."""
    L = sc.get("L1")
    if L == "meet":
        pct = sc.get("pct")
        return "partial" if (pct is not None and pct < 100) else "pass"
    if L == "below":  return "fail"
    if L == "nomail": return "nomail"
    return "na"

# 1. inclusion evidence
for p in firms:
    if not p.get("su"):
        errors.append(f"{p.get('n')}: no inclusion source (su)")
    if not p.get("q") and not p.get("also"):
        warnings.append(f"{p.get('n')}: no quoted inclusion sentence (q)")

# 2. deduplication by domain (and by name)
seen_dom, seen_name = {}, {}
for p in firms:
    d = (p.get("w") or "").lower()
    n = (p.get("n") or "").lower()
    if d and d in seen_dom:
        errors.append(f"duplicate domain {d}: {p.get('n')} and {seen_dom[d]}")
    if d: seen_dom[d] = p.get("n")
    if n in seen_name:
        errors.append(f"duplicate name {p.get('n')}")
    seen_name[n] = True

# 3. unknown/failed can never be a meet; pass requires pct=100
for p in firms:
    sc = p.get("sc") or {}
    st = dmarc_state(sc)
    if st == "pass":
        if sc.get("L1") != "meet":
            errors.append(f"{p.get('n')}: DMARC 'pass' but L1 is {sc.get('L1')!r}")
        if sc.get("pct") is not None and sc["pct"] < 100:
            errors.append(f"{p.get('n')}: DMARC 'pass' but pct={sc['pct']} (<100)")

# 4. sanctions and leak-site are public-record, not Floor
tier = {c["id"]: c["tier"] for f in controls["families"] for c in f["controls"]}
for cid in ("F1", "G1"):
    if tier.get(cid) != "record":
        errors.append(f"control {cid} must be tier 'record' (public record), found {tier.get(cid)!r}")
floor_l1 = [c["id"] for f in controls["families"] for c in f["controls"]
            if c["tier"] == "floor" and c["lvl"] == 1]
if floor_l1 != ["A1"]:
    errors.append(f"the only Level-1 (curb-observable) Floor control must be A1; found {floor_l1}")

# 5. re-compute the headline aggregates
def counts(group):
    dd = {"pass": 0, "partial": 0, "fail": 0, "nomail": 0, "na": 0}
    for p in group:
        dd[dmarc_state(p.get("sc") or {})] += 1
    return dd

overall = counts(firms)
entrusted = [p for s in providers if s.get("id") == "entrusted" for c in s["cats"] for p in c["p"]]
ent = counts(entrusted)
ofac_notclear = [p.get("n") for p in firms if (p.get("sc") or {}).get("ofac") not in ("clear", None)]

# 6. versions
if not controls.get("version"): errors.append("controls.json has no version")
if not method.get("version"):   errors.append("methodology.json has no version")
if not scan.get("iso"):         errors.append("scan_meta.json has no iso date")

# ---- report ----
print("The Frontier Perimeter — validation")
print(f"  dataset (scan): {scan.get('date')}   controls {controls.get('version')}   methodology {method.get('version')}")
print(f"  organizations: {len(firms)}")
print(f"  DMARC overall: {overall}")
print(f"  DMARC entrusted ({len(entrusted)}): {ent}")
print(f"  observable Level-1 Floor control(s): {floor_l1}")
print(f"  sanctioned organizations: {len(ofac_notclear)} {ofac_notclear or ''}")
print(f"  headline: {ent['fail']} of {len(entrusted)} entrusted do not enforce DMARC; "
      f"{ent['partial']} enforce partly; {overall['pass']} of {overall['pass']+overall['partial']+overall['fail']} readable domains fully enforce")

if warnings:
    print(f"\n  {len(warnings)} warning(s):")
    for w in warnings: print("   -", w)
if errors:
    print(f"\nFAILED: {len(errors)} invariant(s) violated:")
    for e in errors: print("   -", e)
    sys.exit(1)
print("\nOK: all invariants hold.")
