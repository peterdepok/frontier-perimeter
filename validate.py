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
    """Mirror of st(sc).A1 in the site, per RFC 9989.

    A record requesting enforcement (p=quarantine or reject) clears the observable
    Floor. Per RFC 9989 the pct tag is retired; a record still carrying pct<100 is
    read as an enforcing policy in *partial rollout* ('partial') — it clears the
    Floor with that caveat, and is never described as a rejection percentage. A
    record expressing no preference (p=none) or absent is 'fail'. Receiver
    behaviour is not measured anywhere.
    """
    L = sc.get("L1")
    if L == "meet":
        pct = sc.get("pct")
        return "partial" if (pct is not None and pct < 100) else "pass"
    if L == "below":  return "fail"
    if L == "nomail": return "nomail"
    return "na"

def clears_floor(sc):
    """The single Floor-clearing rule: the record requests enforcement."""
    return dmarc_state(sc) in ("pass", "partial")

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

# 3. unknown/failed can never be a meet; a clean 'pass' carries no legacy pct tag
for p in firms:
    sc = p.get("sc") or {}
    st = dmarc_state(sc)
    if st == "pass":
        if sc.get("L1") != "meet":
            errors.append(f"{p.get('n')}: DMARC 'pass' but L1 is {sc.get('L1')!r}")
        if sc.get("pct") is not None and sc["pct"] < 100:
            errors.append(f"{p.get('n')}: DMARC 'pass' but carries pct={sc['pct']} (<100); should be 'partial'")

# 3b. no contradictory DMARC conclusions per organization.
#     Every summary, finding, table and aggregate on the site derives from the
#     one interpretation, st(sc).A1. This re-derives the Floor-clearing conclusion
#     two independent ways — from the parsed state, and from the raw published
#     policy tag — and requires them to agree for every org whose mail was read.
#     A disagreement is exactly the "reader sees conflicting conclusions" bug.
ENFORCING_TAGS = ("quarantine", "reject")
NOPREF_TAGS    = ("none", "absent")
for p in firms:
    sc = p.get("sc") or {}
    a1 = dmarc_state(sc)
    if a1 not in ("pass", "partial", "fail"):
        continue  # nomail / not-observable: no policy conclusion is stated
    policy = sc.get("dmarc")
    by_state  = clears_floor(sc)                 # pass|partial -> clears
    by_policy = policy in ENFORCING_TAGS         # raw tag requests enforcement
    if by_state != by_policy:
        errors.append(
            f"{p.get('n')}: contradictory DMARC conclusion — state {a1!r} "
            f"(clears Floor={by_state}) but published policy {policy!r} "
            f"(requests enforcement={by_policy})")
    # a 'fail' must be backed by a no-preference/absent tag, never an enforcing one
    if a1 == "fail" and policy not in NOPREF_TAGS:
        errors.append(f"{p.get('n')}: DMARC 'fail' but policy tag is {policy!r} "
                      f"(expected one of {NOPREF_TAGS})")
    # an enforcing state must be backed by an enforcing tag
    if a1 in ("pass", "partial") and policy not in ENFORCING_TAGS:
        errors.append(f"{p.get('n')}: DMARC {a1!r} but policy tag is {policy!r} "
                      f"(expected one of {ENFORCING_TAGS})")

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

# 5b. ring_agg — the one shared aggregation, mirrored from ringAgg() in the site.
#     Every DMARC/security.txt figure on every surface (Overview ring bars, the
#     Standard "By ring" table, the lede findings, each profile) must come from this,
#     so the presentations reconcile. The classic bug was the Standard table using a
#     pass-only numerator over a pass+fail denominator (partial dropped from both),
#     giving 69% where the Overview showed 71%. These asserts fail if that returns.
def ring_agg(group):
    sc = [p.get("sc") or {} for p in group]
    stt = [dmarc_state(s) for s in sc]
    npass = stt.count("pass"); npart = stt.count("partial")
    nfail = stt.count("fail"); nnom = stt.count("nomail"); nna = stt.count("na")
    enf = npass + npart                      # requests enforcement (partial included)
    dm_den = enf + nfail                     # mail observed
    sec_ok = sum(1 for s in sc if s.get("sectxt") == "yes")
    sec_den = sum(1 for s in sc if s.get("sectxt") and s.get("sectxt") != "?")
    return {"N": len(group), "pass": npass, "partial": npart, "fail": nfail,
            "nomail": nnom, "na": nna, "enf": enf, "dm_den": dm_den,
            "obs_num": enf + nnom, "obs_den": len(group) - nna,
            "sec_ok": sec_ok, "sec_den": sec_den}

rings = [(s.get("name"), s.get("id"),
          [p for c in s["cats"] for p in c["p"]]) for s in providers]
ring_stats = [(name, ring_agg(grp)) for name, rid, grp in rings]

# every ring: the enforcement numerator MUST include partial-rollout records, and
# the denominator MUST be enf+fail (mail observed) — not a pass-only / pass+fail pair.
for name, a in ring_stats:
    if a["enf"] != a["pass"] + a["partial"]:
        errors.append(f"{name}: enforcement numerator drops partial rollouts ({a})")
    if a["dm_den"] != a["pass"] + a["partial"] + a["fail"]:
        errors.append(f"{name}: DMARC denominator is not enf+fail ({a})")
    if a["obs_num"] > a["obs_den"]:
        errors.append(f"{name}: observable-Floor numerator exceeds denominator ({a})")

# aggregates reconcile: the per-ring counts must sum to the overall counts.
for key, tot in (("pass", overall["pass"]), ("partial", overall["partial"]),
                 ("fail", overall["fail"]), ("nomail", overall["nomail"])):
    s = sum(a[key] for _, a in ring_stats)
    if s != tot:
        errors.append(f"aggregate mismatch: rings sum {key}={s} but overall={tot}")

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
ov_den = overall['pass'] + overall['partial'] + overall['fail']
ov_enf = overall['pass'] + overall['partial']
print(f"  headline: {ent['fail']} of {len(entrusted)} entrusted request no DMARC enforcement "
      f"(p=none or absent); {ent['partial']} request enforcement in a legacy partial rollout; "
      f"{ov_enf} of {ov_den} readable domains request enforcement")
print("  note: receiver behaviour is NOT measured; figures describe the published record only")
print("  by ring (one shared calculation — must match every surface on the site):")
print(f"    {'ring':<26}{'orgs':>5}{'req-enf':>12}{'obs-floor':>12}{'sec.txt':>12}")
for name, a in ring_stats:
    def frac(n, d): return f"{n}/{d}" + (f" {round(100*n/d)}%" if d else " —")
    print(f"    {name[:26]:<26}{a['N']:>5}{frac(a['enf'],a['dm_den']):>12}"
          f"{frac(a['obs_num'],a['obs_den']):>12}{frac(a['sec_ok'],a['sec_den']):>12}")

if warnings:
    print(f"\n  {len(warnings)} warning(s):")
    for w in warnings: print("   -", w)
if errors:
    print(f"\nFAILED: {len(errors)} invariant(s) violated:")
    for e in errors: print("   -", e)
    sys.exit(1)
print("\nOK: all invariants hold.")
