#!/usr/bin/env python3
"""Regression tests for the change-feed classifier (scripts/snapshot.py).

These use SYNTHETIC snapshots built in-memory. They never touch snapshots/ and
are never presented as site history; they exist only to prove the classifier
labels each kind of change correctly, so the real feed is trustworthy when a
genuine later snapshot arrives.

Run:  python3 tests/test_snapshot.py    (exits non-zero on failure)
"""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"))
import snapshot as S

fail = []
def check(cond, msg):
    if not cond: fail.append(msg)

# A previous snapshot dated 2026-01-01.
prev = {
    "date": "2026-01-01",
    "orgs": {
        "a.org": {"dmarc_state": "fail", "sectxt": "no", "sanctioned": False, "leak_listed": False},
        "b.org": {"dmarc_state": "pass", "sectxt": "yes", "sanctioned": False, "leak_listed": False},
    },
    "relationships": {
        "m1__a": {"evaluator": "a.org", "evaluator_name": "A", "model_id": "m1", "model": "M1",
                  "lab": "Lab", "access_type": "named-tester", "documented_on": "2025-06", "source_url": "u"},
    },
}
# A current snapshot dated 2026-02-01, with one of each kind of change.
cur = {
    "date": "2026-02-01",
    "orgs": {
        # observation-change: a.org started requesting enforcement, and published a security.txt
        "a.org": {"dmarc_state": "pass", "sectxt": "yes", "sanctioned": False, "leak_listed": False},
        "b.org": {"dmarc_state": "pass", "sectxt": "yes", "sanctioned": False, "leak_listed": False},
    },
    "relationships": {
        "m1__a": {"evaluator": "a.org", "evaluator_name": "A", "model_id": "m1", "model": "M1",
                  "lab": "Lab", "access_type": "named-tester", "documented_on": "2025-06", "source_url": "u"},
        # new-event: a source dated AFTER the previous snapshot (2026-01-15 > 2026-01-01)
        "m2__c": {"evaluator": "c.org", "evaluator_name": "C", "model_id": "m2", "model": "M2",
                  "lab": "Lab", "access_type": "pre-release-access", "documented_on": "2026-01-15", "source_url": "u"},
        # newly-documented: a source dated BEFORE the previous snapshot (2024-09 < 2026-01-01)
        "m0__d": {"evaluator": "d.org", "evaluator_name": "D", "model_id": "m0", "model": "M0",
                  "lab": "Lab", "access_type": "named-tester", "documented_on": "2024-09", "source_url": "u"},
    },
}

changes = S.diff(prev, cur)
by = {}
for c in changes:
    by.setdefault(c["category"], []).append(c)

# new-event: the post-snapshot source (C / M2), and ONLY that one
ne = by.get("new-event", [])
check(len(ne) == 1 and ne[0]["subject"] == "C", "expected exactly one new-event (C/M2), got %r" % ne)

# newly-documented: the pre-snapshot source we just recorded (D / M0)
nd = [c for c in by.get("newly-documented", []) if c["kind"] == "relationship"]
check(len(nd) == 1 and nd[0]["subject"] == "D", "expected one newly-documented relationship (D/M0), got %r" % nd)

# the discovery vs event distinction hinges only on source date vs prev snapshot date
check(nd and nd[0]["date"] < prev["date"] and ne and ne[0]["date"] > prev["date"],
      "classification must compare source date to the previous snapshot date")

# observation-change: a.org DMARC state fail->pass and sectxt no->yes (two changes)
oc = {(c["subject"], c.get("field")): c for c in by.get("observation-change", []) if c["kind"] == "organization"}
check(("a.org", "DMARC policy") in oc and oc[("a.org", "DMARC policy")]["prev"] == "fail"
      and oc[("a.org", "DMARC policy")]["cur"] == "pass", "expected a.org DMARC fail->pass, got %r" % oc)
check(("a.org", "security.txt") in oc, "expected a.org security.txt change, got %r" % list(oc))
# b.org did not change: it must not appear
check(not any(c["subject"] == "b.org" for c in changes), "unchanged b.org must not appear in the feed")

# a removal is classified as removed
prev2 = {"date": "2026-01-01", "orgs": {}, "relationships": cur["relationships"]}
cur2 = {"date": "2026-02-01", "orgs": {}, "relationships": prev["relationships"]}
rem = [c for c in S.diff(prev2, cur2) if c["category"] == "removed"]
check(any(c["subject"] in ("C", "D") for c in rem), "expected removed relationships when they disappear")

# baseline: a single snapshot yields an empty feed (no fabricated history)
check(S.build_feed([cur]) == [], "a single snapshot must produce an empty change feed")
check(len(S.build_feed([prev, cur])) == len(changes), "feed over two snapshots must equal their diff")

if fail:
    print("FAILED:", len(fail), "assertion(s):")
    for m in fail: print("  -", m)
    sys.exit(1)
print("OK: change-feed classifier — new-event, newly-documented, observation-change,")
print("    removed, and empty-baseline all behave correctly (%d synthetic changes checked)." % len(changes))
