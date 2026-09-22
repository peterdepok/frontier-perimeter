#!/usr/bin/env python3
"""Versioned evidence snapshots and the change feed for The Frontier Perimeter.

A snapshot is a dated, point-in-time record of the *observable* evidence: the
security observations read from the public record, plus the documented
model-access relationships. Snapshots live in snapshots/<date>.json and are
written by the weekly rescan (or `python3 scripts/snapshot.py write`).

The change feed is computed by diffing consecutive snapshots. Every change is
classified so a reader can tell three things apart:

  * new-event         a genuinely new real-world event: a source dated AFTER our
                      previous look now documents a relationship, or an
                      observation moved because the world moved.
  * newly-documented  something new to *us*, not to the world: a source that
                      predates our previous snapshot that we have only now
                      recorded, or an organization newly added to the map.
  * observation-change a security observation changed value; previous and
                      current are both shown. No real-world cause is asserted.
  * removed           a record present before is no longer documented.

The distinction that matters most — a newly *discovered* source vs a genuinely
new *event* — is decided by comparing the source's own publication date to the
date of the previous snapshot. Nothing here fabricates history: the feed is
empty at the baseline and fills only when a real later snapshot exists.
"""
import json, os, sys, glob

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
def _p(*a): return os.path.join(ROOT, *a)
def _load(path): return json.load(open(_p(path)))

# Observable fields captured per organization. These are the evidence values the
# site renders and that can change between reads; derived state is added below.
OBS_FIELDS = ["dmarc", "pct", "spf", "dnssec", "mtasts", "tlsrpt", "bimi", "caa",
              "dk", "hsts", "sectxt", "sectxt_exp", "host", "mail", "dns", "cc",
              "ofac"]

def dmarc_state(sc):
    """Mirror of st(sc).A1 / validate.dmarc_state — the one shared reading."""
    L = sc.get("L1")
    if L == "meet":
        pct = sc.get("pct")
        return "partial" if (pct is not None and pct < 100) else "pass"
    if L == "below":  return "fail"
    if L == "nomail": return "nomail"
    return "na"

def capture(providers, relationships, date, scan_label=None):
    """Serialize the current observable state + relationships into a snapshot."""
    firms = [p for s in providers for c in s["cats"] for p in c["p"]]
    orgs = {}
    for p in firms:
        sc = p.get("sc") or {}
        rec = {k: sc.get(k) for k in OBS_FIELDS if sc.get(k) is not None}
        rec["dmarc_state"] = dmarc_state(sc)
        exp = sc.get("exp")
        if exp:  # web-host exposure, reduced to the two facts we render
            rec["exp_webonly"] = bool(exp.get("cdn"))
            rec["exp_nonweb"] = bool(exp.get("o"))
        rec["sanctioned"] = (sc.get("ofac") not in ("clear", None))
        rec["leak_listed"] = bool(sc.get("rec"))
        orgs[p.get("w")] = rec
    rels = {}
    for r in (relationships.get("relationships") or []):
        rels[r["id"]] = {
            "evaluator": r.get("evaluator"),
            "evaluator_name": r.get("evaluator_name"),
            "model_id": r.get("model_id"),
            "model": r.get("model"),
            "lab": r.get("lab"),
            "access_type": r.get("access_type"),
            "documented_on": r.get("documented_on"),
            "source_url": (r.get("model_source") or {}).get("url"),
        }
    return {"date": date, "scan": scan_label, "orgs": orgs, "relationships": rels}

# Human labels for the observable fields, for the rendered feed.
FIELD_LABEL = {
    "dmarc_state": "DMARC policy", "dmarc": "DMARC record", "pct": "DMARC pct tag",
    "sectxt": "security.txt", "hsts": "HSTS", "mtasts": "MTA-STS", "dnssec": "DNSSEC",
    "caa": "CAA", "spf": "SPF", "dk": "DKIM", "host": "web host", "mail": "mail provider",
    "dns": "DNS provider", "sanctioned": "sanctions standing", "leak_listed": "leak-site listing",
    "exp_webonly": "web-host: only web ports", "exp_nonweb": "web-host: non-web services",
}
# Fields whose change is material enough to surface in the feed. Provider/label
# churn (host/mail/dns strings) is captured in the snapshot but not fed, to keep
# the feed about security posture rather than vendor renames.
FEED_FIELDS = ["dmarc_state", "sectxt", "hsts", "mtasts", "dnssec", "caa",
               "sanctioned", "leak_listed", "exp_nonweb"]

def diff(prev, cur):
    """Classified changes from snapshot `prev` to snapshot `cur`."""
    out = []
    pdate = prev.get("date")
    # ---- relationships ----
    pr, cr = prev.get("relationships") or {}, cur.get("relationships") or {}
    for rid in cr:
        if rid not in pr:
            r = cr[rid]
            pub = r.get("documented_on") or ""
            newevent = bool(pub) and pub > (pdate or "")
            out.append({
                "category": "new-event" if newevent else "newly-documented",
                "kind": "relationship",
                "subject": r.get("evaluator_name") or r.get("evaluator"),
                "model": r.get("model"),
                "prev": None,
                "cur": r.get("access_type"),
                "detail": (("A newly published source (dated %s) documents " % pub) if newevent
                           else ("An existing source (dated %s), newly recorded, documents " % pub))
                          + "%s evaluating %s." % (r.get("evaluator_name") or r.get("evaluator"), r.get("model")),
                "source_url": r.get("source_url"), "date": pub,
            })
        else:
            a, b = pr[rid], cr[rid]
            if a.get("access_type") != b.get("access_type"):
                out.append({
                    "category": "observation-change", "kind": "relationship",
                    "subject": b.get("evaluator_name") or b.get("evaluator"), "model": b.get("model"),
                    "prev": a.get("access_type"), "cur": b.get("access_type"),
                    "detail": "Documented access type changed for %s / %s." % (b.get("evaluator_name"), b.get("model")),
                    "source_url": b.get("source_url"), "date": cur.get("date"),
                })
    for rid in pr:
        if rid not in cr:
            r = pr[rid]
            out.append({
                "category": "removed", "kind": "relationship",
                "subject": r.get("evaluator_name") or r.get("evaluator"), "model": r.get("model"),
                "prev": r.get("access_type"), "cur": None,
                "detail": "Relationship no longer documented: %s / %s." % (r.get("evaluator_name"), r.get("model")),
                "source_url": r.get("source_url"), "date": cur.get("date"),
            })
    # ---- organizations / observations ----
    po, co = prev.get("orgs") or {}, cur.get("orgs") or {}
    for dom in co:
        if dom not in po:
            out.append({
                "category": "newly-documented", "kind": "organization",
                "subject": dom, "field": None, "prev": None, "cur": None,
                "detail": "Organization %s added to the map." % dom, "date": cur.get("date"),
            })
            continue
        for f in FEED_FIELDS:
            a, b = po[dom].get(f), co[dom].get(f)
            if a != b:
                out.append({
                    "category": "observation-change", "kind": "organization",
                    "subject": dom, "field": FIELD_LABEL.get(f, f),
                    "prev": a, "cur": b,
                    "detail": "%s: %s changed." % (dom, FIELD_LABEL.get(f, f)),
                    "date": cur.get("date"),
                })
    for dom in po:
        if dom not in co:
            out.append({
                "category": "removed", "kind": "organization", "subject": dom,
                "prev": None, "cur": None,
                "detail": "Organization %s removed from the map." % dom, "date": cur.get("date"),
            })
    return out

def load_snapshots():
    files = sorted(glob.glob(_p("snapshots", "*.json")))
    snaps = []
    for f in files:
        base = os.path.basename(f)
        if base == "index.json":
            continue
        snaps.append(json.load(open(f)))
    snaps.sort(key=lambda s: s.get("date") or "")
    return snaps

def build_feed(snaps):
    """The full change feed across every consecutive pair, newest first."""
    feed = []
    for i in range(1, len(snaps)):
        for c in diff(snaps[i - 1], snaps[i]):
            c = dict(c); c["snapshot"] = snaps[i].get("date")
            feed.append(c)
    feed.sort(key=lambda c: (c.get("snapshot") or "", c.get("date") or ""), reverse=True)
    return feed

def feed_meta(snaps):
    return {
        "snapshots": [s.get("date") for s in snaps],
        "baseline": snaps[0].get("date") if snaps else None,
        "latest": snaps[-1].get("date") if snaps else None,
        "count": len(snaps),
    }

def _write():
    scan = _load("data/scan_meta.json")
    date = scan.get("iso") or scan.get("date")
    snap = capture(_load("data/providers.json"), _load("data/relationships.json"),
                   date, scan.get("date"))
    os.makedirs(_p("snapshots"), exist_ok=True)
    path = _p("snapshots", "%s.json" % date)
    json.dump(snap, open(path, "w"), indent=1, ensure_ascii=False)
    print("wrote snapshots/%s.json  (%d orgs, %d relationships)"
          % (date, len(snap["orgs"]), len(snap["relationships"])))

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "write":
        _write()
    else:
        snaps = load_snapshots()
        feed = build_feed(snaps)
        print("snapshots:", feed_meta(snaps))
        print("change-feed entries:", len(feed))
        for c in feed[:20]:
            print(" ", c["category"], "|", c.get("subject"), "|", c.get("detail"))
