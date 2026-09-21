#!/usr/bin/env python3
"""Ransomware leak-site listings (G1), candidate stage, from ransomware.live's PRO API, month by month from 2021.
Writes out/leaks_candidates.json for a person to review; the site is built only from the reviewed out/leaks.json.
A listing is an attacker's published claim recorded as a matter of public record; it is matched to an
actor only when the victim's listed website is the actor's domain or a subdomain of it.
The API key is a SECRET: read from RANSOMWARE_LIVE_KEY or a gitignored .secrets/ransomware.live.key.
Never committed, never shipped in the site."""
import os, json, sys, time, datetime, pathlib, urllib.request
import domains as _d
ROOT=pathlib.Path(__file__).resolve().parent.parent
KEY=os.environ.get("RANSOMWARE_LIVE_KEY")
for kf in [ROOT/".secrets"/"ransomware.live.key", pathlib.Path(os.environ.get("RANSOMWARE_LIVE_KEYFILE","/nonexistent"))]:
    if not KEY and kf.exists(): KEY=kf.read_text().strip()
if not KEY: sys.exit("No API key. Set RANSOMWARE_LIVE_KEY or create .secrets/ransomware.live.key")
def get(p):
    r=urllib.request.Request("https://api-pro.ransomware.live"+p,headers={"X-API-KEY":KEY,"Accept":"application/json"})
    with urllib.request.urlopen(r,timeout=40) as x: return json.loads(x.read().decode())
def norm(s):
    h=str(s or "").lower().strip()
    for p in ("https://","http://"): h=h[len(p):] if h.startswith(p) else h
    if h.startswith("www."): h=h[4:]
    for c in "/:?#": h=h.split(c)[0]
    return h
roster=set(_d.domains())
def match(site):
    h=norm(site); L=h.split(".")
    for i in range(len(L)-1):
        c=".".join(L[i:])
        if c in roster: return c
t=datetime.date.today(); hits={}; months=0
for y in range(2021,t.year+1):
    for m in range(1,13):
        if y==t.year and m>t.month: break
        try: j=get(f"/victims/?year={y}&month={m:02d}"); months+=1
        except Exception as e: print(f"  {y}-{m:02d}: {e}",file=sys.stderr); continue
        for v in (j.get("victims") or []):
            d=match(v.get("website"))
            if d: hits.setdefault(d,[]).append({"g":v.get("group"),"d":(v.get("discovered") or "")[:10],"u":v.get("permalink"),"n":v.get("victim") or v.get("post_title")})
        time.sleep(0.05)
out={"_meta":{"read":str(t),"months":months,"source":"ransomware.live PRO API"},"hits":hits}
json.dump(out,open(_d.ck("leaks_candidates.json"),"w"),indent=1)   # reviewed by hand into leaks.json
print("months",months,"actors listed",len(hits),{k:len(v) for k,v in hits.items()})
