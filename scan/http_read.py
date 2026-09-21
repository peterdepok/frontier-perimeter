"""HSTS (B2) and security.txt (F5): one ordinary GET of each public homepage and one of
/.well-known/security.txt, paced one host at a time. Nothing else is requested.
Same rules as the browser read that produced the first edition: HSTS meets the control at a
max-age of six months or more; security.txt counts when served as text with a Contact field
and an Expires date in the future. A refused read (403, bot challenge, timeout) is recorded
as not observable, never as a failure."""
import json, os, re, time, datetime, urllib.request, urllib.error, ssl
import domains as _d
CK=_d.ck('http.json'); UA='Mozilla/5.0 (compatible; FrontierPerimeter-curb/0.3; +https://github.com/peterdepok/frontier-perimeter)'
TODAY=datetime.date.today().isoformat()
def get(url):
    r=urllib.request.Request(url,headers={'User-Agent':UA,'Accept':'*/*'})
    with urllib.request.urlopen(r,timeout=15,context=ssl.create_default_context()) as x:
        return x.status, x.geturl(), dict((k.lower(),v) for k,v in x.headers.items()), x.read(20000).decode('utf8','ignore')
out={}
for d in _d.domains():
    o={'d':d}
    try:
        s,final,h,_=get('https://'+d+'/'); host=final.split('/')[2]; o['host']=host
        hs=h.get('strict-transport-security',''); m=re.search(r'max-age=(\d+)',hs); age=int(m.group(1)) if m else 0
        o['hsts']='yes' if age>=15552000 else ('short' if age>0 else 'no'); o['hsts_age']=age
    except Exception as e:
        o['hsts']='?'; host=d; o['err1']=str(e)[:80]
    try:
        s,_,h,t=get('https://'+host+'/.well-known/security.txt')
        c=re.search(r'^\s*Contact:\s*(.+)$',t,re.M|re.I); ex=re.search(r'^\s*Expires:\s*(.+)$',t,re.M|re.I)
        ok=s==200 and c and 'html' not in h.get('content-type','').lower()
        o['sectxt']='yes' if ok else 'no'
        if ex: o['sectxt_exp']=ex.group(1).strip()[:10]
        if ok and ex and ex.group(1).strip()[:10]<TODAY: o['sectxt']='expired'
    except urllib.error.HTTPError as e:
        o['sectxt']='no' if e.code==404 else '?'
    except Exception as e:
        o['sectxt']='?'; o['err2']=str(e)[:80]
    out[d]=o; time.sleep(1.0)
json.dump(out,open(CK,'w'),indent=0)
from collections import Counter
print('hsts',Counter(v['hsts'] for v in out.values()),'sectxt',Counter(v['sectxt'] for v in out.values()))
