import json,os,time,dns.resolver
from concurrent.futures import ThreadPoolExecutor
import domains as _d
CK=_d.ck('posture_results.json')
done=json.load(open(CK)) if os.path.exists(CK) else {}
def txt(q,tries=3):
    for i in range(tries):
        try:
            R=dns.resolver.Resolver();R.lifetime=8+4*i;R.timeout=5+2*i
            return [b''.join(x.strings).decode('utf8','ignore') for x in R.resolve(q,'TXT')]
        except (dns.resolver.NoAnswer,dns.resolver.NXDOMAIN,dns.resolver.NoNameservers): return []   # absent, not unknown
        except Exception: time.sleep(0.3)
    return None
def caa(d,tries=3):
    for i in range(tries):
        try:
            R=dns.resolver.Resolver();R.lifetime=8+4*i;R.timeout=5+2*i
            a=R.resolve(d,'CAA'); return [str(x) for x in a]
        except (dns.resolver.NoAnswer,dns.resolver.NXDOMAIN,dns.resolver.NoNameservers): return []
        except Exception: time.sleep(0.3)
    return None
def go(d):
    o={'d':d}
    for key,q,tag in [('mtasts','_mta-sts.'+d,'v=STSv1'),('tlsrpt','_smtp._tls.'+d,'v=TLSRPTv1'),('bimi','default._bimi.'+d,'v=BIMI1')]:
        r=txt(q); o[key]= '?' if r is None else ('yes' if any(tag in x for x in r) else 'no')
    c=caa(d)
    o['caa']= '?' if c is None else ('yes' if c else 'no')
    return o
doms=_d.domains()
todo=[x for x in doms if x not in done]; n=0
with ThreadPoolExecutor(26) as ex:
    for r in ex.map(go,todo):
        done[r['d']]=r; n+=1
        if n%80==0: json.dump(done,open(CK+'.t','w')); os.replace(CK+'.t',CK); print('  ..',len(done),flush=True)
json.dump(done,open(CK+'.t','w')); os.replace(CK+'.t',CK); print('DONE',len(done),flush=True)
