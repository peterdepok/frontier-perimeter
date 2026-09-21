import json,os,sys,time
import dns.resolver
from concurrent.futures import ThreadPoolExecutor

import domains as _d
CK=_d.ck('dkim.json')
done=json.load(open(CK)) if os.path.exists(CK) else {}

# selectors in rough likelihood order; short-circuit on first hit.
SEL=['google','selector1','selector2','k1','k2','s1','s2','mandrill','default','dkim',
     'fm1','fm2','fm3','zoho','zmail','mxvault','sig1','protonmail','protonmail2',
     'scph0819','ctct1','mail','smtp','key1','dkim1']

def has_key(name):
    try:
        R=dns.resolver.Resolver();R.lifetime=6;R.timeout=4
        recs=[b''.join(x.strings).decode('utf8','ignore') for x in R.resolve(name,'TXT')]
        return any(('v=dkim1' in x.lower().replace(' ','')) or ('p=' in x and 'k=' in x.lower()) or (len(x)>80 and 'p=' in x) for x in recs)
    except (dns.resolver.NoAnswer,dns.resolver.NXDOMAIN,dns.resolver.NoNameservers):
        return False
    except Exception:
        return None  # transient

def probe(d):
    unknown=False
    for s in SEL:
        r=has_key(s+'._domainkey.'+d)
        if r is True: return {'d':d,'dkim':'yes','sel':s}
        if r is None: unknown=True
    return {'d':d,'dkim':('?' if unknown else 'no')}

doms=_d.domains()
todo=[x for x in doms if x not in done]
BATCH=int(sys.argv[1]) if len(sys.argv)>1 else 0
if BATCH>0: todo=todo[:BATCH]
print('domains',len(doms),'todo',len(todo),flush=True)
if todo:
    n=0
    with ThreadPoolExecutor(28) as ex:
        for r in ex.map(probe,todo):
            done[r['d']]=r; n+=1
            if n%60==0:
                json.dump(done,open(CK+'.t','w')); os.replace(CK+'.t',CK)
                print('  ..',len(done),flush=True)
    json.dump(done,open(CK+'.t','w')); os.replace(CK+'.t',CK)
yes=sum(1 for v in done.values() if v['dkim']=='yes')
no=sum(1 for v in done.values() if v['dkim']=='no')
unk=sum(1 for v in done.values() if v['dkim']=='?')
print(f'DONE {len(done)}  yes={yes} no={no} unknown={unk}',flush=True)
