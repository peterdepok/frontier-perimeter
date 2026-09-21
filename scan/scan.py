import json,re,os,sys,time
import dns.resolver, dns.exception
from concurrent.futures import ThreadPoolExecutor

import domains as _d
CK=_d.ck('scan_results.json')
done=json.load(open(CK)) if os.path.exists(CK) else {}

def q(name,rdtype,tries=3):
    """Returns (status, records). status: 'ok' | 'none' | 'unknown'.
       'unknown' means we could not determine, and must never render as a negative."""
    last=None
    for i in range(tries):
        try:
            r=dns.resolver.Resolver(configure=False); r.nameservers=[['8.8.8.8','1.1.1.1','9.9.9.9'][i%3]]
            r.lifetime=5+3*i; r.timeout=3+2*i
            a=r.resolve(name,rdtype)
            return 'ok',[b''.join(x.strings).decode('utf8','ignore') if rdtype=='TXT' else str(x) for x in a]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return 'none',[]
        except dns.resolver.NoNameservers as e:   # SERVFAIL at one resolver is not an absence: try the next
            last=e; continue
        except Exception as e:
            last=e; time.sleep(0.3)
    return 'unknown',[]

def scan(dom):
    o={'d':dom}
    st,recs=q('_dmarc.'+dom,'TXT')
    if st=='unknown': o['dmarc']='?'
    else:
        dm=[t for t in recs if t.lower().replace(' ','').startswith('v=dmarc1')]
        if not dm: o['dmarc']='absent'
        else:
            m=re.search(r'\bp\s*=\s*(none|quarantine|reject)',dm[0],re.I)
            pol=m.group(1).lower() if m else 'none'
            pc=re.search(r'\bpct\s*=\s*(\d+)',dm[0],re.I)
            o['dmarc']=pol
            if pc: o['pct']=int(pc.group(1))
            o['rua']=bool(re.search(r'\brua\s*=',dm[0],re.I))
    st,recs=q(dom,'TXT')
    if st=='unknown': o['spf']='?'
    else:
        sp=[t for t in recs if t.lower().replace(' ','').startswith('v=spf1')]
        if not sp: o['spf']='absent'
        else:
            t=sp[0].lower().rstrip()
            o['spf']='hardfail' if t.endswith('-all') else ('softfail' if '~all' in t else ('neutral' if ('?all' in t or '+all' in t) else 'other'))
    st,_=q(dom,'DS'); o['dnssec']='?' if st=='unknown' else ('yes' if st=='ok' else 'no')
    st,_=q(dom,'MX');  o['mx']='?' if st=='unknown' else ('yes' if st=='ok' else 'no')
    return o

doms=_d.domains()
todo=[x for x in doms if x not in done]
BATCH=int(sys.argv[1]) if len(sys.argv)>1 else 260
todo=todo[:BATCH] if BATCH>0 else todo
if todo:
    n=0
    with ThreadPoolExecutor(30) as ex:
        for r in ex.map(scan,todo):
            done[r['d']]=r; n+=1
            if n%50==0:
                json.dump(done,open(CK+'.tmp','w')); os.replace(CK+'.tmp',CK)
                print(f'  ...{len(done)}',flush=True)
    json.dump(done,open(CK+'.tmp','w')); os.replace(CK+'.tmp',CK)
print(f'scanned {len(done)} / {len(doms)} domains ({len(doms)-len(done)} left)')
