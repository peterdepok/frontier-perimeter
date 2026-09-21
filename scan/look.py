"""Look-alike domains (A5): typo and homoglyph permutations of each actor's domain,
resolved against public DNS only. A variant is kept when it is registered AND publishes MX
(it can send/receive mail as the look-alike). A variant is counted as defensive, not as a
live look-alike, when its name servers or mail servers match the actor's own, or sit with a
brand-protection registrar. Nothing is fetched from, or sent to, any look-alike.
Government domains under restricted registries (gov.uk, go.jp, gov.au, gouv.fr, ...) are skipped."""
import json, os, re, time, dns.resolver
from concurrent.futures import ThreadPoolExecutor
import domains as _d
CK=_d.ck('look.json')
done=json.load(open(CK)) if os.path.exists(CK) else {}
RESTRICTED=re.compile(r'\.(gov|go|gouv|gc|europa|ac|re)\.[a-z]{2}$|\.gov$|\.europa\.eu$|\.canada\.ca$|\.gov\.[a-z]{2}$|\.ac\.uk$|\.re\.kr$|\.go\.jp$')
BRAND=re.compile(r'markmonitor|cscdns|csc\.com|comlaude|safenames|brandshelter|ebrand|nic\.com\.?$|appdetex',re.I)
HOMO={'o':['0'],'l':['1','i'],'i':['1','l'],'m':['rn'],'e':['3'],'a':['4'],'s':['5'],'g':['9'],'b':['8'],'w':['vv']}
ADJ={'q':'wa','w':'qes','e':'wrd','r':'etf','t':'ryg','y':'tuh','u':'yij','i':'uok','o':'ipl','p':'ol',
     'a':'qsz','s':'awdz','d':'sefx','f':'drgc','g':'fthv','h':'gyjb','j':'hukn','k':'jilm','l':'kop',
     'z':'asx','x':'zsdc','c':'xdfv','v':'cfgb','b':'vghn','n':'bhjm','m':'njk'}
TLDS=['com','ai','org','io','co','net','dev','app']
def split(d):
    p=d.split('.'); return p[0], '.'.join(p[1:])
def variants(d):
    sld,tld=split(d); V={}
    for i in range(len(sld)):
        V[sld[:i]+sld[i+1:]+'.'+tld]='y'                      # omission
        V[sld[:i]+sld[i]+sld[i:]+'.'+tld]='y'                 # repetition
        if i<len(sld)-1: V[sld[:i]+sld[i+1]+sld[i]+sld[i+2:]+'.'+tld]='y'  # transposition
        for r in ADJ.get(sld[i],''): V[sld[:i]+r+sld[i+1:]+'.'+tld]='y'   # adjacent key
        for r in HOMO.get(sld[i],[]): V[sld[:i]+r+sld[i+1:]+'.'+tld]='h'  # homoglyph
    for t in TLDS:
        if t!=tld and '.' not in tld: V[sld+'.'+t]='t'           # TLD swap
    V.pop(d,None)
    return {k:v for k,v in V.items() if len(split(k)[0])>=2 and not k.startswith('-')}
def res(n,rd):
    for i in range(2):
        try:
            R=dns.resolver.Resolver();R.lifetime=5+2*i;R.timeout=3+i
            return [str(x).lower() for x in R.resolve(n,rd)]
        except (dns.resolver.NoAnswer,dns.resolver.NXDOMAIN,dns.resolver.NoNameservers): return []
        except Exception: time.sleep(0.2)
    return None
def base(h): return '.'.join(h.rstrip('.').split('.')[-2:])
def go(d):
    if RESTRICTED.search(d): return {'d':d,'skip':'restricted registry'}
    ns0={base(x) for x in (res(d,'NS') or [])}; mx0={base(x.split()[-1]) for x in (res(d,'MX') or [])}
    h=[];y=[];dfn=0;unk=0
    for v,kind in variants(d).items():
        mx=res(v,'MX')
        if mx is None: unk+=1; continue
        if not mx: continue
        mxb={base(x.split()[-1]) for x in mx}
        if any(x in ('.','') for x in mxb) or any(x.endswith(' .') for x in mx): continue   # null MX: cannot receive mail
        ns={base(x) for x in (res(v,'NS') or [])}
        if (ns & ns0) or (mxb & mx0 and not mxb <= {'google.com','outlook.com','googlemail.com'}) or any(BRAND.search(x) for x in ns):
            dfn+=1; continue
        (h if kind=='h' else y).append(v)
    return {'d':d,'h':sorted(h),'y':sorted(y),'dfn':dfn,'unk':unk}
todo=[x for x in _d.domains() if x not in done]
print('todo',len(todo),flush=True)
with ThreadPoolExecutor(16) as ex:
    for r in ex.map(go,todo):
        done[r['d']]=r; json.dump(done,open(CK+'.t','w')); os.replace(CK+'.t',CK)
print('DONE',len(done))
