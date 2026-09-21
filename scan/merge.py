"""Merge every curb layer in scan/out/ onto the actor list and write data/providers.json
(the rings > categories > actors shape the renderer reads). Public flags only: the port and
vulnerability detail behind the origin-exposure flag stays in the gitignored Level-2 file."""
import json, os, re
from collections import OrderedDict
import domains as _d
R=_d.ROOT; L=lambda n: json.load(open(_d.ck(n))) if os.path.exists(_d.ck(n)) else {}
A=json.load(open(os.path.join(R,'data','actors.json')))
scan=L('scan_results.json'); post=L('posture_results.json'); dk=L('dkim.json'); inf=L('infra_results.json')
ovr=L('overrides.json'); look=L('look.json'); rep=L('rep.json'); http=L('http.json'); expo=L('exposure.json'); sanc=L('sanctions.json'); leaks=L('leaks.json')
RINGS=[('entrusted','Entrusted','Named in a frontier lab’s own system card as an external evaluator or red team given access to a model before release. This is the perimeter the argument is about: every organization here has held, at some point, a model its developer had not yet shipped.'),
 ('committed','The labs','The twenty developers that signed the Frontier AI Safety Commitments at Seoul in May 2024, which include a pledge to invest in cybersecurity and insider-threat safeguards for unreleased model weights. The vault the perimeter surrounds.'),
 ('warning','Warning the public','Organizations that have published, under their own name, a warning of catastrophic or extinction-level risk from AI, or a rating of the labs’ safety practices.'),
 ('institutes','Institutes','Government AI safety institutes in the international network, beyond the two already listed as evaluators. The public bodies charged with measuring frontier risk.'),
 ('letter','Signed the defense letter','AI developers and security-ratings firms that signed the Collective Cyber Defense letter of 27 August 2026, whose first ask of every organization is to fix its highest-risk weaknesses.')]
def base_len(d): return len(d.split('.')[0])
def sc_for(a):
    d=a['w']; s=scan.get(d,{}); p=post.get(d,{}); k=dk.get(d,{}); i=inf.get(d,{}); h=http.get(d,{})
    o={}
    o['dmarc']=s.get('dmarc','?')
    if 'pct' in s: o['pct']=s['pct']
    o['spf']=s.get('spf','?'); o['dnssec']=s.get('dnssec','?'); o['mx']=s.get('mx','?')
    for x in ('mtasts','tlsrpt','bimi','caa'): o[x]=p.get(x,'?')
    o['dk']=k.get('dkim','?')
    for x in ('host','cc','mail','dns'):
        if i.get(x): o[x]=i[x]
    if i.get('alive') is False: o['gone']=1
    # Level-1 DMARC floor
    if ovr.get(d,{}).get('mx'): o['mx']=ovr[d]['mx']; o['ovr']=ovr[d]['why']
    if s.get('rua'): o['rua']=1
    if o['dmarc'] in ('quarantine','reject'): o['L1']='meet'
    elif o['dmarc']=='?' or (o['dmarc']=='absent' and o['mx']=='?'): pass
    elif o['mx']=='no' and o['dmarc']=='absent': o['L1']='nomail'
    else: o['L1']='below'
    # look-alikes: homoglyphs and one-keystroke typos with live mail; TLD swaps dropped;
    # labels of four characters or fewer skipped (their typos are ordinary words and other businesses)
    lk=look.get(d,{})
    if lk and not lk.get('skip'):
        sld=d.split('.')[0]
        typo=lambda v: v.split('.',1)[1]==d.split('.',1)[1]
        hh=[v for v in lk.get('h',[]) if len(sld)>=5]
        yy=[v for v in lk.get('y',[]) if len(sld)>=5 and typo(v)]
        lo={}
        if hh: lo['h']=hh[:4]
        if yy: lo['y']=yy[:6]; lo['yn']=len(yy)
        if lk.get('dfn'): lo['d']=lk['dfn']
        if lo: o['look']=lo
        if len(sld)<5: o['look_short']=1
    elif lk.get('skip'): o['look_na']=1
    r=rep.get(d,{}).get('rep')
    if r: o['rep']=r
    c=expo.get(d,{}).get('k','na')
    if c in ('cdn','edge'): o['exp']={'cdn':1,'k':c}
    elif c=='origin': o['exp']={'o':1}
    if h:
        o['hsts']=h.get('hsts','?'); o['sectxt']=h.get('sectxt','?')
        if h.get('sectxt_exp'): o['sectxt_exp']=h['sectxt_exp']
        if h.get('host') and h['host'].replace('www.','')!=d: o['webhost']=h['host']
    # sanctions: floor lists (OFAC) vs. record lists (Commerce, State)
    if sanc.get('_meta'):
        z=sanc.get(d,{})
        o['ofac']=z.get('floor','clear')
        if z.get('record'):
            o['rec']=[{'t':x['list'].split(' - ')[0],'d':x['name']+', listed '+x['since']+' ('+x['frn']+'). '+(str(x.get('related',''))+' related Zhipu entities were listed the same day. ' if x.get('related') else '')+'The Entity List restricts exports of US-regulated items to the listed party; it is not a sanction on dealing with it, which is why it is recorded here and not scored against the Floor.','u':x['u']} for x in z['record']]
    if leaks.get('_meta'):
        hl=leaks.get('hits',{}).get(d)
        if hl: o['rw']=sorted(hl,key=lambda x:x['d'],reverse=True)
        o['rwread']=1
    if a.get('parent'): o['parent']=a['parent']
    return o
S=[]
for rid,name,desc in RINGS:
    acts=[a for a in A['actors'] if a['ring']==rid]
    cats=list(OrderedDict.fromkeys(a['cat'] for a in acts))
    CB={'Evaluation nonprofits':'Research nonprofits that run dangerous-capability and alignment evaluations.',
        'Red-team and security firms':'Companies paid to attack a model, its safeguards or its agents before launch.',
        'Domain specialists':'Firms brought in for a specific hazard: biology, chemistry, or applied AI.',
        'Government evaluators':'State institutes given pre-release access for national-security testing.',
        'Lab raters':'Organizations that publish grades of the labs.','Research institutes':'Research groups whose published work warns of catastrophic AI risk.',
        'Campaigns and public education':'Advocacy and explainer groups whose public message is the risk itself.',
        'Own domain':'Institutes that run a domain of their own.','Under a government parent':'Institutes that live on a ministry’s domain; the curb read is of the parent.',
        'AI developers':'Model and AI-product companies that signed.','Security-ratings firms':'Companies that sell outside-in security ratings of other companies. The Standard rates the raters.'}
    out=[]
    for ci,cn in enumerate(cats):
        ps=[]
        for a in [x for x in acts if x['cat']==cn]:
            p={'n':a['n'],'w':a['w'],'t':a['t'],'f':a['f'],'c':a['c'],'u':a.get('u',0),'x':0,'s':'c','m':[ci],
               'su':a['su'],'doc':a['doc'],'q':a.get('q',''),'hq':a.get('hq',''),'kind':a.get('kind',''),'also':a.get('also',[]),
               'ev':a['doc']+'.','sc':sc_for(a)}
            if a.get('note'): p['o']=a['note']
            if a.get('fw'): p['fw']=a['fw']
            if a.get('fullname'): p['full']=a['fullname']
            ps.append(p)
        out.append({'n':cn,'b':CB.get(cn,''),'p':ps})
    S.append({'id':rid,'name':name,'desc':desc,'cats':out})
json.dump(S,open(os.path.join(R,'data','providers.json'),'w'),ensure_ascii=False,separators=(',',':'))
import datetime
iso=os.environ.get('SCAN_ISO') or datetime.date.today().isoformat()
d0=datetime.date.fromisoformat(iso)
json.dump({'iso':iso,'date':f'{d0.day} {d0.strftime("%B %Y")}'},open(os.path.join(R,'data','scan_meta.json'),'w'))
json.dump(A['hold'],open(os.path.join(R,'data','hold.json'),'w'),ensure_ascii=False,indent=1)
n=sum(len(c['p']) for s in S for c in s['cats']); print('actors',n,[ (s['name'],sum(len(c['p']) for c in s['cats'])) for s in S])
