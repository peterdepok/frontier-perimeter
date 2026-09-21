"""Assemble the curated population (data/actors.json) from the per-ring research files.
Every actor carries: the document that put it here (su), a verbatim excerpt (q), and why (ev).
Inclusion rule: an actor is here because it put its own name to a written commitment or
warning about AI risk or security, or because a frontier lab's own document records
entrusting it with model access. Nothing is here on the author's judgement of who matters."""
import json, os
H=os.path.dirname(os.path.abspath(__file__))
L=lambda f: json.load(open(os.path.join(H,f)))
A=L('ringA.json'); B=L('ringB.json'); Cv={x['name']:x for x in L('ringC_verified.json')}
Dv={x['name']:x for x in L('ringD_verified.json')}; D={x['name']:x for x in L('ringD.json')}
E={x['name']:x for x in L('ringE.json')}; C={x['name']:x for x in L('ringC.json')}

SEOUL='https://www.gov.uk/government/publications/frontier-ai-safety-commitments-ai-seoul-summit-2024/frontier-ai-safety-commitments-ai-seoul-summit-2024'
SEOUL_Q='invest in cybersecurity and insider threat safeguards to protect proprietary and unreleased model weights'
CCD='https://openai.com/collective-cyberdefense/'
CCD_Q='fix the highest-risk weaknesses'
NETWORK='https://www.nist.gov/news-events/news/2024/11/fact-sheet-us-department-commerce-us-department-state-launch-international'

actors=[]
def add(**k):
    k.setdefault('also',[]); k.setdefault('u',0); k.setdefault('note','')
    actors.append(k)

# ---------- Ring A: Committed (Seoul Frontier AI Safety Commitments) ----------
REG={'Amazon':'United States','Anthropic':'United States','Cohere':'Canada & Europe','Google':'United States','G42':'Middle East',
 'IBM':'United States','Inflection AI':'United States','Meta':'United States','Microsoft':'United States','Mistral AI':'Canada & Europe',
 'Naver':'East Asia','OpenAI':'United States','Samsung Electronics':'East Asia','Technology Innovation Institute':'Middle East',
 'xAI':'United States','Zhipu AI (Z.ai)':'East Asia','Magic':'United States','MiniMax':'East Asia','01.AI':'East Asia','NVIDIA':'United States'}
CCD_SIGNED={'Anthropic','Google','Microsoft','OpenAI','Amazon','IBM'}
for a in A:
    also=[]
    if a['name'] in CCD_SIGNED:
        also.append({'doc':'Collective Cyber Defense letter (Aug 2026), signatory'+(' (as AWS)' if a['name']=='Amazon' else ''),'u':CCD,'q':CCD_Q})
    add(ring='committed',cat=REG[a['name']],n=a['name'],w=a['domain'],hq=a.get('hq',''),kind='company',
        t='Frontier developer',f='expert',
        c='Signed the Frontier AI Safety Commitments, which pledge investment in cybersecurity and insider-threat safeguards for unreleased model weights.',
        doc='Frontier AI Safety Commitments, AI Seoul Summit (May 2024)',su=SEOUL,q=SEOUL_Q,
        fw=a.get('framework',''),record=a.get('record',''),also=also,note=a.get('note',''))

# ---------- Ring C: Entrusted (named in a lab's own system card) ----------
CCAT={'METR':'Evaluation nonprofits','Apollo Research':'Evaluation nonprofits','FAR.AI':'Evaluation nonprofits','SecureBio':'Evaluation nonprofits',
 'Epoch AI':'Evaluation nonprofits','Irregular (formerly Pattern Labs)':'Red-team and security firms','Gray Swan AI':'Red-team and security firms',
 'Haize Labs':'Red-team and security firms','Virtue AI':'Red-team and security firms','Trajectory Labs, PBC':'Red-team and security firms',
 '10a Labs':'Red-team and security firms','Faculty':'Domain specialists','Signature Science':'Domain specialists',
 'UK AI Security Institute':'Government evaluators','US Center for AI Standards and Innovation (CAISI)':'Government evaluators'}
DISPLAY={'US Center for AI Standards and Innovation (CAISI)':'US Center for AI Standards and Innovation (CAISI)','Trajectory Labs, PBC':'Trajectory Labs'}
for nm,cat in CCAT.items():
    v=Cv[nm]; base=C.get(nm) or next((x for x in C.values() if x['name'].startswith(nm.split(' (')[0])),{})
    kind='government' if cat=='Government evaluators' else (base.get('kind') or 'company')
    note=''
    if nm=='Virtue AI': note='Virtue AI states it has been acquired by Fortinet; read under its own domain.'
    if nm=='Irregular (formerly Pattern Labs)': note='Named as Pattern Labs in the GPT-5 system card (Aug 2025).'
    if nm.startswith('US Center'): note='No domain of its own: the curb read is of nist.gov, its parent agency.'
    also=[]
    if cat=='Government evaluators':
        also.append({'doc':'International Network of AI Safety Institutes, founding member (Nov 2024)','u':NETWORK,'q':''})
    add(ring='entrusted',cat=cat,n=DISPLAY.get(nm,nm),w=v['domain'],hq=base.get('hq',''),kind=kind,
        t='Pre-deployment evaluator',f='specialist',
        c='Named in a frontier lab’s own system card as an external evaluator or red team.',
        doc=v['doc'],su=v['source'],q=v['quote'],also=also,note=note,
        parent=('nist.gov' if nm.startswith('US Center') else ''))

# ---------- Ring D: Warning the public ----------
DCAT={'Future of Life Institute (FLI)':'Lab raters','SaferAI':'Lab raters','The Midas Project':'Lab raters',
 'Center for AI Safety (CAIS)':'Research institutes','Machine Intelligence Research Institute (MIRI)':'Research institutes',
 'Redwood Research':'Research institutes','Palisade Research':'Research institutes','Centre for the Study of Existential Risk (CSER)':'Research institutes',
 'Centre for Long-Term Resilience (CLTR)':'Research institutes',
 'ControlAI':'Campaigns and public education','PauseAI (Global)':'Campaigns and public education','PauseAI US':'Campaigns and public education',
 'Encode':'Campaigns and public education','CeSIA (Centre pour la Sécurité de l\'IA)':'Campaigns and public education',
 'Existential Risk Observatory':'Campaigns and public education','AISafety.info (Stampy)':'Campaigns and public education'}
for nm,cat in DCAT.items():
    v=Dv[nm]; base=next((x for x in D.values() if x['name'].split(' (')[0]==nm.split(' (')[0]),{})
    note=''
    if nm.startswith('CeSIA'): note='The Global Call for AI Red Lines was issued jointly with The Future Society and CHAI; CeSIA is a co-organizer.'
    if nm.startswith('ControlAI'): note='controlai.com redirects to controlai.org; the curb read is of controlai.org.'
    if nm.startswith('AISafety'): note='A fiscally sponsored project (Ashgro Inc.) that runs its own domain.'
    if nm.startswith('Existential'): note='Quote taken from the organization’s homepage; its stronger AI-specific posts should be checked in a browser.'
    add(ring='warning',cat=cat,n=nm,w=v['domain'],hq=v.get('hq') or base.get('hq',''),kind='nonprofit',
        t='Lab rater' if cat=='Lab raters' else 'AI-risk organization',f='capable',
        c='Published, under its own name, a rating of AI labs’ safety practices.' if cat=='Lab raters' else 'Published, under its own name, a warning of catastrophic or extinction-level risk from AI.',
        doc=v['doc'],su=v['source'],q=v['quote'],note=note)

# ---------- Ring E: Institutes (network members, less those already Entrusted) ----------
ECAT={'Japan AI Safety Institute (J-AISI)':'Own domain','Korea AI Safety Institute (Korea AISI)':'Own domain','Singapore AI Safety Institute':'Own domain',
 'Canadian Artificial Intelligence Safety Institute (CAISI)':'Under a government parent','Institut national pour l\'évaluation et la sécurité de l\'intelligence artificielle (INESIA)':'Under a government parent',
 'European AI Office':'Under a government parent','Australian AI Safety Institute':'Under a government parent'}
SHORT={'Institut national pour l\'évaluation et la sécurité de l\'intelligence artificielle (INESIA)':'INESIA (France)','Canadian Artificial Intelligence Safety Institute (CAISI)':'Canadian AI Safety Institute'}
for nm,cat in ECAT.items():
    e=E[nm]; par=e['domain'] if cat=='Under a government parent' else ''
    add(ring='institutes',cat=cat,n=SHORT.get(nm,nm),w=e['domain'],hq=e.get('hq',''),kind='government',
        t='Government AI safety institute',f='capable',
        c='A member of the international network of government AI safety institutes, the bodies charged with measuring frontier-model risk.',
        doc='International Network of AI Safety Institutes (Nov 2024; renamed Dec 2025)',su=e['source'],q='',
        note=('No domain of its own: the curb read is of '+par+', its parent.' if par else ''),parent=par,fullname=nm)

# ---------- Ring B slice: signed the Collective Cyber Defense letter ----------
BSEL={'Cognition':'AI developers','Hugging Face':'AI developers','Perplexity':'AI developers','Scale AI':'AI developers',
      'Bitsight':'Security-ratings firms','Black Kite':'Security-ratings firms','Security Scorecard':'Security-ratings firms'}
for b in B:
    if b['name'] in BSEL:
        cat=BSEL[b['name']]
        add(ring='letter',cat=cat,n=('SecurityScorecard' if b['name']=='Security Scorecard' else b['name']),w=b['domain'],hq=b.get('hq',''),kind='company',
            t='Security-ratings firm' if cat=='Security-ratings firms' else 'AI developer',f='expert',
            c=('Signed a letter asking every organization to fix its highest-risk weaknesses, and sells outside-in security ratings of other companies.' if cat=='Security-ratings firms'
               else 'Signed a letter asking every organization to fix its highest-risk weaknesses.'),
            doc='Collective Cyber Defense letter (Aug 2026), signatory',su=CCD,q=CCD_Q,note=b.get('note','') if cat=='AI developers' else '')

HOLD=[
 ('Andon Labs','andonlabs.com','Named in Anthropic system cards under an "External testing" heading, but no sentence confirming pre-release access was verified.'),
 ('Eleos AI Research','eleosai.org','Named for an external welfare assessment in the Mythos Preview card; no pre-release wording verified.'),
 ('Centre for the Governance of AI','governance.ai','Qualifying text is a co-authored paper led by Google DeepMind, not an organizational warning.'),
 ('AI Futures Project','aifutures.org','Its AI 2027 scenario is a forecast narrative; no direct organizational warning verified on its own site.'),
 ('AI Lab Watch','ailabwatch.org','A one-person project; its site says maintenance stopped in September 2025.'),
 ('UpGuard','upguard.com','A security-ratings firm, but not a signatory of the Collective Cyber Defense letter, so it has no signed document to anchor inclusion.'),
 ('Deloitte','deloitte.com','Named in Anthropic cards for evaluations "developed with" it, not for model access.'),
 ('Coefficient Giving and the Survival and Flourishing Fund','coefficientgiving.org','Funders of AI-safety work; a candidate "money behind the warning" ring for a later edition.'),
 ('IndiaAI Safety Institute and Kenya','indiaai.gov.in','India is not a network member; Kenya is a member without a dedicated institute.'),
 ('~150 security vendors that signed the letter','','Cyber companies, not AI-risk actors. A possible second edition.')]
out={'actors':actors,'hold':[{'n':a,'w':b,'why':c} for a,b,c in HOLD]}
json.dump(out,open(os.path.join(H,'..','data','actors.json'),'w'),ensure_ascii=False,indent=1)
from collections import Counter
print(len(actors), Counter(a['ring'] for a in actors))
print([a['n'] for a in actors if not a['w']])
