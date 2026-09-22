"""Build the site from the engine and the data. Run from the repo root:  python3 src/build.py
Reads data/providers.json, data/hold.json, controls.json, questionnaire.json, methodology.json,
substitutes them into src/template.html and src/assessment-template.html, and writes the
standalone site: index.html and assessment.html at the repo root (what Vercel serves)."""
import json, re, os, sys
ROOT=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
P=lambda *a: os.path.join(ROOT,*a)
rd=lambda *a: open(P(*a)).read().strip()
sys.path.insert(0, P('scripts'))
import snapshot as _snap   # change-feed engine, shared with the tests and the rescan
tpl=rd('src','template.html')
data=rd('data','providers.json'); hold=rd('data','hold.json')
scan=rd('data','scan_meta.json'); ctrl=rd('controls.json'); ques=rd('questionnaire.json'); meth=rd('methodology.json')
rel=rd('data','relationships.json')
checks=rd('data','check_proposals.json')
for name,blob in [('scan',scan),('providers',data),('controls',ctrl),('questionnaire',ques),('methodology',meth),('hold',hold),('relationships',rel),('check_proposals',checks)]:
    json.loads(blob)   # fail loudly on a malformed data file
# change feed, computed at build time from the committed snapshots (empty at baseline)
_snaps=_snap.load_snapshots()
changes=json.dumps(_snap.build_feed(_snaps), ensure_ascii=False)
snapmeta=json.dumps(_snap.feed_meta(_snaps), ensure_ascii=False)
body=(tpl.replace('__DATA__',data).replace('__ECON__','{}').replace('__CONTROLS__',ctrl)
         .replace('__QUESTIONS__',ques).replace('__METHOD__',meth).replace('__HOLD__',hold).replace('__SCAN__',scan)
         .replace('__RELATIONSHIPS__',rel).replace('__CHANGES__',changes).replace('__SNAPMETA__',snapmeta)
         .replace('__CHECKS__',checks))
m=re.match(r'\s*<title>(.*?)</title>\s*',body,re.S); title=m.group(1); rest=body[m.end():]
DESC='A curb inspection of the organizations in the AI-risk debate: the labs, the evaluators they entrust with unreleased models, the groups warning the public, and the institutes charged with measuring the risk. Read from the public record against a published code. A record, not a grade.'
head=('<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n'
'<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">\n'
f'<meta name="description" content="{DESC}">\n'
'<meta property="og:title" content="The Frontier Perimeter">\n'
'<link rel="canonical" href="https://frontier-perimeter.vercel.app/">\n'
'<meta property="og:type" content="website">\n'
'<meta property="og:url" content="https://frontier-perimeter.vercel.app/">\n'
'<meta property="og:site_name" content="The Frontier Perimeter">\n'
'<meta property="og:image" content="https://frontier-perimeter.vercel.app/og.png">\n'
'<meta property="og:image:width" content="2400">\n'
'<meta property="og:image:height" content="1260">\n'
'<meta property="og:image:alt" content="The Frontier Perimeter — a curb inspection of the organizations in the AI-risk debate.">\n'
'<meta name="twitter:card" content="summary_large_image">\n'
'<meta name="twitter:title" content="The Frontier Perimeter">\n'
'<meta name="twitter:description" content="A frontier lab’s attack surface includes everyone it lets test the model. 65 organizations, read from the curb against a published code.">\n'
'<meta name="twitter:image" content="https://frontier-perimeter.vercel.app/og.png">\n'
'<meta property="og:description" content="A frontier lab’s attack surface includes everyone it lets test the model. 65 organizations, read from the curb against a published code.">\n'
'<meta name="theme-color" content="#072a3a">\n'
f'<title>{title}</title>\n<style>\n'
':root{color-scheme:dark light;padding-top:env(safe-area-inset-top,0px);padding-bottom:env(safe-area-inset-bottom,0px)}\n'
'html,body{margin:0}\nimg{max-width:100%}\n[hidden]{display:none!important}\n</style>\n</head>\n<body>\n')
open(P('index.html'),'w').write(head+rest+'\n</body>\n</html>\n')
atpl=rd('src','assessment-template.html').replace('__QUESTIONS__',ques)
am=re.match(r'\s*<title>(.*?)</title>\s*',atpl,re.S); arest=atpl[am.end():]
ahead=('<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n'
'<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">\n'
'<meta name="theme-color" content="#072a3a">\n'
f'<title>{am.group(1)}</title>\n<style>\n:root{{color-scheme:dark light}}\nhtml,body{{margin:0}}\n[hidden]{{display:none!important}}\n</style>\n</head>\n<body>\n')
open(P('assessment.html'),'w').write(ahead+arest+'\n</body>\n</html>\n')
n=sum(len(c['p']) for s in json.loads(data) for c in s['cats'])
print(f'built index.html ({len(head+rest):,} bytes, {n} organizations) and assessment.html')
