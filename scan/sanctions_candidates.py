"""Sanctions screening (F1), candidate stage. Downloads the US Consolidated Screening List and
writes every exact normalized name/alias match to out/sanctions_candidates.json for a person to
review. It never writes the reviewed file (out/sanctions.json) that the site is built from:
a name match is not a finding until someone has read it."""
import csv, io, json, re, unicodedata, urllib.request, datetime
import domains as _d
URL='https://data.trade.gov/downloadable_consolidated_screening_list/v1/consolidated.csv'
A=json.load(open(_d.ROOT+'/data/actors.json'))['actors']
def N(s):
    s=unicodedata.normalize('NFKD',s or '').encode('ascii','ignore').decode().lower()
    s=re.sub(r'\(.*?\)',' ',s); s=re.sub(r'[^a-z0-9 ]',' ',s)
    s=re.sub(r'\b(inc|llc|ltd|limited|co|corp|corporation|company|pbc|gmbh|sa|sas|plc|the)\b',' ',s)
    return re.sub(r'\s+',' ',s).strip()
want={}
for a in A:
    for n in [a['n'],a.get('fullname','')]+a.get('legal',[]):
        if n: want[N(n)]=a['w']
rows=list(csv.DictReader(io.StringIO(urllib.request.urlopen(URL,timeout=120).read().decode('utf8','ignore'))))
hits=[]
for r in rows:
    for c in [r.get('name','')]+(r.get('alt_names') or '').split(';'):
        if N(c) in want: hits.append({'domain':want[N(c)],'name':r.get('name'),'matched':c.strip(),'source':r.get('source'),'start':r.get('start_date'),'frn':r.get('federal_register_notice')}); break
json.dump({'read':datetime.date.today().isoformat(),'entries':len(rows),'hits':hits},open(_d.ck('sanctions_candidates.json'),'w'),indent=1)
print('entries',len(rows),'candidate matches',len(hits))
