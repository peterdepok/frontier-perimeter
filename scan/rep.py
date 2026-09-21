"""Network reputation (C3): is the actor's web address on the FireHOL level1 blocklist?
One public list, fetched once. The address comes from infra_results.json (scan/infra.py)."""
import json, ipaddress, urllib.request, os
import domains as _d
URL='https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset'
nets=[ipaddress.ip_network(l.strip()) for l in urllib.request.urlopen(URL,timeout=60).read().decode().splitlines() if l and not l.startswith('#')]
infra=json.load(open(_d.ck('infra_results.json'))); out={}
for d in _d.domains():
    ip=infra.get(d,{}).get('ip')
    if not ip: out[d]={'d':d,'rep':'?'}; continue
    a=ipaddress.ip_address(ip); hit=any(a in n for n in nets)
    out[d]={'d':d,'rep':'listed' if hit else 'clean','ip':ip}
json.dump(out,open(_d.ck('rep.json'),'w'),indent=0)
print('listed',[d for d,v in out.items() if v['rep']=='listed'],'clean',sum(v['rep']=='clean' for v in out.values()))
