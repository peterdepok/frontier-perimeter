"""Origin exposure (B3; B4 and C1 held to Level 2): each website address is looked up in
Shodan's passive InternetDB. Nothing is sent to the organization. The public file carries one
flag per domain; the port and CVE detail is written only to a gitignored Level-2 file."""
import json, urllib.request, urllib.error, time, datetime
import domains as _d
WEB={80,443,8080,8443,8880,2052,2053,2082,2083,2086,2087,2095,2096}
ADMIN={21,22,23,135,139,445,1433,1521,2222,2082,2083,2086,2087,3306,3389,5432,5900,5985,5986,6379,9200,10000,11211,27017}
CDN=('cloudflare','incapsula','imperva','akamai','fastly','cloudfront','sucuri')
infra=json.load(open(_d.ck('infra_results.json'))); pub={'_meta':{'source':'Shodan InternetDB','read':datetime.date.today().isoformat(),
 'rule':'cdn = CDN/WAF edge; edge = shared managed web edge answering only web ports; origin = address also answering remote-admin, file-transfer or database services'}}; priv={}
for d in _d.domains():
    ip=infra.get(d,{}).get('ip')
    if not ip: pub[d]={'k':'na'}; continue
    try:
        with urllib.request.urlopen('https://internetdb.shodan.io/'+ip,timeout=20) as r: j=json.loads(r.read())
    except urllib.error.HTTPError as e:
        pub[d]={'ip':ip,'k':'na'}; continue
    ports=set(j.get('ports',[])); cpes=' '.join(j.get('cpes',[])).lower(); cdn=any(c in cpes for c in CDN) or 'cdn' in j.get('tags',[])
    admin=(ports&ADMIN)-(WEB if cdn else set())   # 2082-2087 are Cloudflare edge ports on a CDN, cPanel/WHM on a bare host
    if cdn and len(ports)>40: k='cdn'
    elif admin: k='origin'
    else: k='cdn' if cdn else 'edge'
    pub[d]={'ip':ip,'k':k}
    if k=='origin': priv[d]={'ip':ip,'ports':sorted(ports),'vulns':len(j.get('vulns',[]))}
    time.sleep(0.3)
json.dump(pub,open(_d.ck('exposure.json'),'w'),indent=0); json.dump(priv,open(_d.ck('exposure_L2_PRIVATE.json'),'w'),indent=0)
print('origin',[d for d,v in pub.items() if isinstance(v,dict) and v.get('k')=='origin'])
