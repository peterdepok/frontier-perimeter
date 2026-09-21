import json,os,re,socket,time
import dns.resolver
from concurrent.futures import ThreadPoolExecutor
import domains as _d
CK=_d.ck('infra_results.json')
done=json.load(open(CK)) if os.path.exists(CK) else {}

HOST=[('Amazon Web Services',r'AMAZON|AWS'),('Microsoft Azure',r'MICROSOFT'),('Google Cloud',r'GOOGLE'),
 ('Cloudflare',r'CLOUDFLARE'),('Akamai',r'AKAMAI|LINODE'),('Fastly',r'FASTLY'),('GoDaddy',r'GODADDY'),
 ('DigitalOcean',r'DIGITALOCEAN'),('OVH',r'\bOVH'),('Hetzner',r'HETZNER'),('Rackspace',r'RACKSPACE'),
 ('Squarespace',r'SQUARESPACE'),('WordPress.com',r'AUTOMATTIC|WORDPRESS'),('Wix',r'\bWIX'),
 ('Shopify',r'SHOPIFY'),('Newfold (Bluehost)',r'UNIFIEDLAYER|BLUEHOST|HOSTGATOR|NEWFOLD'),
 ('IONOS',r'IONOS|1AND1'),('Web.com',r'NETWORK-SOLUTIONS|WEBCOM|WEB\.COM'),('Vultr',r'VULTR|CONSTANT'),
 ('Alibaba Cloud',r'ALIBABA'),('Tencent Cloud',r'TENCENT'),('Oracle Cloud',r'ORACLE'),
 ('Equinix',r'EQUINIX'),('Hostinger',r'HOSTINGER'),('Namecheap',r'NAMECHEAP'),('Liquid Web',r'LIQUIDWEB'),
 ('Wpengine',r'WPENGINE'),('HubSpot',r'HUBSPOT'),('Netlify/Vercel',r'NETLIFY|VERCEL'),('Incapsula',r'INCAPSULA|IMPERVA')]
MAIL=[('Microsoft 365',r'outlook|protection\.outlook|microsoft'),('Google Workspace',r'google|googlemail'),
 ('Proofpoint',r'pphosted|proofpoint'),('Mimecast',r'mimecast'),('Barracuda',r'barracuda|\bess\.'),
 ('Cisco Secure Email',r'iphmx|cisco'),('Fortinet',r'fortimail'),('Trend Micro',r'trendmicro|\bhes\.'),
 ('Sophos',r'sophos'),('Zoho',r'zoho'),('GoDaddy',r'secureserver'),('Rackspace',r'emailsrvr'),
 ('Mailprotector',r'mailprotector'),('Intermedia',r'intermedia'),('Titan/Hostinger',r'titan\.email|hostinger'),
 ('Fasthosts/IONOS',r'ionos|1and1|fasthosts'),('Cloudflare',r'cloudflare')]
NS=[('Cloudflare',r'cloudflare'),('AWS Route 53',r'awsdns'),('GoDaddy',r'domaincontrol|godaddy'),
 ('Azure DNS',r'azure-dns'),('Google',r'googledomains|ns-cloud|google\.com'),('Akamai',r'akam'),
 ('DNS Made Easy',r'dnsmadeeasy'),('NS1',r'nsone'),('Squarespace',r'squarespace'),('Wix',r'wixdns'),
 ('Web.com',r'worldnic|networksolutions|register\.com'),('Verisign',r'verisigndns'),('CSC',r'cscdns'),
 ('MarkMonitor',r'markmonitor'),('WordPress.com',r'wordpress|automattic'),('Namecheap',r'registrar-servers'),
 ('Hostinger',r'hostinger'),('IONOS',r'ui-dns|ionos'),('Oracle/Dyn',r'dynect|oracle'),('Rackspace',r'stabletransit')]
def lab(t,tbl,dflt='other'):
    for n,p in tbl:
        if re.search(p,t,re.I): return n
    return dflt
def res(name,rd,tries=2):
    for i in range(tries):
        try:
            R=dns.resolver.Resolver(configure=False); R.nameservers=[['8.8.8.8','1.1.1.1'][i%2]]; R.lifetime=6+3*i; R.timeout=4+2*i
            return list(R.resolve(name,rd))
        except (dns.resolver.NoAnswer,dns.resolver.NXDOMAIN): return []
        except dns.resolver.NoNameservers: continue
        except Exception: time.sleep(0.2)
    return None
def go(dom):
    o={'d':dom}
    a=res(dom,'A')
    o['alive']= None if a is None else bool(a)
    if a:
        ip=str(a[0]); o['ip']=ip
        try:
            rev='.'.join(reversed(ip.split('.')))
            t=res(rev+'.origin.asn.cymru.com','TXT')
            if t:
                parts=b''.join(t[0].strings).decode().split('|')
                num=parts[0].strip().split()[0]; o['cc']=parts[2].strip()
                nm=res('AS'+num+'.asn.cymru.com','TXT')
                if nm:
                    raw=b''.join(nm[0].strings).decode().split('|')[-1].strip()
                    o['asn']=raw; o['host']=lab(raw,HOST,raw.split(' - ')[0][:28])
        except Exception: pass
    mx=res(dom,'MX')
    if mx is None: o['mail']='?'
    elif not mx: o['mail']='none'
    else: o['mail']=lab(' '.join(str(x.exchange).lower() for x in mx),MAIL,'other / self-hosted')
    ns=res(dom,'NS')
    if ns is None: o['dns']='?'
    elif not ns: o['dns']='none'
    else: o['dns']=lab(' '.join(str(x.target).lower() for x in ns),NS)
    return o
doms=_d.domains()
todo=[x for x in doms if x not in done]
n=0
with ThreadPoolExecutor(28) as ex:
    for r in ex.map(go,todo):
        done[r['d']]=r; n+=1
        if n%60==0:
            json.dump(done,open(CK+'.t','w')); os.replace(CK+'.t',CK); print('  ..',len(done),flush=True)
json.dump(done,open(CK+'.t','w')); os.replace(CK+'.t',CK)
print('DONE',len(done),'/',len(doms),flush=True)
