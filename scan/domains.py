"""The one place the scanners learn which domains to read: data/actors.json.
Checkpoints are written beside the scripts in scan/out/ so every run is resumable."""
import json, os
ROOT=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT=os.path.join(ROOT,'scan','out'); os.makedirs(OUT,exist_ok=True)
def domains():
    a=json.load(open(os.path.join(ROOT,'data','actors.json')))['actors']
    return sorted({x['w'] for x in a if x.get('w')})
def ck(name): return os.path.join(OUT,name)
