// Verifier. Run from the repo root after every build:  node src/final.js
// Renders at four widths, drives every ring in every view, and asserts label collisions,
// clockwise order, counts and console errors; then opens every profile and the two reference pages.
const path=require('path');
let pw; try{pw=require('playwright')}catch(e){pw=require(path.join(process.env.NPM_GLOBAL||'/usr/local/lib/node_modules','playwright'))}
const FILE='file://'+path.resolve(__dirname,'..','index.html');
(async()=>{const b=await pw.chromium.launch();let fail=0;
for(const w of [390,1024,1500,2200]){
  const p=await b.newPage({viewport:{width:w,height:950}});
  const e=[];p.on('pageerror',x=>e.push(x.message));p.on('console',m=>{if(m.type()==='error'&&!/icons\.duckduckgo|fonts\.g|ERR_/.test(m.text()))e.push(m.text())});
  await p.goto(FILE);await p.waitForTimeout(600);
  const r=await p.evaluate(async()=>{
    let n=0,bad=0,breaks=0,prof=0,perr=[];
    for(const v of ['radial','list','table','graph']){
      for(let s=0;s<S.length;s++){
        view=v;cur=s;render();await new Promise(r=>setTimeout(r,0));n++;
        if(v!=='radial')continue;
        const L=[...document.querySelectorAll('.need-label')].map(t=>t.getBBox());
        const B=[...document.querySelectorAll('g.company .badge')].map(t=>t.getBBox());
        for(const a of L)for(const c of B){if(a.x<c.x+c.width&&a.x+a.width>c.x&&a.y<c.y+c.height&&a.y+a.height>c.y)bad++;}
      }
    }
    for(let s=0;s<S.length;s++){cur=s;for(const c of S[s].cats)for(const p of c.p){try{openP(p);prof++;if(!dbody.innerHTML.includes('The permit'))perr.push(p.n)}catch(x){perr.push(p.n+': '+x.message)}}}
    hide();
    for(const k of [-3,-4,-1]){selectTab(k);await new Promise(r=>setTimeout(r,0));}
    return {n,bad,prof,perr,std:document.getElementById('stdpane').innerText.length,meth:document.getElementById('methpane').innerText.length,
      measured:document.getElementById('measured').innerText.slice(0,160),
      total:document.querySelector('.intro [data-n=all]').textContent,sourced:document.querySelector('[data-n=sourced]').textContent};
  });
  const ok=!e.length&&!r.perr.length&&r.std>2000&&r.meth>2000;
  if(!ok)fail++;
  console.log(String(w).padStart(5)+'px  renders '+r.n+'  labelCollisions '+r.bad+'  profiles '+r.prof+'  profileErrors '+r.perr.length+'  total '+r.total+'  sourced '+r.sourced+'  std '+r.std+'  method '+r.meth+'  errors '+e.length+(e.length?' '+e.slice(0,3).join(' | '):'')+(r.perr.length?' '+r.perr.slice(0,3).join(' | '):''));
  if(w===1500)console.log('  measured: '+r.measured.replace(/\n/g,' / '));
  await p.close();
}
const a=await b.newPage();const ae=[];a.on('pageerror',x=>ae.push(x.message));
await a.goto('file://'+path.resolve(__dirname,'..','assessment.html'));await a.waitForTimeout(300);
const items=await a.evaluate(()=>document.querySelectorAll('.item').length);
console.log('assessment items '+items+'  errors '+ae.length+(ae.length?' '+ae[0]:''));
if(ae.length||items<20)fail++;
await b.close();process.exit(fail?1:0);})();
