"use strict";
const $ = id => document.getElementById(id);
let activeQuery = "";
const escapeHtml = s => String(s ?? "").replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function toast(s) {const e=$('toast');e.textContent=s;e.classList.add('visible');setTimeout(()=>e.classList.remove('visible'),4500)}
function route(){
  const hash=location.hash.slice(1), [path, queryPart]=hash.split('?');
  const page=['home','search','admin'].includes(path)?path:'home';
  document.querySelectorAll('.page').forEach(p=>p.classList.toggle('hidden',p.id!==`page-${page}`));
  document.querySelectorAll('[data-page]').forEach(a=>a.classList.toggle('active',a.dataset.page===page));
  if(page==='search'){const q=new URLSearchParams(queryPart||'').get('q')||activeQuery; activeQuery=q;$('header-query').value=q;search(q)}
  if(page==='admin'&&sessionStorage.getItem('scanlattice_admin')) { $('admin-token').value=sessionStorage.getItem('scanlattice_admin');loadAdmin(); }
}
function submitSearch(s){activeQuery=s.trim();location.hash='#search?q='+encodeURIComponent(activeQuery);route()}
$('hero-search').addEventListener('submit',e=>{e.preventDefault();submitSearch($('hero-query').value)});
$('top-search').addEventListener('submit',e=>{e.preventDefault();submitSearch($('header-query').value)});
$('scan-query').addEventListener('click',()=>toast('On-demand scans are not enabled in this starter build. No target was contacted.'));
async function search(q){
  $('result-query').textContent=q?`/ ${q}`:'';$('result-items').innerHTML='<div class="empty">Loading index...</div>';
  try {
    const res=await fetch(`/api/search?q=${encodeURIComponent(q)}&limit=100`);const json=await res.json();
    if(!res.ok)throw Error(json.detail||'Search failed');
    $('search-meta').textContent=`${json.total.toLocaleString()} indexed observation${json.total===1?'':'s'}`;
    const facets=(el,data,key)=>{const entries=Object.entries(data).sort((a,b)=>b[1]-a[1]); $(el).innerHTML=entries.length?entries.map(([v,n])=>`<div><a href="#search?q=${encodeURIComponent(key+':'+v)}">${escapeHtml(v)}</a><span>${n}</span></div>`).join(''):'<div>No data yet</div>'};
    facets('facet-ports',json.facets.ports,'port');facets('facet-countries',json.facets.countries,'country');
    $('result-items').innerHTML=json.results.length?json.results.map(x=>`<article class="observation">
      <h3><a href="#search?q=${encodeURIComponent('ip:'+x.ip)}">${escapeHtml(x.ip)}</a></h3><div class="org">${escapeHtml(x.org||'Unknown organization')}</div>
      <div class="meta">${escapeHtml(x.country||'Unknown country')} &nbsp; · &nbsp; ${escapeHtml(x.asn)} &nbsp; · &nbsp; Last observed: ${escapeHtml(x.seen_at)} &nbsp; · &nbsp; Source: ${escapeHtml(x.source)}${x.is_demo?' &nbsp; · &nbsp; DEMO DATA':''}</div>
      <div><span class="service">${escapeHtml(x.port)}/${escapeHtml(x.proto)}</span><span class="service">${escapeHtml(x.product||'Unknown service')}</span></div>
      <pre>${escapeHtml(x.banner||'No banner collected')}</pre></article>`).join(''):'<div class="empty"><strong>No matching records.</strong>Import passive observations or change your search filters.</div>';
  }catch(e){$('result-items').innerHTML=`<div class="empty"><strong>Search unavailable</strong>${escapeHtml(e.message)}</div>`}
}
$('admin-login').addEventListener('click',()=>{sessionStorage.setItem('scanlattice_admin',$('admin-token').value);loadAdmin()});
async function loadAdmin(){
  const token=sessionStorage.getItem('scanlattice_admin');if(!token)return;
  try{const r=await fetch('/api/admin/workers',{headers:{'X-Admin-Token':token}});const json=await r.json();if(!r.ok)throw Error(json.detail||'Unauthorized');
    $('admin-content').classList.remove('hidden');$('workers-online').textContent=json.workers.filter(w=>w.online).length;
    const s=await fetch('/api/stats').then(r=>r.json());$('indexed-hosts').textContent=s.hosts;
    $('worker-table').innerHTML=json.workers.length?json.workers.map(w=>`<tr><td>${escapeHtml(w.name)}</td><td class="${w.online?'online':'offline'}">${w.online?'● Online':'○ Offline'}</td><td>${w.cpu_pct.toFixed(1)}%</td><td>${w.memory_pct.toFixed(1)}%</td><td>${w.active_jobs}</td><td>${new Date(w.last_seen*1000).toLocaleString()}</td></tr>`).join(''):'<tr><td colspan="6">No workers registered yet. Add the enrollment token to your worker configuration.</td></tr>';
  }catch(e){$('admin-content').classList.add('hidden');toast(e.message)}
}
setInterval(()=>{if(location.hash.startsWith('#admin'))loadAdmin()},10000);
window.addEventListener('hashchange',route);route();
