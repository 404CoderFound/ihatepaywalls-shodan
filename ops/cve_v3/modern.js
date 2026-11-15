"use strict";
/* ScanLattice: simplify navigation and make the existing search easier.
   All routes keep using the existing host/admin APIs, no extra permissions. */
(() => {
  function setup(){
    document.body.classList.add("sl-modern");
    const nav=document.querySelector(".mainnav nav");
    if(!nav||nav.dataset.slModern)return;
    nav.dataset.slModern="1";
    nav.setAttribute("aria-label","Primary navigation");
    const entries=[...nav.querySelectorAll("a[data-page]")];
    const primary=new Set(["home","search","vulnerabilities","monitor","admin"]);
    const names={home:"Explore",search:"Hosts",vulnerabilities:"CVEs",monitor:"Monitor",admin:"Admin"};
    const more=document.createElement("details");
    more.className="sl-more";
    const summary=document.createElement("summary");
    summary.textContent="More";
    summary.setAttribute("aria-label","More sections");
    const menu=document.createElement("div");
    menu.className="sl-more-menu";
    more.append(summary,menu);
    for(const entry of entries){
      const page=entry.dataset.page;
      if(primary.has(page)){
        entry.textContent=names[page];
        nav.append(entry);
      }else{
        menu.append(entry);
      }
    }
    nav.append(more);
    document.addEventListener("click",e=>{
      if(!more.contains(e.target))more.open=false;
    });
    menu.addEventListener("click",e=>{if(e.target.closest("a"))more.open=false;});
    const hero=document.querySelector(".hero");
    if(hero){
      const title=hero.querySelector("h1");
      const desc=hero.querySelector("p");
      if(title)title.textContent="Discover what’s connected.";
      if(desc)desc.textContent="Search indexed hosts, services and networks. Explore verified evidence without the noise.";
      const search=hero.querySelector('input[id="hero-query"]');
      if(search)search.placeholder='Search an IP, port:443, country:NL, asn:AS30925…';
      const eye=hero.querySelector(".eyebrow");
      if(eye)eye.textContent="INTERNET SEARCH · OBSERVED DATA";
      const ex=hero.querySelector(".examples");
      if(ex){
        ex.innerHTML='POPULAR FILTERS: <a href="#search?q=port%3A443">port:443</a>'+
          '<a href="#search?q=country%3ANL">country:NL</a>'+
          '<a href="#search?q=service%3Assh">service:ssh</a>'+
          '<a href="#vulnerabilities">Explore CVEs</a>';
      }
    }
    const headInput=document.getElementById("header-query");
    if(headInput)headInput.placeholder="Search IPs, hostnames, products, CVE IDs…";
    // CVE identifiers entered into either existing global search bar are
    // redirected into the real public CVE search endpoint. Normal host
    // searches keep their existing code path and filter syntax.
    for(const id of ["top-search","hero-search"]){
      const form=document.getElementById(id);
      if(!form)continue;
      form.addEventListener("submit",e=>{
        const q=form.querySelector("input")?.value.trim()||"";
        const term=q.replace(/^cve:\s*/i,"");
        if(/^CVE-\d{4}-\d{4,}$/i.test(term)){
          e.preventDefault();e.stopImmediatePropagation();
          location.hash="#vulnerabilities?query="+encodeURIComponent(term.toUpperCase());
        }
      },true);
    }
    document.addEventListener("keydown",e=>{
      if(e.key!=="/"||e.ctrlKey||e.metaKey||e.altKey)return;
      const el=document.activeElement;
      if(el&&(/^(input|textarea|select)$/i.test(el.tagName)||el.isContentEditable))return;
      e.preventDefault();
      (document.getElementById("header-query")||document.getElementById("hero-query"))?.focus();
    });
  }
  if(document.readyState==="loading")document.addEventListener("DOMContentLoaded",setup);
  else setup();
})();
