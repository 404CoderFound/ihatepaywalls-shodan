"use strict";

const $ = id => document.getElementById(id);
const esc = value => String(value ?? "").replace(/[&<>"']/g, char => (
  {"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[char]
));
let activeQuery = "";
let csrfToken = sessionStorage.getItem("scanlattice_csrf") || "";
let enrichmentTimer = null;
document.querySelector("#page-docs .sectionheader span").textContent = "VERSION 0.4";
document.querySelector("footer .right").textContent = "CONTROL PLANE v0.4 / HOST INDEX + PASSIVE DISCOVERY";

function toast(message) {
  const element = $("toast");
  element.textContent = message;
  element.classList.add("visible");
  setTimeout(() => element.classList.remove("visible"), 4500);
}

async function api(path, options = {}) {
  const response = await fetch(path, {credentials: "same-origin", ...options});
  const data = await response.json();
  if (!response.ok) throw Error(data.detail || "Request failed");
  return data;
}

function adminHeaders() {
  return {"Content-Type": "application/json", "X-CSRF-Token": csrfToken};
}

async function checkSession() {
  try {
    const state = await api("/api/admin/session");
    $("admin-scan-action").classList.toggle("hidden", !state.authenticated);
    return state.authenticated;
  } catch (_) {
    $("admin-scan-action").classList.add("hidden");
    return false;
  }
}

async function route() {
  const [path, queryPart] = location.hash.slice(1).split("?");
  const page = ["home", "search", "host", "admin", "docs"].includes(path) ? path : "home";
  document.querySelectorAll(".page").forEach(node => node.classList.toggle("hidden", node.id !== `page-${page}`));
  document.querySelectorAll("[data-page]").forEach(node => node.classList.toggle("active", node.dataset.page === page));
  const params = new URLSearchParams(queryPart || "");
  if (page === "search") {
    activeQuery = params.get("q") || activeQuery;
    $("header-query").value = activeQuery;
    await search(activeQuery, Number(params.get("page") || 1), Number(params.get("prefix_page") || 1), Number(params.get("metadata_page") || 1));
  } else if (page === "host") {
    await loadHost(params.get("ip"));
  } else if (page === "admin") {
    if (await checkSession()) await loadAdmin();
  } else if (page === "home") {
    await loadStats();
  }
  await checkSession();
}

function submitSearch(value) {
  activeQuery = value.trim();
  location.hash = `#search?q=${encodeURIComponent(activeQuery)}&page=1`;
}

$("hero-search").addEventListener("submit", event => {event.preventDefault(); submitSearch($("hero-query").value);});
$("top-search").addEventListener("submit", event => {event.preventDefault(); submitSearch($("header-query").value);});
$("admin-scan-action").addEventListener("click", openDeepRecon);

async function loadStats() {
  try {
    const stats = await api("/api/stats");
    $("home-hosts").textContent = stats.hosts.toLocaleString();
    $("home-services").textContent = stats.services.toLocaleString();
  } catch (_) {
    $("system-status").textContent = "UNAVAILABLE";
  }
}

function passiveCard(row) {
  const subject = row.ip || row.domain || row.subject;
  return `<article class="observation passive-record">
    <h3>${row.ip ? `<a href="#host?ip=${encodeURIComponent(row.ip)}">${esc(subject)}</a>` : esc(subject)}</h3>
    <div class="org">${esc(row.org || row.asn || row.record_type)}</div>
    <div class="meta">PASSIVE INTELLIGENCE · Source: ${esc(row.source)} · Observed: ${esc(row.observed_at)}</div>
    <div><span class="service">${esc(row.record_type)}</span>${row.network ? `<span class="service">${esc(row.network)}</span>` : ""}</div>
    <pre>${esc(JSON.stringify(row.value, null, 2))}</pre>
  </article>`;
}

function hostCard(host) {
  const services = host.services || [];
  return `<article class="observation host-card">
    <h3><a href="#host?ip=${encodeURIComponent(host.ip)}">${esc(host.ip)}</a></h3>
    <div class="org">${esc(host.hostname || host.hostnames?.[0]?.hostname || "No hostname")} · ${esc(host.asn || "Unknown ASN")} · ${esc(host.org || "Unknown organization")}</div>
    <div class="meta">First seen: ${esc(host.first_seen)} · Last observed: ${esc(host.last_seen)} · Source: ${esc(host.source || "indexed observation")}${host.network_prefix ? ` · Prefix: ${esc(host.network_prefix)}` : ""}</div>
    <div>${services.map(service => `<span class="service">${service.port}/${esc(service.proto)} ${esc(service.service || service.product || "unknown")}</span>`).join("") || '<span class="service">NO INDEXED SERVICES</span>'}</div>
    ${services.slice(0,3).map(service => `<div class="service-detail"><b>${service.port}/${esc(service.proto)} ${esc(service.product || service.service || "")}</b><span>${esc(service.banner || service.http?.status || "No banner metadata")}</span><small>Observed ${esc(service.last_seen)} · ${esc(service.source)}</small></div>`).join("")}
  </article>`;
}

function pageUrl(query, page, prefixPage=1, metadataPage=1) {
  return `#search?q=${encodeURIComponent(query)}&page=${page}&prefix_page=${prefixPage}&metadata_page=${metadataPage}`;
}

function numberedPagination(data, query, prefixPage, metadataPage) {
  if (!data.total_pages) return "";
  const pages=[];
  for (let number=1;number<=data.total_pages;number++) {
    if (data.total_pages>15 && number>2 && number<data.total_pages-1 && Math.abs(number-data.page)>2) {
      if (pages.at(-1)!=="…") pages.push("…");
      continue;
    }
    pages.push(`<a class="${number===data.page?"current":""}" href="${pageUrl(query,number,prefixPage,metadataPage)}">${number}</a>`);
  }
  return `${data.has_previous?`<a href="${pageUrl(query,data.page-1,prefixPage,metadataPage)}">← Previous</a>`:""}${pages.join("")}${data.has_next?`<a href="${pageUrl(query,data.page+1,prefixPage,metadataPage)}">Next →</a>`:""}`;
}

function asnOverview(asn, query, hostPage, metadataPage) {
  if (!asn) return "";
  const networks=asn.announced_networks;
  const prefixRows=networks.results.map(row=>`<tr><td><a href="#search?q=${encodeURIComponent(`net:${row.prefix}`)}">${esc(row.prefix)}</a></td><td>${row.prefix.includes(":")?"IPv6":"IPv4"}</td><td>${esc(row.source)}</td><td>${esc(row.last_seen)}</td></tr>`).join("");
  const prefixNav=`${networks.page>1?`<a href="${pageUrl(query,hostPage,networks.page-1,metadataPage)}">← Previous networks</a>`:""}${networks.has_next?`<a href="${pageUrl(query,hostPage,networks.page+1,metadataPage)}">Next networks →</a>`:""}`;
  return `<section class="asn-overview"><div class="asn-title"><div><small>ASN INTELLIGENCE</small><h2>${esc(asn.asn)} — ${esc(asn.organization || "Unknown organization")}</h2></div><span>Updated ${esc(asn.last_enrichment || "not yet")}</span></div><div class="asn-stats"><div><strong>${asn.statistics.ipv4_prefixes ?? 0}</strong><span>IPv4 PREFIXES</span></div><div><strong>${asn.statistics.ipv6_prefixes ?? 0}</strong><span>IPv6 PREFIXES</span></div><div><strong>${asn.indexed_host_count}</strong><span>INDEXED HOSTS</span></div><div><strong>${asn.indexed_service_count}</strong><span>INDEXED SERVICES</span></div></div><div class="asn-meta"><b>Sources:</b> ${esc(asn.sources.join(", ") || "enrichment pending")}<details><summary>Technical ASN details</summary><pre>${esc(JSON.stringify(asn.overview,null,2))}</pre></details></div><div class="coverage-note">${esc(asn.host_intelligence.message)}${asn.host_intelligence.sources.length?` Sources: ${esc(asn.host_intelligence.sources.join(", "))}`:" No external host/service dataset is currently contributing results."}</div><h3>Announced Networks <span>${networks.total}</span></h3><table class="workers"><thead><tr><th>PREFIX</th><th>FAMILY</th><th>SOURCE</th><th>FRESHNESS</th></tr></thead><tbody>${prefixRows||'<tr><td colspan="4">Gathering announced networks…</td></tr>'}</tbody></table><div class="subpagination">${prefixNav}</div><h3>Discovered Hosts <span>${asn.indexed_host_count}</span></h3></section>`;
}

async function search(query, page, prefixPage=1, metadataPage=1) {
  $("result-query").textContent = query ? `/ ${query}` : "";
  $("result-items").innerHTML = '<div class="empty">Loading public index...</div>';
  try {
    const data = await api(`/api/search?q=${encodeURIComponent(query)}&page=${page}&prefix_page=${prefixPage}&metadata_page=${metadataPage}`);
    renderEnrichment(data.enrichment, query, page, prefixPage, metadataPage);
    $("search-meta").textContent = data.total ? `Hosts ${data.range_start}–${data.range_end} of ${data.total}` : `0 indexed hosts`;
    const facets = (id, values, key) => {
      $(id).innerHTML = Object.entries(values).sort((a,b) => b[1]-a[1]).slice(0,10)
        .map(([value,count]) => `<div><a href="#search?q=${encodeURIComponent(`${key}:${value}`)}">${esc(value)}</a><span>${count}</span></div>`).join("") || "No data";
    };
    facets("facet-ports", data.facets.ports, "port");
    facets("facet-countries", data.facets.countries, "country");
    const indexed = data.hosts.map(hostCard).join("");
    const passive = data.passive_intelligence.map(passiveCard).join("");
    $("result-items").innerHTML = data.has_information
      ? `${asnOverview(data.asn_intelligence,query,data.page,metadataPage)}${indexed ? `<h3 class="result-category">Indexed Service Observations</h3>${indexed}` : data.asn_intelligence?'<div class="empty compact"><strong>No indexed hosts for this ASN.</strong>Announced networks are not treated as active hosts.</div>':""}${passive ? `<h3 class="result-category">Passive Intelligence</h3>${passive}` : ""}`
      : `<div class="empty"><strong>${esc(data.message)}</strong>No active measurement was started.</div>`;
    $("pagination").innerHTML = numberedPagination(data,query,prefixPage,metadataPage);
  } catch (error) {
    $("result-items").innerHTML = `<div class="empty"><strong>Search unavailable</strong>${esc(error.message)}</div>`;
  }
}

function renderEnrichment(job, query, page, prefixPage=1, metadataPage=1) {
  clearTimeout(enrichmentTimer);
  const box = $("enrichment-status");
  if (!job || !job.id) {box.innerHTML = ""; return;}
  if (job.status === "enriching") {
    box.innerHTML = '<div class="enrichment-banner"><b>Gathering passive intelligence…</b><span>Results will update automatically.</span></div>';
    enrichmentTimer = setTimeout(() => pollEnrichment(job.id, query, page, prefixPage, metadataPage), 1500);
  } else if (job.status === "failed") {
    box.innerHTML = `<div class="enrichment-banner failed"><b>Passive enrichment failed.</b><span>${esc(job.error || "Providers returned no usable data.")}</span></div>`;
  } else {
    box.innerHTML = `<div class="freshness">PASSIVE CACHE: ${esc(job.status.toUpperCase())} · Updated ${esc(job.completed_at || job.updated_at)}</div>`;
  }
}

async function pollEnrichment(jobId, query, page, prefixPage=1, metadataPage=1) {
  try {
    const job = await api(`/api/enrichment/${jobId}`);
    if (["completed","partial","failed"].includes(job.status)) await search(query, page, prefixPage, metadataPage);
    else enrichmentTimer = setTimeout(() => pollEnrichment(jobId, query, page, prefixPage, metadataPage), 1500);
  } catch (error) {
    $("enrichment-status").innerHTML = `<div class="enrichment-banner failed">${esc(error.message)}</div>`;
  }
}

async function openDeepRecon() {
  try {
    if (!(await checkSession())) return;
    const profiles = await api("/api/admin/profiles", {headers:adminHeaders()});
    $("recon-profile").innerHTML = profiles.profiles.map(profile => `<option value="${profile.id}" ${profile.name === "Quick Recon" ? "selected" : ""}>${esc(profile.name)} — ${profile.ports.length} ports</option>`).join("");
    $("recon-query").textContent = `Current search: ${activeQuery}`;
    $("recon-summary").textContent = "Preview validates every candidate against the configured allowlist.";
    $("recon-candidates").innerHTML = "";
    $("recon-launch").classList.add("hidden");
    $("recon-modal").classList.remove("hidden");
  } catch (error) {toast(error.message);}
}

$("recon-close").addEventListener("click", () => $("recon-modal").classList.add("hidden"));
$("recon-preview").addEventListener("click", async () => {
  try {
    const preview = await api("/api/admin/deep-recon/preview", {method:"POST",headers:adminHeaders(),body:JSON.stringify({query:activeQuery,profile_id:Number($("recon-profile").value)})});
    $("recon-summary").innerHTML = `<b>${preview.target_count.toLocaleString()} authorized address(es)</b> · ${preview.estimated_connections.toLocaleString()} estimated connections · ${esc(preview.notice)}`;
    $("recon-candidates").innerHTML = preview.candidates.map(candidate => `<label class="reconcandidate ${candidate.authorized ? "" : "blocked"}"><input type="checkbox" value="${esc(candidate.target)}" ${candidate.authorized ? "" : "disabled"}><span><b>${esc(candidate.target)}</b><small>${candidate.addresses.toLocaleString()} addresses · ${candidate.authorized ? `${candidate.batches} bounded job(s) · covered by ${esc(candidate.authorization)}` : "NOT AUTHORIZED"}</small></span></label>`).join("") || '<div class="empty">No eligible targets are available yet. Wait for passive enrichment or configure a permitted association.</div>';
    $("recon-launch").classList.toggle("hidden", !preview.candidates.some(candidate => candidate.authorized));
  } catch (error) {toast(error.message);}
});
$("recon-launch").addEventListener("click", async () => {
  const targets = [...document.querySelectorAll("#recon-candidates input:checked")].map(input => input.value);
  if (!targets.length) {toast("Select at least one authorized target."); return;}
  try {
    const result = await api("/api/admin/deep-recon/launch", {method:"POST",headers:adminHeaders(),body:JSON.stringify({query:activeQuery,profile_id:Number($("recon-profile").value),targets})});
    toast(`Campaign created: ${result.job_count} bounded job(s)`);
    $("recon-modal").classList.add("hidden");
    location.hash = "#admin";
  } catch (error) {toast(error.message);}
});

async function loadHost(ip) {
  if (!ip) return;
  $("host-title").textContent = ip;
  $("host-content").innerHTML = '<div class="empty">Loading host record...</div>';
  try {
    const data = await api(`/api/hosts/${encodeURIComponent(ip)}`);
    const host = data.host;
    const observations = data.latest_by_port.map(row => `<article class="observation"><h3>${row.port}/${esc(row.proto)} — ${esc(row.product || row.service || "Unknown service")}</h3><div class="meta">HISTORICAL OBSERVATION · ${esc(row.seen_at)} · ${esc(row.source)}</div><pre>${esc(row.banner || "No banner collected")}</pre></article>`).join("");
    const passive = data.passive_intelligence.map(passiveCard).join("");
    $("host-content").innerHTML = `<div class="hostmeta"><div><small>HOSTNAME</small><strong>${esc(host.hostname || "Not available")}</strong></div><div><small>ORGANIZATION / ASN</small><strong>${esc(host.org || "Unknown")} / ${esc(host.asn || "Unknown")}</strong></div><div><small>COUNTRY</small><strong>${esc(host.country || "Unknown")}</strong></div><div><small>LAST ACTIVE SCAN</small><strong>${esc(host.last_scan_at || "No active scan recorded")}</strong></div></div>${observations ? `<h3>Indexed Observations</h3>${observations}` : ""}${passive ? `<h3>Passive Intelligence</h3>${passive}` : ""}`;
  } catch (error) {
    $("host-content").innerHTML = `<div class="empty"><strong>${esc(error.message)}</strong></div>`;
  }
}

$("admin-login").addEventListener("click", async () => {
  try {
    const data = await api("/api/admin/session", {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({admin_token:$("admin-token").value})});
    csrfToken = data.csrf_token;
    sessionStorage.setItem("scanlattice_csrf", csrfToken);
    $("admin-token").value = "";
    await loadAdmin();
    await checkSession();
  } catch (error) {toast(error.message);}
});

async function loadAdmin() {
  try {
    const headers = adminHeaders();
    const [workers,jobs,authorizations,profiles,stats] = await Promise.all([
      api("/api/admin/workers",{headers}), api("/api/admin/jobs",{headers}),
      api("/api/admin/authorizations",{headers}), api("/api/admin/profiles",{headers}), api("/api/stats")
    ]);
    $("admin-content").classList.remove("hidden");
    $("workers-online").textContent = workers.workers.filter(row => row.online).length;
    $("indexed-hosts").textContent = stats.hosts;
    $("open-jobs").textContent = jobs.jobs.filter(row => ["queued","assigned","running"].includes(row.status)).length;
    $("job-profile").innerHTML = profiles.profiles.map(row => `<option value="${row.id}">${esc(row.name)} — ${row.ports.join(",")}</option>`).join("");
    const selected = $("job-worker").value;
    $("job-worker").innerHTML = '<option value="">Automatic worker selection</option>' + workers.workers.map(row => `<option value="${row.id}">${esc(row.name)}${row.online ? "" : " (offline)"}</option>`).join("");
    $("job-worker").value = selected;
    $("auth-list").innerHTML = authorizations.authorizations.map(row => `<div><b>${esc(row.name)}</b><code>${esc(row.cidr)}</code><span>${row.enabled ? "ENABLED" : "DISABLED"}</span></div>`).join("") || "No authorized target ranges.";
    $("worker-table").innerHTML = workers.workers.map(row => `<tr><td>${esc(row.name)}<br><small>${row.id}</small></td><td class="${row.online ? "online" : "offline"}">${row.online ? "● Online" : "○ Offline"}</td><td>${row.cpu_pct.toFixed(1)}% / ${row.memory_pct.toFixed(1)}%</td><td>${row.running_jobs} / ${row.max_concurrent}</td><td>${row.completed_jobs}</td><td>${esc(row.version || "legacy")}<br><small>${esc(row.capabilities.join(", "))}</small></td><td>${new Date(row.last_seen*1000).toLocaleString()}</td></tr>`).join("") || '<tr><td colspan="7">No workers enrolled.</td></tr>';
    $("job-table").innerHTML = jobs.jobs.map(row => `<tr><td><small>${row.id}</small><br><b>${esc(row.target)}</b><br>${row.ports.join(", ")}</td><td>${esc(row.profile_name)}</td><td class="status-${row.status}">${esc(row.status.toUpperCase())}</td><td>${row.progress_done} / ${row.progress_total}</td><td>${esc(row.worker_name || "Unassigned")}</td><td>${esc(row.error || "")}${["queued","assigned","running"].includes(row.status) ? `<button class="tiny cancel-job" data-id="${row.id}">CANCEL</button>` : ""}</td></tr>`).join("") || '<tr><td colspan="6">No scan jobs.</td></tr>';
    document.querySelectorAll(".cancel-job").forEach(button => button.onclick = () => cancelJob(button.dataset.id));
  } catch (error) {
    $("admin-content").classList.add("hidden"); toast(error.message);
  }
}

$("auth-form").addEventListener("submit", async event => {
  event.preventDefault();
  try {await api("/api/admin/authorizations",{method:"POST",headers:adminHeaders(),body:JSON.stringify({name:$("auth-name").value,cidr:$("auth-cidr").value})}); event.target.reset(); toast("Target authorization created"); await loadAdmin();} catch(error){toast(error.message);}
});
$("job-form").addEventListener("submit", async event => {
  event.preventDefault(); const ports=$("job-ports").value.trim();
  try {await api("/api/admin/jobs",{method:"POST",headers:adminHeaders(),body:JSON.stringify({target:$("job-target").value,profile_id:Number($("job-profile").value),ports:ports?ports.split(",").map(Number):null,worker_id:$("job-worker").value||null})}); toast("Scan job submitted"); await loadAdmin();} catch(error){toast(error.message);}
});
async function cancelJob(id){try{await api(`/api/admin/jobs/${id}/cancel`,{method:"POST",headers:adminHeaders()});toast("Job cancelled");await loadAdmin();}catch(error){toast(error.message);}}

$("job-target").addEventListener("input",()=>{$("job-estimate").textContent="The server validates target size and authorization before accepting this job.";});
setInterval(()=>{if(location.hash.startsWith("#admin"))loadAdmin();},10000);
window.addEventListener("hashchange",route);
route();
