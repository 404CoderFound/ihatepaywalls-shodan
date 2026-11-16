"use strict";
/* ScanLattice V5 search presentation: one result per IP, indexed before passive.
 * Read-only: no scan requests, data updates, or application API mutations. */
(() => {
  const cache = new Map();
  const asnPages = new Map();
  const observed = new WeakSet();
  let timer = 0;
  let searchRunning = false;

  function ipFromCard(card) {
    const link = card.querySelector('h3 a[href^="#host?ip="]');
    if (!link) return "";
    try {
      return (new URLSearchParams(link.getAttribute("href").split("?")[1] || "").get("ip") || "").toLowerCase();
    } catch (_) { return ""; }
  }

  function normalizeMetadata(card) {
    const title = card.querySelector("h3")?.textContent.trim().toLowerCase() || "";
    const type = card.querySelector(".service")?.textContent.trim().toLowerCase() || "";
    return title + "\u0000" + type;
  }

  // The host endpoint exposes {ip,last_scan_at:''} for passive-only IPs.
  // Only an actual indexed host has a first_seen column in its host row.
  async function hasIndexedHost(ip) {
    if (cache.has(ip)) return cache.get(ip);
    const promise = (async () => {
      try {
        const response = await fetch("/api/hosts/" + encodeURIComponent(ip), {
          credentials: "same-origin"
        });
        if (!response.ok) return null;
        const result = await response.json();
        return !!(result.host && Object.prototype.hasOwnProperty.call(result.host, "first_seen"));
      } catch (_) {
        return null;  // Keep passive data if the index cannot be checked.
      }
    })();
    cache.set(ip, promise);
    return promise;
  }

  function createPassiveCard(row) {
    const article = document.createElement("article");
    article.className = "observation passive-record";
    article.dataset.scanlatticePassiveOnly = "true";
    const heading = document.createElement("h3");
    const link = document.createElement("a");
    link.href = "#host?ip=" + encodeURIComponent(row.ip);
    link.textContent = row.ip;
    heading.append(link);
    const org = document.createElement("div");
    org.className = "org";
    org.textContent = row.org || row.asn || "Passive-only host";
    const meta = document.createElement("div");
    meta.className = "meta";
    meta.textContent = "PASSIVE-ONLY · " + (row.source || "unknown source") +
      (row.observed_at ? " · Observed " + row.observed_at : "");
    const info = document.createElement("div");
    const marker = document.createElement("span");
    marker.className = "service";
    marker.textContent = row.record_type || "passive";
    info.append(marker);
    article.append(heading, org, meta, info);
    return article;
  }

  async function getAsnMetadata(hash) {
    if (!asnPages.has(hash)) {
      const params = new URLSearchParams(hash.split("?")[1] || "");
      const q = params.get("q") || "";
      if (!/(?:^|\s)asn\s*:/i.test(q)) return [];
      const url = "/api/search?" + new URLSearchParams({
        q,
        page: params.get("page") || "1",
        prefix_page: params.get("prefix_page") || "1",
        metadata_page: params.get("metadata_page") || "1"
      });
      asnPages.set(hash, fetch(url, {credentials: "same-origin"})
        .then(response => response.ok ? response.json() : null)
        .then(data => data?.asn_intelligence?.passive_metadata?.results || [])
        .catch(() => []));
    }
    return asnPages.get(hash);
  }

  async function normalizeSearch() {
    const page = document.getElementById("page-search");
    const out = document.getElementById("result-items");
    if (!page || page.classList.contains("hidden") || !out) return;
    if (out.textContent.includes("Loading public index")) return;
    if (searchRunning) return;
    searchRunning = true;
    const hash = location.hash;
    try {
      // ASN prefix/registry facts remain in the network overview. A metadata
      // record with an explicit IP, however, can represent a passive-only host.
      const rows = await getAsnMetadata(hash);
      if (location.hash !== hash) return;
      const existing = new Set([...out.querySelectorAll(".observation")]
        .map(ipFromCard).filter(Boolean));
      for (const row of rows) {
        if (!row.ip || existing.has(String(row.ip).toLowerCase())) continue;
        existing.add(String(row.ip).toLowerCase());
        out.append(createPassiveCard(row));
      }

      const indexed = new Set();
      for (const card of out.querySelectorAll(".host-card")) {
        const ip = ipFromCard(card);
        if (!ip) continue;
        if (indexed.has(ip)) card.remove();
        else indexed.add(ip);
      }
      const seenPassive = new Set();
      const passive = [...out.querySelectorAll(".passive-record")];
      for (const card of passive) {
        const ip = ipFromCard(card);
        const key = ip ? "ip:" + ip : "metadata:" + normalizeMetadata(card);
        if ((ip && indexed.has(ip)) || seenPassive.has(key)) {
          card.remove();
          continue;
        }
        seenPassive.add(key);
        if (ip) {
          const isIndexed = await hasIndexedHost(ip);
          if (location.hash !== hash) return;
          if (isIndexed === true) card.remove();
        }
      }
      if (location.hash !== hash) return;
      const headings = [...out.querySelectorAll(".result-category")];
      headings.forEach((node, n) => {
        if (n === 0) {
          if (node.textContent !== "Results") node.textContent = "Results";
        } else node.remove();
      });
      const cards = out.querySelectorAll(".observation");
      if (cards.length && !headings.length) {
        const h = document.createElement("h3");
        h.className = "result-category";
        h.textContent = "Results";
        out.insertBefore(h, cards[0]);
      }
      if (cards.length) {
        out.querySelectorAll(".empty.compact").forEach(node => node.remove());
      }
    } finally {
      searchRunning = false;
    }
  }

  async function normalizeHost() {
    const page = document.getElementById("page-host");
    const out = document.getElementById("host-content");
    if (!page || page.classList.contains("hidden") || !out ||
        out.textContent.includes("Loading host record")) return;
    const passive = [...out.querySelectorAll(".passive-record")];
    if (!passive.length) return;
    const indexedObservations = [...out.querySelectorAll(".observation:not(.passive-record)")];
    const ip = new URLSearchParams(location.hash.split("?")[1] || "").get("ip") || "";
    const indexed = indexedObservations.length || (ip && await hasIndexedHost(ip.toLowerCase()) === true);
    if (!location.hash.startsWith("#host")) return;
    passive.forEach((node, index) => {
      if (indexed || index !== 0) node.remove();
    });
    [...out.querySelectorAll("h3")].forEach(node => {
      if (node.textContent.trim() === "Passive Intelligence") {
        if (indexed) node.remove();
        else node.textContent = "Passive-only result";
      }
    });
  }

  function schedule() {
    if (timer) clearTimeout(timer);
    timer = setTimeout(() => {
      timer = 0;
      if (location.hash.startsWith("#search")) {
        normalizeSearch().catch(error => console.warn("Search dedup unavailable", error));
      } else if (location.hash.startsWith("#host")) {
        normalizeHost().catch(error => console.warn("Host dedup unavailable", error));
      }
    }, 80);
  }

  function start() {
    for (const id of ["result-items", "host-content"]) {
      const node = document.getElementById(id);
      if (node && !observed.has(node)) {
        observed.add(node);
        new MutationObserver(schedule).observe(node, {childList: true, subtree: true});
      }
    }
    window.addEventListener("hashchange", schedule);
    schedule();
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start);
  else start();
})();