// Top Critical Threats page — renders /api/critical (scoring lives in backend/critical.py)
const POLL_INTERVAL_MS = 60_000;
const LEVELS = ["critical", "high", "medium", "low"];
const CATEGORY_LABELS = {
  "vulnerability": "Vulnerability",
  "malware-ioc": "Malware IOC",
  "malicious-url": "Malicious URL",
  "phishing": "Phishing",
  "attacker-ip": "Attacker IP",
  "advisory": "Advisory",
  "threat-intel": "Threat intel",
  "news": "News",
  "other": "Other",
};

const openKeys = new Set();  // expanded rows survive the 60s re-render

// Feed content is third-party — escape everything interpolated into HTML.
function escapeHtml(value) {
  const div = document.createElement("div");
  div.textContent = value == null ? "" : String(value);
  return div.innerHTML;
}

function safeUrl(url) {
  if (!url) return null;
  try {
    const u = new URL(url, window.location.href);
    return (u.protocol === "http:" || u.protocol === "https:") ? u.href : null;
  } catch {
    return null;
  }
}

function fmtTime(iso) {
  if (!iso) return "unknown";
  try { return new Date(iso).toLocaleString(); } catch { return iso; }
}

function fmtAge(hours) {
  if (hours == null) return "live list";
  if (hours < 1) return "<1h";
  if (hours < 48) return `${Math.round(hours)}h`;
  return `${Math.round(hours / 24)}d`;
}

function catLabel(c) { return CATEGORY_LABELS[c] || c; }

function rowKey(item) { return `${item.source}|${item.indicator || item.id}`; }

// ---- summary + warnings ---------------------------------------------------
function renderSummary(data) {
  const scoredFeeds = data.feeds.filter(f => f.items > 0 && !f.unscored).length;
  document.getElementById("summary-line").textContent =
    `Top ${data.items.length} of ${data.unique} unique threats, ranked from ${data.considered} scored items across ${scoredFeeds} feeds.`;
  document.getElementById("last-refresh").textContent = `Updated ${fmtTime(data.generated)}`;

  const problems = data.feeds.filter(f => f.error || f.unscored);
  const box = document.getElementById("feed-warnings");
  if (!problems.length) { box.hidden = true; box.innerHTML = ""; return; }
  box.hidden = false;
  box.innerHTML = "<strong>Not fully included in this ranking:</strong><br>" + problems.map(f => {
    const why = f.error
      ? (f.items ? `last refresh failed (using ${f.items} older items): ${f.error}` : `unavailable: ${f.error}`)
      : "cached items predate scoring; they'll be included after the next refresh";
    return `${escapeHtml(f.name)} — ${escapeHtml(why)}`;
  }).join("<br>");
}

// ---- stat tiles -----------------------------------------------------------
function renderTiles(data) {
  const b = data.breakdown;
  const tiles = LEVELS.map(lvl => `
    <div class="tile lvl-${lvl}">
      <div class="tile-label">${lvl}</div>
      <div class="tile-value">${b.by_level[lvl] || 0}</div>
      <div class="tile-sub">${{critical: "score 85+", high: "70–84", medium: "50–69", low: "below 50"}[lvl]}</div>
    </div>`);
  tiles.push(`
    <div class="tile accent">
      <div class="tile-label">Corroborated</div>
      <div class="tile-value">${b.corroborated}</div>
      <div class="tile-sub">seen in 2+ feeds</div>
    </div>`);
  tiles.push(`
    <div class="tile accent">
      <div class="tile-label">Avg score</div>
      <div class="tile-value">${b.avg_score ?? "—"}</div>
      <div class="tile-sub">of the top ${data.items.length}</div>
    </div>`);
  document.getElementById("tiles").innerHTML = tiles.join("");
}

// ---- bar charts (plain CSS, no chart library) -----------------------------
function renderBars(elId, rows) {
  const el = document.getElementById(elId);
  if (!rows.length) { el.innerHTML = `<div class="empty">No data yet.</div>`; return; }
  const max = Math.max(...rows.map(r => r.value), 1);
  el.innerHTML = rows.map(r => `
    <div class="bar-row" title="${escapeHtml(r.label)}: ${r.value}">
      <span class="bar-label">${escapeHtml(r.label)}</span>
      <span class="bar-track"><span class="bar-fill ${r.cls || ""}" style="width:${(r.value / max) * 100}%"></span></span>
      <span class="bar-value">${r.value}</span>
    </div>`).join("");
}

function renderCharts(data) {
  const b = data.breakdown;
  renderBars("chart-source", b.by_source.map(s => ({ label: s.name, value: s.count })));
  renderBars("chart-category", Object.entries(b.by_category).map(([c, n]) => ({ label: catLabel(c), value: n })));

  const bands = [
    { label: "95–100", min: 95, max: 100 },
    { label: "85–94", min: 85, max: 94 },
    { label: "70–84", min: 70, max: 84 },
    { label: "50–69", min: 50, max: 69 },
    { label: "0–49", min: 0, max: 49 },
  ];
  renderBars("chart-score", bands.map(band => {
    const value = data.items.filter(i => i.score >= band.min && i.score <= band.max).length;
    const lvl = band.min >= 85 ? "critical" : band.min >= 70 ? "high" : band.min >= 50 ? "medium" : "low";
    return { label: band.label, value, cls: `lvl-${lvl}` };
  }));
}

// ---- ranked list ----------------------------------------------------------
function scoreMath(item) {
  const parts = [`base ${item.base_score}`];
  if (item.freshness_penalty) parts.push(`<span class="minus">− ${item.freshness_penalty} age</span>`);
  if (item.corroboration_bonus) parts.push(`<span class="plus">+ ${item.corroboration_bonus} corroboration</span>`);
  return `<span class="math">${parts.join(" ")} = <strong>${item.score}</strong></span>`;
}

function renderThreat(item) {
  const key = rowKey(item);
  const wrap = document.createElement("div");
  wrap.className = "threat" + (openKeys.has(key) ? " open" : "");

  const sourceNames = item.sources.map(s => s.name);
  const multi = item.sources.length > 1
    ? `<span class="cat-chip multi-chip">${item.sources.length} feeds</span>` : "";
  const url = safeUrl(item.source_url);

  wrap.innerHTML = `
    <div class="threat-row" role="button" tabindex="0" aria-expanded="${openKeys.has(key)}">
      <span class="rank">${item.rank}</span>
      <span class="score-cell">
        <span><span class="score-num">${item.score}</span><span class="lvl-badge lvl-${item.level}">${item.level}</span></span>
        <span class="score-track"><span class="score-fill lvl-${item.level}" style="width:${item.score}%"></span></span>
      </span>
      <span class="threat-main">
        <div class="threat-title">${escapeHtml(item.title)}</div>
        <div class="threat-reason"><span class="cat-chip">${escapeHtml(catLabel(item.category))}</span>${multi}${escapeHtml(item.reason)}</div>
      </span>
      <span class="threat-source" title="${escapeHtml(sourceNames.join(", "))}">${escapeHtml(sourceNames[0])}</span>
      <span class="threat-age" title="${escapeHtml(item.timestamp ? fmtTime(item.timestamp) : "from a list of currently active threats (no timestamp)")}">${fmtAge(item.age_hours)}</span>
      <span class="chev">›</span>
    </div>
    <div class="threat-detail">
      <h3>Threat</h3>
      <div class="full-title">${escapeHtml(item.title)}</div>
      ${item.detail ? `<div class="detail-text">${escapeHtml(item.detail)}</div>` : ""}
      ${item.indicator ? `<div>Indicator: <code>${escapeHtml(item.indicator)}</code></div>` : ""}
      <h3>Why it ranks #${item.rank}</h3>
      <div>${scoreMath(item)} → <span class="lvl-badge lvl-${item.level}">${item.level}</span></div>
      <h3>Reported by</h3>
      <ul class="src-list">
        ${item.sources.map(s => `<li><strong>${escapeHtml(s.name)}</strong> — ${escapeHtml(s.reason)}</li>`).join("")}
      </ul>
      <h3>When</h3>
      <div>${item.timestamp ? escapeHtml(fmtTime(item.timestamp)) : "Currently active (the feed gives no timestamp)"}</div>
      ${url ? `<h3>Reference</h3><a class="detail-link" href="${escapeHtml(url)}" target="_blank" rel="noopener">${escapeHtml(url)}</a>` : ""}
    </div>`;

  const row = wrap.querySelector(".threat-row");
  const toggle = () => {
    const open = wrap.classList.toggle("open");
    row.setAttribute("aria-expanded", String(open));
    if (open) openKeys.add(key); else openKeys.delete(key);
  };
  row.addEventListener("click", toggle);
  row.addEventListener("keydown", e => {
    if (e.key === "Enter" || e.key === " ") { e.preventDefault(); toggle(); }
  });
  return wrap;
}

function renderList(data) {
  const list = document.getElementById("threat-list");
  list.innerHTML = "";
  if (!data.items.length) {
    list.innerHTML = `<div class="list-msg">No scored threats yet — waiting on the first feed refresh.</div>`;
    return;
  }
  for (const item of data.items) list.appendChild(renderThreat(item));
}

// ---- load loop ------------------------------------------------------------
async function load() {
  try {
    const res = await fetch("/api/critical?limit=25");
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();
    renderSummary(data);
    renderTiles(data);
    renderCharts(data);
    renderList(data);
  } catch (err) {
    document.getElementById("summary-line").textContent = `Failed to load critical threats: ${err.message}`;
  }
}

load();
setInterval(load, POLL_INTERVAL_MS);
