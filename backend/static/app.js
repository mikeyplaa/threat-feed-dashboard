const board = document.getElementById("board");
const lastRefreshEl = document.getElementById("last-refresh");
const refreshBtn = document.getElementById("refresh-btn");

const POLL_INTERVAL_MS = 60_000;
const charts = {};  // keyed chart instances — destroyed before each re-render

function destroyCharts() {
  for (const c of Object.values(charts)) c.destroy();
  for (const k of Object.keys(charts)) delete charts[k];
}

function fmtTime(iso) {
  if (!iso) return "unknown";
  try { return new Date(iso).toLocaleString(); } catch { return iso; }
}

function severityClass(sev) {
  if (!sev) return "";
  const s = String(sev).toLowerCase();
  if (s.includes("critical") || s === "malicious") return "severity-critical";
  if (s.includes("high") || s.includes("exploited") || s === "suspicious") return "severity-known-exploited";
  if (s.includes("medium")) return "severity-medium";
  return "";
}

// Map NVD severity strings or raw CVSS scores to canonical bucket labels
function nvdSeverityLabel(sev) {
  if (!sev) return "N/A";
  const s = String(sev).toUpperCase();
  if (["CRITICAL", "HIGH", "MEDIUM", "LOW"].includes(s)) return s;
  const n = parseFloat(sev);
  if (!isNaN(n)) {
    if (n >= 9.0) return "CRITICAL";
    if (n >= 7.0) return "HIGH";
    if (n >= 4.0) return "MEDIUM";
    if (n > 0)   return "LOW";
  }
  return "N/A";
}

function renderColumn(key, feed) {
  const col = document.createElement("div");
  col.className = "column";
  col.id = `col-${key}`;

  // InfoCON badge — SANS ISC only (severity is a channel-level attribute there)
  let infoconHtml = "";
  if (key === "sans_isc" && feed.items && feed.items.length > 0) {
    const level = feed.items[0].severity || "unknown";
    infoconHtml = `<span class="infocon infocon-${level}">InfoCON: ${level}</span>`;
  }

  const header = document.createElement("div");
  header.className = "column-header";
  header.innerHTML = `
    <div class="column-header-top">
      <h2>${feed.name}</h2>
      <div class="header-right">
        ${infoconHtml}
        <span class="meta">${fmtTime(feed.updated)}</span>
      </div>
    </div>
    <div class="sparkline-wrap"><canvas id="sparkline-${key}"></canvas></div>
  `;
  col.appendChild(header);

  const body = document.createElement("div");
  body.className = "column-body";

  // NVD severity donut sits above the item list
  if (key === "nvd_recent" && !feed.error && feed.items && feed.items.length > 0) {
    const chartArea = document.createElement("div");
    chartArea.className = "chart-area";
    chartArea.innerHTML = `<canvas id="nvd-donut" width="260" height="130"></canvas>`;
    body.appendChild(chartArea);
  }

  if (feed.error) {
    const err = document.createElement("div");
    err.className = "error-msg";
    err.textContent = `Feed error: ${feed.error}`;
    body.appendChild(err);
  } else if (!feed.items || feed.items.length === 0) {
    const empty = document.createElement("div");
    empty.className = "empty-msg";
    empty.textContent = "No items yet — waiting on first refresh.";
    body.appendChild(empty);
  } else {
    for (const item of feed.items) {
      const el = document.createElement("div");
      el.className = "item";
      const sevBadge = item.severity
        ? `<span class="badge ${severityClass(item.severity)}">${item.severity}</span>`
        : "";
      const titleInner = item.source_url
        ? `<a href="${item.source_url}" target="_blank" rel="noopener">${item.title}</a>`
        : item.title;
      el.innerHTML = `
        <div class="item-title">${titleInner}${sevBadge}</div>
        <div class="item-detail">${item.detail || ""}</div>
      `;
      body.appendChild(el);
    }
  }

  col.appendChild(body);
  return col;
}

function initNvdDonut(items) {
  const canvas = document.getElementById("nvd-donut");
  if (!canvas) return;

  const buckets = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, "N/A": 0 };
  for (const item of items) {
    const label = nvdSeverityLabel(item.severity);
    buckets[label] = (buckets[label] || 0) + 1;
  }

  const COLORS = {
    CRITICAL: "rgba(255,107,107,0.85)",
    HIGH:     "rgba(255,140,80,0.85)",
    MEDIUM:   "rgba(255,180,84,0.85)",
    LOW:      "rgba(79,209,197,0.7)",
    "N/A":    "rgba(125,143,160,0.4)",
  };

  const labels = Object.keys(buckets).filter(k => buckets[k] > 0);

  charts.nvd_donut = new Chart(canvas, {
    type: "doughnut",
    data: {
      labels,
      datasets: [{
        data: labels.map(l => buckets[l]),
        backgroundColor: labels.map(l => COLORS[l] || COLORS["N/A"]),
        borderWidth: 0,
        hoverOffset: 4,
      }],
    },
    options: {
      responsive: false,
      cutout: "65%",
      plugins: {
        legend: {
          position: "right",
          labels: { color: "#dbe4ec", font: { size: 11 }, boxWidth: 10, padding: 8 },
        },
        tooltip: {
          callbacks: { label: ctx => ` ${ctx.label}: ${ctx.raw} CVEs` },
        },
      },
    },
  });
}

function initSparkline(key, history) {
  const canvas = document.getElementById(`sparkline-${key}`);
  if (!canvas || history.length < 2) return;

  charts[`spark_${key}`] = new Chart(canvas, {
    type: "line",
    data: {
      labels: history.map(d => d.date),
      datasets: [{
        data: history.map(d => d.avg_items),
        borderColor: "rgba(79,209,197,0.6)",
        borderWidth: 1.5,
        pointRadius: 0,
        tension: 0.4,
        fill: { target: "origin", above: "rgba(79,209,197,0.07)" },
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      animation: false,
      plugins: { legend: { display: false }, tooltip: { enabled: false } },
      scales: { x: { display: false }, y: { display: false, min: 0 } },
    },
  });
}

async function loadSparklines(keys) {
  await Promise.all(keys.map(async key => {
    try {
      const res = await fetch(`/api/history/${key}?days=7`);
      const data = await res.json();
      if (Array.isArray(data)) initSparkline(key, data);
    } catch { /* sparklines are non-critical */ }
  }));
}

async function loadFeeds() {
  try {
    const res = await fetch("/api/feeds");
    const data = await res.json();

    destroyCharts();
    board.innerHTML = "";

    for (const [key, feed] of Object.entries(data)) {
      board.appendChild(renderColumn(key, feed));
    }

    if (data.nvd_recent && !data.nvd_recent.error) {
      initNvdDonut(data.nvd_recent.items || []);
    }

    loadSparklines(Object.keys(data));  // async, non-blocking

    lastRefreshEl.textContent = `Loaded ${new Date().toLocaleTimeString()}`;
  } catch (e) {
    lastRefreshEl.textContent = "Failed to load feeds";
    console.error(e);
  }
}

refreshBtn.addEventListener("click", async () => {
  refreshBtn.disabled = true;
  refreshBtn.textContent = "Refreshing…";
  try {
    await fetch("/api/refresh", { method: "POST" });
    await loadFeeds();
  } finally {
    refreshBtn.disabled = false;
    refreshBtn.textContent = "Refresh now";
  }
});

loadFeeds();
setInterval(loadFeeds, POLL_INTERVAL_MS);


// ---------------------------------------------------------------------------
// VirusTotal on-demand lookup
// ---------------------------------------------------------------------------
async function vtLookup() {
  const q = document.getElementById("vt-input").value.trim();
  if (!q) return;

  const btn    = document.getElementById("vt-btn");
  const result = document.getElementById("vt-result");

  btn.disabled = true;
  btn.textContent = "Looking up…";
  result.innerHTML = `<div class="vt-loading">Querying VirusTotal…</div>`;
  result.hidden = false;

  try {
    const res  = await fetch(`/api/vt/lookup?q=${encodeURIComponent(q)}`);
    const data = await res.json();
    renderVtResult(data);
  } catch (e) {
    result.innerHTML = `<div class="vt-error">Request failed: ${e.message}</div>`;
  } finally {
    btn.disabled = false;
    btn.textContent = "Look up";
  }
}

function renderVtResult(data) {
  const result = document.getElementById("vt-result");

  if (data.error) {
    result.innerHTML = `<div class="vt-error">${data.error}</div>`;
    result.hidden = false;
    return;
  }

  const malicious  = data.malicious  || 0;
  const suspicious = data.suspicious || 0;
  const total      = data.total      || 0;

  let verdictClass, verdictText;
  if      (malicious >= 4)                    { verdictClass = "vt-malicious";  verdictText = "Malicious";  }
  else if (malicious > 0 || suspicious > 0)   { verdictClass = "vt-suspicious"; verdictText = "Suspicious"; }
  else                                        { verdictClass = "vt-clean";      verdictText = "Clean";      }

  const TYPE_LABELS = { ip: "IP", domain: "Domain", hash: "File Hash", url: "URL" };

  let extras = "";
  if (data.type === "ip") {
    const parts = [data.as_owner, data.country, data.network].filter(Boolean);
    if (parts.length) extras = `<div class="vt-extra">${parts.join(" · ")}</div>`;
  } else if (data.type === "domain") {
    const parts = [...(data.categories || []), data.registrar].filter(Boolean);
    if (parts.length) extras = `<div class="vt-extra">${parts.join(" · ")}</div>`;
  } else if (data.type === "hash") {
    const size  = data.size ? `${(data.size / 1024).toFixed(1)} KB` : null;
    const parts = [data.name, data.file_type, size].filter(Boolean);
    if (parts.length) extras = `<div class="vt-extra">${parts.join(" · ")}</div>`;
  } else if (data.type === "url") {
    const display = data.title || (data.final_url !== data.query ? data.final_url : null);
    if (display) extras = `<div class="vt-extra">${display}</div>`;
  }

  const tags = (data.tags || []).length
    ? `<div class="vt-tags">${data.tags.map(t => `<span class="badge">${t}</span>`).join(" ")}</div>`
    : "";

  result.innerHTML = `
    <div class="vt-card">
      <div class="vt-card-top">
        <div class="vt-ioc-info">
          <span class="vt-type-badge">${TYPE_LABELS[data.type] || data.type}</span>
          <span class="vt-query">${data.query}</span>
        </div>
        <a class="vt-link" href="${data.vt_url}" target="_blank" rel="noopener">Full report →</a>
      </div>
      <div class="vt-verdict-row">
        <span class="vt-score ${verdictClass}">${malicious}<span class="vt-total">/${total}</span></span>
        <div class="vt-verdict-info">
          <span class="vt-verdict-text ${verdictClass}">${verdictText}</span>
          <span class="vt-verdict-detail">${malicious} malicious · ${suspicious} suspicious · ${data.undetected} undetected</span>
        </div>
      </div>
      ${extras}
      ${tags}
    </div>
  `;
  result.hidden = false;
}

document.getElementById("vt-btn").addEventListener("click", vtLookup);
document.getElementById("vt-input").addEventListener("keydown", e => {
  if (e.key === "Enter") vtLookup();
});
