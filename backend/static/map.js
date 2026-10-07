const POLL_INTERVAL_MS = 60_000;
const lastRefreshEl = document.getElementById("last-refresh");

// Same escaping discipline as app.js — this feed's title/detail/country
// fields ultimately trace back to third-party IP data, never trust as HTML.
function escapeHtml(value) {
  const div = document.createElement("div");
  div.textContent = value == null ? "" : String(value);
  return div.innerHTML;
}

const map = L.map("map", { worldCopyJump: true }).setView([20, 10], 2);

L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
  attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors',
  maxZoom: 10,
}).addTo(map);

const markers = L.layerGroup().addTo(map);

// Pin size = how many distinct victims (targets) this source has hit today;
// color = report volume (yellow = low, red = high). Both on a sqrt scale
// since a handful of sources report 100x the volume of the rest.
const RADIUS_MIN = 6;
const RADIUS_MAX = 26;

function scaleRadius(targets, maxTargets) {
  if (maxTargets <= 0) return RADIUS_MIN;
  const t = Math.sqrt(targets) / Math.sqrt(maxTargets);
  return RADIUS_MIN + t * (RADIUS_MAX - RADIUS_MIN);
}

function colorForReports(reports, maxReports) {
  if (maxReports <= 0) return "#ffb454";
  const t = Math.sqrt(reports) / Math.sqrt(maxReports);
  // interpolate amber (#ffb454) -> red (#ff3b3b)
  const r1 = 0xff, g1 = 0xb4, b1 = 0x54;
  const r2 = 0xff, g2 = 0x3b, b2 = 0x3b;
  const r = Math.round(r1 + (r2 - r1) * t);
  const g = Math.round(g1 + (g2 - g1) * t);
  const b = Math.round(b1 + (b2 - b1) * t);
  return `rgb(${r},${g},${b})`;
}

async function loadMap() {
  try {
    const res = await fetch("/api/feeds/dshield_map");
    const feed = await res.json();

    markers.clearLayers();

    if (feed.error) {
      lastRefreshEl.textContent = `Feed error: ${feed.error}`;
      return;
    }

    const items = (feed.items || []).filter(
      i => typeof i.lat === "number" && typeof i.lon === "number"
    );

    const maxTargets = Math.max(0, ...items.map(i => i.targets || 0));
    const maxReports = Math.max(0, ...items.map(i => i.reports || 0));

    // Draw biggest-impact pins first so smaller ones stay clickable on top.
    const sorted = [...items].sort((a, b) => (b.targets || 0) - (a.targets || 0));

    for (const item of sorted) {
      const targets = item.targets || 0;
      const reports = item.reports || 0;
      const fill = colorForReports(reports, maxReports);
      const marker = L.circleMarker([item.lat, item.lon], {
        radius: scaleRadius(targets, maxTargets),
        color: fill,
        fillColor: fill,
        fillOpacity: 0.45,
        weight: 1.5,
      });
      marker.bindPopup(
        `<strong>${escapeHtml(item.title)}</strong><br>${escapeHtml(item.detail || "")}`
      );
      marker.addTo(markers);
    }

    const updated = feed.updated ? new Date(feed.updated).toLocaleTimeString() : "—";
    const missing = (feed.items || []).length - items.length;
    lastRefreshEl.textContent =
      `${items.length} active sources · updated ${updated}` +
      (missing > 0 ? ` (${missing} ungeolocated)` : "");
  } catch (e) {
    lastRefreshEl.textContent = "Failed to load map data";
    console.error(e);
  }
}

loadMap();
setInterval(loadMap, POLL_INTERVAL_MS);
