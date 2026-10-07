# Threat Feed Dashboard

A self-hosted, single-container personal threat intelligence dashboard. Pulls
live data from 11 public and semi-public threat intel feeds on a 15-minute
schedule and displays them in a browser with charts and live sparklines. Built
for ongoing personal threat awareness — not a production SOC tool, but written
cleanly enough to grow into one.

---

## Features

- **11 live threat intel feeds** — vulnerabilities, malware IOCs, phishing
  URLs, malicious URL scans, SSH attackers, IP reputation, security news
- **SQLite persistence** — feed data survives container restarts; history is
  used to drive trend sparklines
- **Charts** — NVD severity donut (CRITICAL/HIGH/MEDIUM/LOW breakdown) and
  per-column 7-day sparklines showing item count over time
- **SANS ISC InfoCON badge** — live colour-coded threat level badge
  (green / yellow / orange / red)
- **Auto-refresh** — UI polls `/api/feeds` every 60 seconds; background
  scheduler refreshes feeds every 15 minutes
- **Zero frontend build step** — vanilla HTML/CSS/JS + Chart.js via CDN

---

## Feeds

| Column | Source | Auth required |
|---|---|---|
| Hacker News — Security Stories | Algolia HN Search API | None |
| CISA Known Exploited Vulnerabilities | cisa.gov | None |
| NVD — Recently Published CVEs | nvd.nist.gov | None (rate-limited) |
| SANS ISC — Threat Diaries | isc.sans.edu RSS | None |
| OpenPhish — Active Phishing URLs | openphish.com | None |
| Blocklist.de — SSH Attackers | lists.blocklist.de | None |
| ThreatFox — Recent Malware IOCs | abuse.ch | `ABUSECH_API_KEY` |
| URLhaus — Recent Malicious URLs | abuse.ch | `ABUSECH_API_KEY` |
| LevelBlue OTX — Threat Pulses | otx.alienvault.com | `OTX_API_KEY` |
| CrowdSec — SSH Attacker Reputation | cti.api.crowdsec.net | `CROWDSEC_API_KEY` |
| urlscan.io — Malicious URL Scans | urlscan.io | `URLSCAN_API_KEY` |

Feeds that need API keys display an error card in the dashboard if the key is
not set — they fail independently and never take down the others.

---

## Quick start

**Requirements:** Docker and Docker Compose. No host Python needed.

```bash
git clone https://github.com/mikeyplaa/threat-feed-dashboard.git
cd threat-feed-dashboard

# Configure API keys (copy the template and fill in your keys)
cp .env.example .env
notepad .env   # or your editor of choice

# Build and start
docker compose up --build -d

# Watch startup logs
docker compose logs -f
```

Open **http://localhost:8000**. Columns appear within a few seconds as feeds
are fetched on startup.

```bash
# Stop
docker compose down
```

---

## API keys

Four feeds require free API keys. All four can be left blank — those columns
will show an error card and the rest of the dashboard keeps working.

### abuse.ch (covers both ThreatFox and URLhaus)

1. Register at **https://abuse.ch/**
2. Account settings → copy your API key
3. `ABUSECH_API_KEY=<key>` in `.env`

### LevelBlue OTX

1. Register at **https://otx.alienvault.com/**
2. Settings → copy your OTX Key
3. `OTX_API_KEY=<key>` in `.env`

### CrowdSec CTI

The free community tier supports per-IP smoke lookups, which is what this
dashboard uses. The paid `/v2/fire` bulk endpoint is not used.

1. Register at **https://app.crowdsec.net/**
2. CTI API → generate a community key
3. `CROWDSEC_API_KEY=<key>` in `.env`

### urlscan.io

Unauthenticated search requests return 403 — a key is required.

1. Register at **https://urlscan.io/**
2. Account → API → copy your key
3. `URLSCAN_API_KEY=<key>` in `.env`

---

## Configuration

All configuration is via environment variables. Set them in `.env` — Docker
Compose reads this file automatically.

| Variable | Default | Purpose |
|---|---|---|
| `ABUSECH_API_KEY` | _(blank)_ | ThreatFox and URLhaus auth |
| `OTX_API_KEY` | _(blank)_ | LevelBlue OTX auth |
| `CROWDSEC_API_KEY` | _(blank)_ | CrowdSec CTI auth |
| `URLSCAN_API_KEY` | _(blank)_ | urlscan.io auth |
| `DB_PATH` | `/data/feeds.db` | SQLite database path inside the container |

The `data/` directory is bind-mounted (`./data:/data`) so the SQLite database
persists across container restarts and upgrades.

**Never commit `.env`** — it is gitignored. Only `.env.example` (the blank
template) is committed.

---

## Architecture

```
threat-feed-dashboard/
├── .env.example          # blank key template (committed)
├── docker-compose.yml
└── backend/
    ├── Dockerfile
    ├── requirements.txt
    ├── app.py            # FastAPI app: scheduler, in-memory cache + DB wiring,
    │                     #   API routes, static file mount
    ├── db.py             # aiosqlite helpers: init, save_snapshot, load_latest,
    │                     #   get_daily_counts (7-day retention, auto-pruned)
    ├── feeds.py          # one fetch_* function per source + FEEDS registry
    └── static/
        ├── index.html
        ├── style.css
        └── app.js        # polls /api/feeds, renders columns, Chart.js charts
```

### How data flows

1. On startup `app.py` warms the in-memory `CACHE` from the latest SQLite
   snapshot per feed, so the dashboard shows data immediately even before the
   first live fetch completes.
2. APScheduler fires `refresh_all()` every 15 minutes (configurable via
   `REFRESH_INTERVAL_MINUTES` in `app.py`). Each feed runs independently — one
   failure never affects the others.
3. Successful fetches are saved to the `feed_snapshots` SQLite table.
   Snapshots older than 7 days are pruned automatically.
4. `GET /api/history/{key}` returns daily item counts for the past 7 days,
   which `app.js` uses to draw the sparkline in each column header.

### Adding a new feed

1. Write `async def fetch_yourfeed(client: httpx.AsyncClient, limit=...)` in
   `feeds.py`, returning a list of normalised dicts:
   ```python
   {"id": str, "title": str, "detail": str,
    "severity": str | None, "source_url": str | None, "timestamp": str | None}
   ```
2. Register it in the `FEEDS` dict at the bottom of `feeds.py`:
   ```python
   "yourfeed": ("Display Name", fetch_yourfeed),
   ```
3. Rebuild: `docker compose up --build -d`

The frontend automatically renders a new column for every key in `/api/feeds`
— no frontend changes needed. For a feed that needs an API key, declare it in
`docker-compose.yml` under `environment:` and read it via `os.environ` in the
fetcher.

---

## API endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/feeds` | Full cache — all feeds |
| `GET` | `/api/feeds/{key}` | Single feed |
| `POST` | `/api/refresh` | Force immediate re-fetch of all feeds |
| `GET` | `/api/history/{key}?days=7` | Daily item count history |
| `GET` | `/api/health` | Health check — returns feed key list |

---

## Known constraints and gotchas

**NVD rate limits** — NVD throttles unauthenticated requests hard (roughly
5 per 30 minutes). If the NVD column shows 403 errors, either increase
`REFRESH_INTERVAL_MINUTES` in `app.py` or get a free NVD API key and pass it
as an `apiKey` query parameter in `fetch_nvd_recent`.

**CrowdSec free tier** — the community key covers per-IP `/v2/smoke/{ip}`
lookups only, at a flat **50 queries/day** (per CrowdSec's own CTI product
page). The bulk `/v2/fire` list requires a paid subscription and is not used
here. Polling every 15 minutes would blow through 50/day almost immediately,
so `fetch_crowdsec` self-throttles independently of the dashboard's refresh
schedule: it only calls CrowdSec once every 3 hours (5 IPs per call, ~40
requests/day) and serves the cached batch the rest of the time. That cache is
in-memory, so a container restart will trigger an immediate API call on the
next refresh regardless of the cooldown. A 429 still surfaces as an error
card rather than rendering an empty column.

**abuse.ch auth** — ThreatFox uses a POST endpoint; URLhaus switched from POST
to GET in mid-2026. Both require an `Auth-Key` request header. A 401 means
the key is missing or wrong.

**Static files are baked into the image** — `docker compose restart` does NOT
pick up frontend changes. Always use `docker compose up --build -d` after
editing `index.html`, `style.css`, or `app.js`. Hard-refresh the browser
(Ctrl+Shift+R) after rebuilding to bust the local cache.

**No auth on the dashboard** — designed for localhost / home network only. If
you expose it further, put it behind a reverse proxy with authentication
(Caddy, nginx, or Tailscale) rather than adding auth to the app itself.

---

## Development

```bash
# Run without Docker (from backend/)
pip install -r requirements.txt
uvicorn app:app --reload --port 8000

# Syntax check all Python modules
python -m py_compile backend/app.py backend/feeds.py backend/db.py

# View live container logs
docker compose logs -f

# Rebuild image (required after any static file or Python change)
docker compose up --build -d
```

There are no automated tests yet. When adding them, mock `httpx.AsyncClient`
responses rather than hitting live APIs in CI.

---

## Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.12, FastAPI, httpx (async), APScheduler |
| Persistence | aiosqlite (SQLite) |
| Frontend | Vanilla HTML/CSS/JS, Chart.js 4 (via CDN) |
| Deployment | Docker + Docker Compose |
