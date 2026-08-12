# Threat Feed Dashboard

A self-hosted, single-container dashboard that pulls live data from several
public threat intelligence feeds and displays them in a refreshing web UI.

## What's included (v1 feeds)

| Feed | Source | Notes |
|---|---|---|
| CISA KEV | cisa.gov | Known Exploited Vulnerabilities catalog |
| NVD Recent | nvd.nist.gov | Recently published CVEs |
| ThreatFox | abuse.ch | Recent malware IOCs (IPs, domains, hashes) |
| URLhaus | abuse.ch | Recently reported malicious URLs |

No API keys required for any of these to get started.

## Run it

```bash
docker compose up --build -d
```

Then open **http://localhost:8000**.

The backend fetches all feeds on startup, then refreshes every 15 minutes
in the background. Click "Refresh now" in the UI to force an immediate pull.

## Architecture

```
threat-feed-dashboard/
├── docker-compose.yml
└── backend/
    ├── Dockerfile
    ├── requirements.txt
    ├── app.py          # FastAPI app, scheduler, in-memory cache, API routes
    ├── feeds.py         # one fetch_* function per feed source
    └── static/           # frontend (vanilla HTML/CSS/JS), served by FastAPI
        ├── index.html
        ├── style.css
        └── app.js
```

Data is cached in memory only (no database) — simplest possible setup for a
personal dashboard. If you restart the container, it just re-fetches on
startup. If you want history/persistence later, swap the in-memory `CACHE`
dict in `app.py` for SQLite (a single file, easy to add).

## Adding a new feed

1. Write a new `async def fetch_yourfeed(client, limit=...)` in `feeds.py`
   that returns a list of dicts with keys: `id`, `title`, `detail`,
   `severity`, `source_url`, `timestamp`.
2. Register it in the `FEEDS` dict at the bottom of `feeds.py`:
   ```python
   "yourfeed": ("Display Name", fetch_yourfeed),
   ```
3. Rebuild: `docker compose up --build -d`

The frontend automatically renders a new column for any key present in
`/api/feeds` — no frontend changes needed.

## Feeds that need an API key (not wired in yet, easy to add)

- **AlienVault OTX** — free key from otx.alienvault.com, richer IOC pulses
- **VirusTotal** — free tier, 4 req/min, good for on-demand lookups
- **Shodan** — needs paid plan for most useful queries

To add one: same pattern as above, just read the key from an environment
variable (add it to `docker-compose.yml` under `environment:`) rather than
hardcoding it.

## Adjusting refresh interval

Change `REFRESH_INTERVAL_MINUTES` in `app.py`. Be mindful of rate limits —
NVD in particular throttles unauthenticated requests fairly aggressively
(5 requests per 30 seconds). If you hit 403/429s, either slow the interval
down or get a free NVD API key and add it as a request header.

## Security notes for running this yourself

- This exposes port 8000 with no auth — fine on localhost/home network,
  put it behind a reverse proxy (e.g. Caddy/nginx with basic auth, or
  Tailscale) before exposing it anywhere else.
- All feed fetches are outbound-only; the container doesn't need any
  inbound access besides the dashboard port.
