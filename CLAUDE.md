# CLAUDE.md

This file gives Claude Code context on the project so it doesn't have to
re-derive architecture decisions on every session.

## What this is

A self-hosted, single-container personal dashboard that pulls live data
from public threat intelligence feeds (CISA KEV, NVD, abuse.ch ThreatFox,
abuse.ch URLhaus) on a schedule and displays them in a browser. Built as a
personal project for ongoing threat awareness — not a production SOC tool,
but written cleanly enough to grow into one.

## Stack

- **Backend**: Python 3.12, FastAPI, httpx (async), APScheduler for the
  polling loop, aiosqlite for persistence. Feed results are cached in an
  in-memory dict and persisted to SQLite.
- **Frontend**: vanilla HTML/CSS/JS, no build step, no framework. Served
  directly by FastAPI's `StaticFiles` mount. Polls `/api/feeds` every 60s.
- **Deployment**: single Docker container via `docker-compose.yml`.
  `docker compose up --build -d`, exposed on `:8000`.

## Architecture

```
threat-feed-dashboard/
├── docker-compose.yml
├── data/                 # Docker volume mount — holds feeds.db (gitignored)
└── backend/
    ├── Dockerfile
    ├── requirements.txt
    ├── app.py            # FastAPI app: scheduler, cache, API routes, static mount
    ├── db.py             # SQLite helpers: init, save_snapshot, load_latest, get_daily_counts
    ├── feeds.py          # one fetch_* function per feed source + FEEDS registry
    └── static/
        ├── index.html
        ├── style.css
        ├── app.js        # fetches /api/feeds, renders one column per feed
        ├── map.html      # second page — attack SOURCES map (Leaflet via CDN)
        ├── map.css
        └── map.js        # fetches /api/feeds/dshield_map, plots lat/lon pins
```

**Key pattern — adding a feed**: every feed source is one `async def
fetch_x(client: httpx.AsyncClient, limit=...)` function in `feeds.py` that
returns a list of normalised dicts:
```python
{"id": str, "title": str, "detail": str, "severity": str|None,
 "source_url": str|None, "timestamp": str|None}
```
Register it in the `FEEDS` dict at the bottom of `feeds.py`. Nothing else
needs to change — `app.py` iterates `FEEDS` for the scheduler and API
routes, and `app.js` renders a column per key it receives from
`/api/feeds`. Don't special-case individual feeds in `app.py` or the
frontend; keep that logic inside each `fetch_*` function so the registry
pattern stays true.

**Different pattern — on-demand lookup widgets**: VirusTotal (`/api/vt/lookup`)
and EmailRep (`/api/emailrep/lookup`) don't fit the scheduled-feed registry —
they query only when the user submits something, not on a timer, and return
a single result object rather than a list. These are one-off `@app.get`
routes in `app.py`, each with its own small frontend widget
(`#vt-widget`/`#emailrep-widget` in `index.html`, paired lookup/render
functions in `app.js`). Don't force a new on-demand lookup into the `FEEDS`
registry; follow the VT/EmailRep route+widget pattern instead.

**Cache shape** (`CACHE` dict in `app.py`, keyed by feed key):
```python
{"name": str, "updated": iso8601|None, "items": [...], "error": str|None}
```
On fetch failure, keep the previous items if you change this — currently
it clears items to `[]` on error inside `fetch_*` only if the exception
happens before building the list, but a failed refresh always overwrites
`CACHE[key]` with the error and empty state (see `refresh_feed` in
`app.py`). Worth revisiting before adding persistence.

## Commands

```bash
# run locally without Docker (from backend/)
pip install -r requirements.txt
uvicorn app:app --reload --port 8000

# run via Docker (from repo root)
docker compose up --build -d   # --build required any time backend/ files change
docker compose logs -f
docker compose down

# syntax check
python3 -m py_compile backend/app.py backend/feeds.py
```

There are currently no automated tests — see roadmap doc for adding
pytest coverage of the `fetch_*` functions (mock httpx responses, don't
hit live APIs in tests).

## Known constraints / gotchas

- **EmailRep requires a key, full stop** (confirmed Oct 2026 — unauthenticated
  requests return 429 `"the unauthenticated API is currently disabled.
  please use an API key"`, not a lower rate limit). Auth is a `Key` header,
  not `Authorization`/`X-Api-Key`. No public report page exists to link to
  (API-only product), so `emailrep_lookup` doesn't return a GUI URL the way
  `vt_lookup` does.
- **NVD rate limits unauthenticated requests hard** (5 req/30 min window
  roughly). If NVD starts 403ing, either back off `REFRESH_INTERVAL_MINUTES`
  in `app.py` or add an NVD API key (free) as a request header in
  `fetch_nvd_recent`.
- **abuse.ch API methods**: ThreatFox is POST-based (intentional). URLhaus
  switched from POST to GET (confirmed Aug 2026 — `"http_get_expected"` error).
  Don't revert URLhaus back to POST.
- **urlscan.io search requires an API key** (unauthenticated search returns
  403) and the free plan can't query the `verdicts.overall.malicious` field
  (confirmed Oct 2026 — `"Your current plan does not allow you to search
  field..."`; the `verdicts` object isn't even in the response). `fetch_urlscan`
  queries `task.tags:malicious` instead, which is free-tier accessible.
- **CrowdSec CTI free tier is a flat 50 queries/day** (per CrowdSec's own CTI
  product page). That's far below what the 15-minute dashboard refresh would
  burn through even at a handful of IPs per call, so `fetch_crowdsec`
  self-throttles independently of the scheduler: a module-level cache
  (`_crowdsec_cache` / `_CROWDSEC_COOLDOWN_MINUTES` in `feeds.py`) only hits
  the real API once per 3 hours and returns the last cached batch the rest of
  the time, at `limit=5` IPs — roughly 40 requests/day. That cache lives in
  process memory, so a container restart resets it and the next refresh will
  hit the API immediately regardless of cooldown. A 429 still raises so
  quota exhaustion (e.g. from manual testing against the same key) surfaces
  as an error card instead of silently rendering empty.
- **DShield's per-IP lookup (`/api/ip/{ip}`) is too fragile to fan out** —
  confirmed Oct 2026: one extra call right after a `/api/topips` request
  tripped a shared "Too Many Requests... bots cranky" 300s cooldown, which
  looks like a community-wide limit rather than per-caller. `fetch_dshield_map`
  only uses DShield for the top-IPs list itself (no auth, fine in bulk) and
  geolocates via `ipwho.is` instead (free, HTTPS, no key). A module-level
  `_geo_cache` in `feeds.py` keyed by IP keeps lookups low since the same
  handful of scanners dominate the top-IPs list day to day — don't add
  per-IP calls back to DShield's own API without re-confirming it can take it.
- No auth on the dashboard itself — it's designed to sit on localhost/home
  network only. Anything exposing it further needs a reverse proxy with
  auth in front (Caddy/nginx/Tailscale), not auth built into the app.
- SQLite persistence is in `backend/db.py`, writing to `DB_PATH` (defaults
  to `./feeds.db`; Docker sets it to `/data/feeds.db` via the `data` volume).
  On startup, `app.py` warms the in-memory `CACHE` from the last persisted
  snapshot so the dashboard isn't blank after a restart. Snapshots older than
  7 days are pruned on every save. History is exposed at `/api/history/{key}`
  (returns per-day `avg_items`/`max_items`/`snapshots` counts).

## Conventions

- Keep the frontend dependency-free (no npm, no build step) — this is a
  personal project meant to stay easy to hack on and redeploy without a
  build pipeline.
- Feed fetchers should fail independently — one feed erroring must never
  take down the others or crash the scheduler (see the per-feed try/except
  in `refresh_feed`).
- Prefer adding config via environment variables (declared in
  `docker-compose.yml` under `environment:`) over hardcoding, especially
  for anything that becomes an API key.
