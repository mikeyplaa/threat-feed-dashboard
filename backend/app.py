import asyncio
import base64
import ipaddress
import logging
import os
import re
from datetime import datetime, timezone

import httpx
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from apscheduler.schedulers.asyncio import AsyncIOScheduler

import db
from feeds import FEEDS

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("app")

app = FastAPI(title="Threat Feed Dashboard")

# The frontend is served from this same app (StaticFiles mount below), so no
# cross-origin requests are legitimate. Wildcard CORS would let any site the
# user visits script calls against this unauthenticated API — see CLAUDE.md's
# "localhost/home network only" trust model — so no CORS middleware is added.

# In-memory cache: { feed_key: {"name": ..., "updated": ..., "items": [...], "error": ...} }
CACHE: dict = {
    key: {"name": name, "updated": None, "items": [], "error": None}
    for key, (name, _) in FEEDS.items()
}

REFRESH_INTERVAL_MINUTES = 15


async def refresh_feed(key: str):
    name, fetch_fn = FEEDS[key]
    async with httpx.AsyncClient() as client:
        try:
            items = await fetch_fn(client)
            fetched_at = datetime.now(timezone.utc).isoformat()
            CACHE[key] = {
                "name": name,
                "updated": fetched_at,
                "items": items,
                "error": None,
            }
            await db.save_snapshot(key, items, fetched_at)
            logger.info(f"Refreshed {key}: {len(items)} items")
        except Exception as e:
            logger.warning(f"Failed to refresh {key}: {e}")
            CACHE[key]["error"] = str(e)
            CACHE[key]["updated"] = datetime.now(timezone.utc).isoformat()


async def refresh_all():
    await asyncio.gather(*(refresh_feed(k) for k in FEEDS))


scheduler = AsyncIOScheduler()


@app.on_event("startup")
async def startup():
    await db.init_db()
    # Warm cache from persisted snapshots so dashboard isn't blank on restart
    for key, (name, _) in FEEDS.items():
        snapshot = await db.load_latest_snapshot(key)
        if snapshot:
            CACHE[key].update(snapshot)
            logger.info(f"Loaded persisted snapshot for {key}: {len(snapshot['items'])} items")
    asyncio.create_task(refresh_all())
    scheduler.add_job(refresh_all, "interval", minutes=REFRESH_INTERVAL_MINUTES)
    scheduler.start()


@app.get("/api/feeds")
async def get_all_feeds():
    return CACHE


@app.get("/api/feeds/{key}")
async def get_feed(key: str):
    return CACHE.get(key, {"error": "unknown feed"})


@app.post("/api/refresh")
async def force_refresh():
    await refresh_all()
    return {"status": "refreshed", "at": datetime.now(timezone.utc).isoformat()}


@app.get("/api/health")
async def health():
    return {"status": "ok", "feeds": list(FEEDS.keys())}


@app.get("/api/history/{key}")
async def get_feed_history(key: str, days: int = 7):
    if key not in FEEDS:
        return {"error": "unknown feed"}
    return await db.get_daily_counts(key, days)


# ---------------------------------------------------------------------------
# VirusTotal on-demand lookup
# ---------------------------------------------------------------------------
_VT_BASE = "https://www.virustotal.com/api/v3"
_VT_GUI_PATH = {"ip": "ip-address", "domain": "domain", "hash": "file", "url": "url"}


def _vt_classify(query: str) -> tuple[str, str]:
    """Return (ioc_type, api_url) for a raw query string."""
    q = query.strip()
    if q.startswith(("http://", "https://", "ftp://")):
        url_id = base64.urlsafe_b64encode(q.encode()).decode().rstrip("=")
        return "url", f"{_VT_BASE}/urls/{url_id}"
    try:
        ipaddress.ip_address(q)
        return "ip", f"{_VT_BASE}/ip_addresses/{q}"
    except ValueError:
        pass
    if re.fullmatch(r"[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", q):
        return "hash", f"{_VT_BASE}/files/{q}"
    return "domain", f"{_VT_BASE}/domains/{q}"


@app.get("/api/vt/lookup")
async def vt_lookup(q: str):
    api_key = os.environ.get("VT_API_KEY")
    if not api_key:
        return {"error": "VT_API_KEY not set — free account at https://www.virustotal.com/"}
    q = q.strip()
    if not q:
        return {"error": "Empty query"}

    ioc_type, api_url = _vt_classify(q)
    async with httpx.AsyncClient() as client:
        try:
            r = await client.get(api_url, headers={"x-apikey": api_key}, timeout=15.0)
            if r.status_code == 404:
                return {"error": "Not found in VirusTotal", "query": q, "type": ioc_type}
            r.raise_for_status()
            raw = r.json()
        except httpx.HTTPStatusError as e:
            return {"error": f"VirusTotal returned {e.response.status_code}", "query": q}
        except Exception as e:
            return {"error": str(e), "query": q}

    attrs = raw.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})

    if ioc_type == "url":
        url_id = base64.urlsafe_b64encode(q.encode()).decode().rstrip("=")
        gui_url = f"https://www.virustotal.com/gui/url/{url_id}"
    else:
        gui_url = f"https://www.virustotal.com/gui/{_VT_GUI_PATH[ioc_type]}/{q}"

    result = {
        "query": q,
        "type": ioc_type,
        "malicious":  stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "undetected": stats.get("undetected", 0),
        "harmless":   stats.get("harmless", 0),
        "total":      sum(stats.values()),
        "reputation": attrs.get("reputation"),
        "tags":       attrs.get("tags", [])[:5],
        "vt_url":     gui_url,
    }
    if ioc_type == "ip":
        result["country"]  = attrs.get("country", "")
        result["as_owner"] = attrs.get("as_owner", "")
        result["network"]  = attrs.get("network", "")
    elif ioc_type == "domain":
        result["registrar"]   = attrs.get("registrar", "")
        result["categories"]  = list(attrs.get("categories", {}).values())[:3]
    elif ioc_type == "hash":
        result["name"]      = attrs.get("meaningful_name") or next(iter(attrs.get("names", [])), None)
        result["file_type"] = attrs.get("type_description", "")
        result["size"]      = attrs.get("size")
    elif ioc_type == "url":
        result["final_url"] = attrs.get("last_final_url", "")
        result["title"]     = attrs.get("title", "")
    return result


# ---------------------------------------------------------------------------
# EmailRep on-demand lookup
# EmailRep's unauthenticated API is fully disabled, not just rate-limited
# (confirmed Oct 2026 — 429 "the unauthenticated API is currently disabled.
# please use an API key") — EMAILREP_API_KEY is required, sent via a `Key`
# header (not Authorization/X-Api-Key). There's no public report page to
# link out to (unlike VirusTotal's GUI) since EmailRep is API-only.
# ---------------------------------------------------------------------------
@app.get("/api/emailrep/lookup")
async def emailrep_lookup(q: str):
    api_key = os.environ.get("EMAILREP_API_KEY")
    if not api_key:
        return {"error": "EMAILREP_API_KEY not set — free key at https://emailrep.io/"}
    q = q.strip()
    if not q or "@" not in q:
        return {"error": "Enter a valid email address"}

    async with httpx.AsyncClient() as client:
        try:
            r = await client.get(f"https://emailrep.io/{q}", headers={"Key": api_key}, timeout=15.0)
            raw = r.json()
        except Exception as e:
            return {"error": str(e), "query": q}

    if raw.get("status") == "fail":
        return {"error": raw.get("reason", "Lookup failed"), "query": q}

    details = raw.get("details", {})
    return {
        "query": q,
        "reputation": raw.get("reputation"),
        "suspicious": raw.get("suspicious"),
        "references": raw.get("references"),
        "blacklisted": details.get("blacklisted"),
        "malicious_activity": details.get("malicious_activity"),
        "credentials_leaked": details.get("credentials_leaked"),
        "data_breach": details.get("data_breach"),
        "domain_reputation": details.get("domain_reputation"),
        "new_domain": details.get("new_domain"),
        "free_provider": details.get("free_provider"),
        "disposable": details.get("disposable"),
        "deliverable": details.get("deliverable"),
        "spam": details.get("spam"),
        "spoofable": details.get("spoofable"),
        "first_seen": details.get("first_seen"),
        "last_seen": details.get("last_seen"),
        "profiles": details.get("profiles", []),
    }


# Serve the frontend
app.mount("/", StaticFiles(directory="static", html=True), name="static")
