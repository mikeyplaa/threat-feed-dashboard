import asyncio
import base64
import ipaddress
import logging
import os
import re
from datetime import datetime, timezone

import httpx
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from apscheduler.schedulers.asyncio import AsyncIOScheduler

import db
from feeds import FEEDS

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("app")

app = FastAPI(title="Threat Feed Dashboard")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

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


# Serve the frontend
app.mount("/", StaticFiles(directory="static", html=True), name="static")
