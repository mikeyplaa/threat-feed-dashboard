import asyncio
import logging
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


# Serve the frontend
app.mount("/", StaticFiles(directory="static", html=True), name="static")
