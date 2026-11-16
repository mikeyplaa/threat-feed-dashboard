"""
critical.py — cross-feed "Top Critical Threats" ranking for /api/critical.

Pure functions over the CACHE dict from app.py, so this is testable without
touching the network. It knows nothing about individual feeds: each fetch_*
in feeds.py attaches its own `risk` block ({"score", "category", "reason"}),
and this module only applies generic rules on top:

  1. Freshness   — items lose FRESHNESS_PENALTY_PER_DAY points per day of age
                   after the first 24h (capped at MAX_FRESHNESS_PENALTY).
                   Items without a timestamp come from "currently active"
                   lists (OpenPhish, Blocklist.de, ...) and get no penalty.
  2. Corroboration — the same risk["indicator"] (CVE, IP, URL) seen in
                   several feeds is merged into one entry and gets CORROBORATION_BONUS per
                   extra feed (capped), e.g. a CVE in both KEV and NVD.
  3. Diversity   — at most `max_per_source` entries from any one feed, so a
                   single high-volume source can't fill the whole list.

Final score -> level: 85+ critical, 70+ high, 50+ medium, else low.
"""

from collections import Counter
from datetime import datetime, timezone

FRESHNESS_PENALTY_PER_DAY = 2
MAX_FRESHNESS_PENALTY = 30
CORROBORATION_BONUS = 5
MAX_CORROBORATION_BONUS = 10

LEVELS = ("critical", "high", "medium", "low")


def level_for(score: int) -> str:
    if score >= 85:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 50:
        return "medium"
    return "low"


def parse_timestamp(value) -> datetime | None:
    """Parse the assorted timestamp formats the feeds emit into aware UTC."""
    if not value or not isinstance(value, str):
        return None
    s = value.strip()
    if s.endswith(" UTC"):  # abuse.ch: "2026-11-16 08:12:33 UTC"
        s = s[:-4]
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    s = s.replace(" ", "T", 1)
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def freshness_penalty(ts: datetime | None, now: datetime) -> tuple[int, float | None]:
    """Return (penalty points, age in hours). No timestamp -> no penalty."""
    if ts is None:
        return 0, None
    age_hours = max(0.0, (now - ts).total_seconds() / 3600)
    days_past_first = max(0.0, age_hours / 24 - 1)
    penalty = min(MAX_FRESHNESS_PENALTY, int(days_past_first * FRESHNESS_PENALTY_PER_DAY))
    return penalty, round(age_hours, 1)


def build_critical(cache: dict, limit: int = 25, max_per_source: int = 10, now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)

    # 1. Collect every scored item, merged by id across feeds.
    merged: dict[str, dict] = {}
    considered = 0
    unscored_feeds = []
    for key, feed in cache.items():
        items = feed.get("items") or []
        if items and not any(isinstance(i.get("risk"), dict) for i in items):
            unscored_feeds.append(key)
        for item in items:
            risk = item.get("risk")
            if not isinstance(risk, dict) or "score" not in risk:
                continue
            considered += 1
            ts = parse_timestamp(item.get("timestamp"))
            penalty, age_hours = freshness_penalty(ts, now)
            adjusted = risk["score"] - penalty
            # Merge across feeds only on an explicit indicator; otherwise scope
            # the key to the feed so unrelated numeric row IDs never collide.
            dedupe_key = risk.get("indicator") or f"{key}:{item.get('id') or item.get('title')}"
            candidate = {
                "id": item.get("id"),
                "indicator": risk.get("indicator"),
                "title": item.get("title"),
                "detail": item.get("detail"),
                "source_url": item.get("source_url"),
                "timestamp": ts.isoformat() if ts else None,
                "age_hours": age_hours,
                "base_score": risk["score"],
                "freshness_penalty": penalty,
                "category": risk.get("category") or "other",
                "reason": risk.get("reason") or "",
                "source": key,
                "_adjusted": adjusted,
            }
            existing = merged.get(dedupe_key)
            if existing is None:
                candidate["sources"] = [{"key": key, "name": feed.get("name", key), "reason": candidate["reason"]}]
                merged[dedupe_key] = candidate
                continue
            if key not in {s["key"] for s in existing["sources"]}:
                existing["sources"].append({"key": key, "name": feed.get("name", key), "reason": candidate["reason"]})
            if adjusted > existing["_adjusted"]:
                candidate["sources"] = existing["sources"]
                merged[dedupe_key] = candidate

    # 2. Corroboration bonus + final score/level.
    entries = []
    for e in merged.values():
        # primary (highest-scoring) feed first, so it's the one the UI names
        e["sources"].sort(key=lambda src: src["key"] != e["source"])
        extra = len(e["sources"]) - 1
        bonus = min(MAX_CORROBORATION_BONUS, extra * CORROBORATION_BONUS)
        e["corroboration_bonus"] = bonus
        e["score"] = max(0, min(100, e.pop("_adjusted") + bonus))
        e["level"] = level_for(e["score"])
        entries.append(e)

    # 3. Rank: score desc, then newest first (no timestamp sorts after dated items).
    entries.sort(key=lambda e: (e["score"], e["timestamp"] or ""), reverse=True)

    # 4. Diversity cap per primary source.
    top, per_source = [], Counter()
    for e in entries:
        if per_source[e["source"]] >= max_per_source:
            continue
        per_source[e["source"]] += 1
        top.append(e)
        if len(top) >= limit:
            break
    for rank, e in enumerate(top, 1):
        e["rank"] = rank

    names = {k: f.get("name", k) for k, f in cache.items()}
    breakdown = {
        "by_level": {lvl: sum(1 for e in top if e["level"] == lvl) for lvl in LEVELS},
        "by_category": dict(Counter(e["category"] for e in top).most_common()),
        "by_source": [
            {"key": k, "name": names.get(k, k), "count": n}
            for k, n in Counter(e["source"] for e in top).most_common()
        ],
        "corroborated": sum(1 for e in top if len(e["sources"]) > 1),
        "avg_score": round(sum(e["score"] for e in top) / len(top), 1) if top else None,
    }
    feed_status = [
        {
            "key": k,
            "name": f.get("name", k),
            "items": len(f.get("items") or []),
            "error": f.get("error"),
            "updated": f.get("updated"),
            "unscored": k in unscored_feeds,
        }
        for k, f in cache.items()
    ]
    return {
        "generated": now.isoformat(),
        "limit": limit,
        "max_per_source": max_per_source,
        "considered": considered,
        "unique": len(entries),
        "items": top,
        "breakdown": breakdown,
        "feeds": feed_status,
    }
