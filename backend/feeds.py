"""
feeds.py — fetchers for each threat intel source.

Each fetch_* function returns a list of normalised dicts:
    {
        "id": str,
        "title": str,
        "detail": str,
        "severity": str | None,
        "source_url": str | None,
        "timestamp": str (ISO8601) | None,
        "risk": {"score": int 0-100, "category": str, "reason": str,
                 "indicator": str (optional — CVE/IP/URL for cross-feed merging)},
    }

`risk` feeds the Top Critical Threats page (critical.py / /api/critical).
Every fetcher scores its own items with _risk() so feed-specific judgement
stays inside the fetcher, same as the rest of the registry pattern. Rough
scale: 85+ critical, 70+ high, 50+ medium, below that low.

Add a new feed by writing a fetch_* function and registering it in FEEDS
at the bottom of this file.

Feeds that require API keys read them from environment variables. If the var
is not set the fetcher raises RuntimeError, which the scheduler catches and
surfaces as an error card in the dashboard — nothing else breaks.
"""

import os
import re
import asyncio
import httpx
import logging
import xml.etree.ElementTree as ET
from email.utils import parsedate_to_datetime
from datetime import datetime, timedelta, timezone

logger = logging.getLogger("feeds")

HEADERS = {"User-Agent": "personal-threat-dashboard/0.1 (+https://github.com/)"}
TIMEOUT = 20.0


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def _risk(score: float, category: str, reason: str, indicator: str | None = None) -> dict:
    """Normalised risk block attached to every item (see module docstring).

    `indicator` is the real-world thing the item is about (CVE ID, IP, URL).
    critical.py merges items from different feeds that share an indicator, so
    only set it when it's a genuine cross-feed identifier — not a feed's own
    internal row ID.
    """
    risk = {"score": max(0, min(100, int(round(score)))), "category": category, "reason": reason}
    if indicator:
        risk["indicator"] = str(indicator).strip().lower()
    return risk


# ---------------------------------------------------------------------------
# CISA Known Exploited Vulnerabilities (KEV)
# ---------------------------------------------------------------------------
async def fetch_cisa_kev(client: httpx.AsyncClient, limit: int = 25):
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    r = await client.get(url, headers=HEADERS, timeout=TIMEOUT)
    r.raise_for_status()
    data = r.json()
    vulns = data.get("vulnerabilities", [])
    vulns.sort(key=lambda v: v.get("dateAdded", ""), reverse=True)
    out = []
    for v in vulns[:limit]:
        ransomware = (v.get("knownRansomwareCampaignUse") or "").lower() == "known"
        reason = "Actively exploited in the wild (CISA KEV)"
        if ransomware:
            reason += "; used in ransomware campaigns"
        if v.get("dueDate"):
            reason += f"; federal remediation due {v.get('dueDate')}"
        out.append({
            "id": v.get("cveID"),
            "title": f"{v.get('cveID')} — {v.get('vulnerabilityName')}",
            "detail": f"{v.get('vendorProject', '')} {v.get('product', '')}: {v.get('shortDescription', '')}",
            "severity": "known-exploited",
            "source_url": f"https://nvd.nist.gov/vuln/detail/{v.get('cveID')}",
            "timestamp": v.get("dateAdded"),
            "risk": _risk(98 if ransomware else 95, "vulnerability", reason, v.get("cveID")),
        })
    return out


# ---------------------------------------------------------------------------
# NVD — CRITICAL CVEs published in the last NVD_WINDOW_DAYS days
# NVD returns results oldest-first, so we pull the whole window in ONE request
# (a week of CRITICAL CVEs is a few hundred at most, well under the 2000/page
# cap) and sort newest-first locally — a second request to page from the end
# would double our use of NVD's tight unauthenticated rate limit.
# ---------------------------------------------------------------------------
NVD_WINDOW_DAYS = 7


async def fetch_nvd_recent(client: httpx.AsyncClient, limit: int = 25):
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=NVD_WINDOW_DAYS)
    fmt = "%Y-%m-%dT%H:%M:%S.000"
    params = {
        "pubStartDate": start.strftime(fmt),
        "pubEndDate": end.strftime(fmt),
        "cvssV3Severity": "CRITICAL",
        "resultsPerPage": 2000,
        "startIndex": 0,
    }
    r = await client.get(url, headers=HEADERS, params=params, timeout=TIMEOUT)
    r.raise_for_status()
    data = r.json()
    vulns = data.get("vulnerabilities", [])
    vulns.sort(key=lambda v: v.get("cve", {}).get("published", ""), reverse=True)
    out = []
    for item in vulns[:limit]:
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        descs = cve.get("descriptions", [])
        desc_en = next((d["value"] for d in descs if d.get("lang") == "en"), "")
        metrics = cve.get("metrics", {})
        severity = None
        base_score = None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                cvss = metrics[key][0]["cvssData"]
                base_score = cvss.get("baseScore")
                severity = cvss.get("baseSeverity") or str(base_score)
                break
        try:
            cvss_num = float(base_score) if base_score is not None else 9.0
        except (TypeError, ValueError):
            cvss_num = 9.0
        # CVSS 9.0 -> 80 ... 10.0 -> 90: critical, but below "actively exploited" (KEV)
        nvd_risk = _risk(
            80 + (cvss_num - 9.0) * 10,
            "vulnerability",
            f"CVSS {cvss_num:.1f} {severity or 'CRITICAL'} (NVD) — not yet known to be exploited",
            cve_id,
        )
        out.append({
            "id": cve_id,
            "title": cve_id,
            "detail": desc_en[:300],
            "severity": severity,
            "source_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "timestamp": cve.get("published"),
            "risk": nvd_risk,
        })
    return out


# ---------------------------------------------------------------------------
# abuse.ch ThreatFox — recent malware IOCs (POST API, requires Auth-Key)
# Set ABUSECH_API_KEY from your account at https://abuse.ch/
# ---------------------------------------------------------------------------
async def fetch_threatfox_recent(client: httpx.AsyncClient, limit: int = 25):
    api_key = os.environ.get("ABUSECH_API_KEY")
    if not api_key:
        raise RuntimeError("ABUSECH_API_KEY not set — register at https://abuse.ch/ to get a key")
    url = "https://threatfox-api.abuse.ch/api/v1/"
    payload = {"query": "get_iocs", "days": 1}
    headers = {**HEADERS, "Auth-Key": api_key}
    r = await client.post(url, headers=headers, json=payload, timeout=TIMEOUT)
    r.raise_for_status()
    data = r.json()
    items = data.get("data", [])
    if not isinstance(items, list):
        items = []
    items.sort(key=lambda i: i.get("first_seen", ""), reverse=True)
    out = []
    _tf_base = {"botnet_cc": 85, "payload_delivery": 75, "payload": 70}
    _tf_label = {"botnet_cc": "Botnet C2 server", "payload_delivery": "Malware delivery host", "payload": "Malware payload"}
    for i in items[:limit]:
        threat_type = i.get("threat_type") or ""
        try:
            confidence = int(i.get("confidence_level") or 0)
        except (TypeError, ValueError):
            confidence = 0
        malware = i.get("malware_printable") or "unknown malware"
        out.append({
            "id": str(i.get("id")),
            "title": f"{i.get('ioc_type', 'IOC').upper()}: {i.get('ioc')}",
            "detail": f"Malware: {i.get('malware_printable', 'unknown')} | Confidence: {i.get('confidence_level')}%",
            "severity": i.get("threat_type"),
            "source_url": i.get("reference"),
            "timestamp": i.get("first_seen"),
            # lose up to 10 points for low reporter confidence
            "risk": _risk(
                _tf_base.get(threat_type, 60) - (100 - confidence) / 10,
                "malware-ioc",
                f"{_tf_label.get(threat_type, threat_type or 'IOC')} for {malware} ({confidence}% confidence, ThreatFox)",
                # ip:port IOCs reduce to the bare IP so they match attacker-IP feeds
                re.sub(r":\d+$", "", i.get("ioc") or "") if i.get("ioc_type") == "ip:port" else i.get("ioc"),
            ),
        })
    return out


# ---------------------------------------------------------------------------
# abuse.ch URLhaus — recent malicious URLs (POST API, requires Auth-Key)
# Same ABUSECH_API_KEY as ThreatFox — same account at https://abuse.ch/
# ---------------------------------------------------------------------------
async def fetch_urlhaus_recent(client: httpx.AsyncClient, limit: int = 25):
    api_key = os.environ.get("ABUSECH_API_KEY")
    if not api_key:
        raise RuntimeError("ABUSECH_API_KEY not set — register at https://abuse.ch/ to get a key")
    url = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
    headers = {**HEADERS, "Auth-Key": api_key}
    r = await client.get(url, headers=headers, timeout=TIMEOUT)
    r.raise_for_status()
    data = r.json()
    items = data.get("urls", [])
    out = []
    for i in items[:limit]:
        out.append({
            "id": str(i.get("id")),
            "title": i.get("url", "")[:120],
            "detail": f"Threat: {i.get('threat')} | Tags: {', '.join(i.get('tags') or [])}",
            "severity": i.get("url_status"),
            "source_url": i.get("urlhaus_reference"),
            "timestamp": i.get("date_added"),
            "risk": _risk(
                75 if i.get("url_status") == "online" else 40,
                "malicious-url",
                ("Live" if i.get("url_status") == "online" else "Offline")
                + f" malware distribution URL ({i.get('threat') or 'unknown threat'}, URLhaus)",
                i.get("url"),
            ),
        })
    return out


# ---------------------------------------------------------------------------
# SANS Internet Storm Center — threat diary entries via RSS (no auth)
# The old JSON diary API now returns HTML; RSS is the reliable public feed.
# ---------------------------------------------------------------------------
async def fetch_sans_isc(client: httpx.AsyncClient, limit: int = 20):
    url = "https://isc.sans.edu/rssfeed.xml"
    r = await client.get(url, headers=HEADERS, timeout=TIMEOUT)
    r.raise_for_status()
    root = ET.fromstring(r.content)
    # InfoCON level is embedded in the channel <title> e.g. "..., InfoCON: green"
    channel_title = root.findtext("channel/title") or ""
    infocon_match = re.search(r"InfoCON:\s*(\w+)", channel_title, re.I)
    infocon = infocon_match.group(1).lower() if infocon_match else None
    _severity_map = {"green": "low", "yellow": "medium", "orange": "high", "red": "critical"}
    infocon_severity = _severity_map.get(infocon, infocon)
    _infocon_score = {"red": 90, "orange": 75, "yellow": 55, "green": 30}
    sans_risk = _risk(
        _infocon_score.get(infocon, 30),
        "advisory",
        f"SANS ISC diary at InfoCON {infocon or 'unknown'}",
    )
    out = []
    for item in root.findall(".//item")[:limit]:
        title = item.findtext("title") or ""
        link = item.findtext("link") or ""
        pub_date = item.findtext("pubDate")
        description = re.sub(r"<[^>]+>", "", item.findtext("description") or "").strip()
        # diary ID from URL: .../diary/rss/12345 or .../diary/12345
        diary_id_match = re.search(r"/diary(?:/rss)?/(\d+)", link)
        diary_id = diary_id_match.group(1) if diary_id_match else link
        canonical_url = f"https://isc.sans.edu/diary/{diary_id}" if diary_id_match else link
        try:
            ts = parsedate_to_datetime(pub_date).isoformat() if pub_date else None
        except Exception:
            ts = pub_date
        out.append({
            "id": diary_id,
            "title": title,
            "detail": description[:300] or f"InfoCON: {infocon or 'unknown'}",
            "severity": infocon_severity,
            "source_url": canonical_url,
            "timestamp": ts,
            "risk": sans_risk,
        })
    return out


# ---------------------------------------------------------------------------
# OpenPhish — active phishing URLs (no auth, plain-text feed)
# The URL does a redirect; follow_redirects is required.
# ---------------------------------------------------------------------------
async def fetch_openphish(client: httpx.AsyncClient, limit: int = 30):
    url = "https://openphish.com/feed.txt"
    r = await client.get(url, headers=HEADERS, timeout=TIMEOUT, follow_redirects=True)
    r.raise_for_status()
    urls = [line.strip() for line in r.text.splitlines() if line.strip() and not line.startswith("#")]
    out = []
    for phish_url in urls[:limit]:
        # use a stable ID derived from the URL itself
        out.append({
            "id": str(abs(hash(phish_url)) % 10**9),
            "title": phish_url[:120],
            "detail": "Active phishing URL (OpenPhish community feed)",
            "severity": "phishing",
            "source_url": None,
            "timestamp": None,
            "risk": _risk(65, "phishing", "Currently active phishing URL (OpenPhish)", phish_url),
        })
    return out


# ---------------------------------------------------------------------------
# Blocklist.de — SSH brute-force attacker IPs (no auth, plain-text feed)
# List is rebuilt every 30 min; we take the first `limit` entries.
# ---------------------------------------------------------------------------
async def fetch_blocklist_de(client: httpx.AsyncClient, limit: int = 30):
    url = "https://lists.blocklist.de/lists/ssh.txt"
    r = await client.get(url, headers=HEADERS, timeout=TIMEOUT)
    r.raise_for_status()
    ips = [
        line.strip()
        for line in r.text.splitlines()
        if line.strip() and not line.startswith("#")
    ]
    out = []
    for ip in ips[:limit]:
        out.append({
            "id": ip,
            "title": ip,
            "detail": "SSH brute-force attacker reported to Blocklist.de",
            "severity": "brute-force",
            "source_url": f"https://www.blocklist.de/en/search.html?ip={ip}",
            "timestamp": None,
            "risk": _risk(45, "attacker-ip", "Reported for SSH brute-forcing in the last 48h (Blocklist.de)", ip),
        })
    return out


# ---------------------------------------------------------------------------
# LevelBlue OTX — recent threat intelligence pulses
# Requires OTX_API_KEY — free account at https://otx.alienvault.com/
# ---------------------------------------------------------------------------
async def fetch_otx(client: httpx.AsyncClient, limit: int = 20):
    api_key = os.environ.get("OTX_API_KEY")
    if not api_key:
        raise RuntimeError("OTX_API_KEY not set — free account at https://otx.alienvault.com/")
    url = "https://otx.alienvault.com/api/v1/pulses/activity"
    headers = {**HEADERS, "X-OTX-API-KEY": api_key}
    r = await client.get(url, headers=headers, params={"limit": limit}, timeout=TIMEOUT)
    r.raise_for_status()
    data = r.json()
    out = []
    for pulse in data.get("results", []):
        tags = ", ".join(pulse.get("tags", [])[:5])
        desc = (pulse.get("description") or tags or "")[:300]
        out.append({
            "id": pulse.get("id", ""),
            "title": pulse.get("name", ""),
            "detail": desc,
            "severity": pulse.get("TLP"),
            "source_url": f"https://otx.alienvault.com/pulse/{pulse.get('id')}",
            "timestamp": pulse.get("created"),
            "risk": _risk(55, "threat-intel", "Community threat intel pulse (LevelBlue OTX)"),
        })
    return out


# ---------------------------------------------------------------------------
# CrowdSec — Blocklist.de SSH attackers enriched with CrowdSec reputation
# Free key supports /v2/smoke/{ip} lookups; bulk /v2/fire needs a paid plan.
# We fetch the blocklist.de SSH list then fan out parallel smoke lookups.
# Requires CROWDSEC_API_KEY — free community key at https://app.crowdsec.net/
#
# The free CTI tier is a flat 50 queries/day (confirmed via CrowdSec's own
# CTI product page, Oct 2026) — far less than the 15-minute dashboard refresh
# would burn through even at a handful of IPs per call. This fetcher
# self-throttles below the scheduler's cadence: it only hits the CrowdSec API
# once per _CROWDSEC_COOLDOWN_MINUTES and returns the last cached batch the
# rest of the time, so the column still "refreshes" every cycle without
# spending quota. 5 IPs every 3h is ~40 requests/day, leaving headroom.
# ---------------------------------------------------------------------------
_crowdsec_cache: dict = {"items": [], "fetched_at": None}
_CROWDSEC_COOLDOWN_MINUTES = 180


async def fetch_crowdsec(client: httpx.AsyncClient, limit: int = 5):
    api_key = os.environ.get("CROWDSEC_API_KEY")
    if not api_key:
        raise RuntimeError("CROWDSEC_API_KEY not set — free community key at https://app.crowdsec.net/")

    now = datetime.now(timezone.utc)
    last = _crowdsec_cache["fetched_at"]
    if last and (now - last) < timedelta(minutes=_CROWDSEC_COOLDOWN_MINUTES):
        return _crowdsec_cache["items"]

    # Pull a fresh batch of SSH attacker IPs from Blocklist.de
    r = await client.get("https://lists.blocklist.de/lists/ssh.txt", headers=HEADERS, timeout=TIMEOUT)
    r.raise_for_status()
    ips = [
        line.strip()
        for line in r.text.splitlines()
        if line.strip() and not line.startswith("#")
    ][:limit]

    smoke_headers = {**HEADERS, "x-api-key": api_key}

    async def _smoke(ip: str) -> dict | None:
        resp = await client.get(
            f"https://cti.api.crowdsec.net/v2/smoke/{ip}",
            headers=smoke_headers,
            timeout=TIMEOUT,
        )
        if resp.status_code == 429:
            raise RuntimeError("CrowdSec CTI quota exceeded (429) — lower `limit` in fetch_crowdsec or back off REFRESH_INTERVAL_MINUTES")
        return resp.json() if resp.status_code == 200 else None

    results = await asyncio.gather(*(_smoke(ip) for ip in ips))

    _rep_order = {"malicious": 0, "suspicious": 1, "known": 2, "benign": 3}
    out = []
    for ip, data in zip(ips, results):
        if data is None:
            continue
        reputation = data.get("reputation") or "unknown"
        behaviors = ", ".join(b.get("label", "") for b in (data.get("behaviors") or [])[:3])
        location = data.get("location") or {}
        country = location.get("country", "")
        as_name = data.get("as_name", "")
        noise = data.get("background_noise", "")

        parts = []
        if as_name:
            parts.append(as_name)
        if country:
            parts.append(f"({country})")
        if behaviors:
            parts.append(f"· {behaviors}")
        if noise and noise != "none":
            parts.append(f"· noise: {noise}")

        _cs_score = {"malicious": 70, "suspicious": 55, "known": 35, "benign": 10}
        out.append({
            "id": ip,
            "title": ip,
            "detail": " ".join(parts),
            "severity": reputation,
            "source_url": f"https://app.crowdsec.net/cti/{ip}",
            "timestamp": None,
            "risk": _risk(
                _cs_score.get(reputation, 30),
                "attacker-ip",
                f"CrowdSec reputation: {reputation}" + (f" ({behaviors})" if behaviors else ""),
                ip,
            ),
        })

    out.sort(key=lambda x: _rep_order.get(x["severity"], 9))
    _crowdsec_cache["items"] = out
    _crowdsec_cache["fetched_at"] = now
    return out


# ---------------------------------------------------------------------------
# UK NCSC — news + threat reports via RSS (no auth)
# Two official feeds merged into one column, newest first. The threat-report
# feed has been reported by RSS aggregators as having gone quiet, so each feed
# is fetched independently: one failing is logged and skipped, and the column
# only errors if BOTH fail. Items carry no severity, so the risk score is
# keyword-based: titles that read like an active threat get boosted.
# ---------------------------------------------------------------------------
# Order matters: an item in both feeds keeps the label of the first one.
NCSC_FEEDS = {
    "threat report": "https://www.ncsc.gov.uk/api/1/services/v1/report-rss-feed.xml",
    "news": "https://www.ncsc.gov.uk/api/1/services/v1/news-rss-feed.xml",
}
_NCSC_URGENT = re.compile(
    r"\b(vulnerab\w*|exploit\w*|ransomware|alert|advisory|zero[- ]day|"
    r"critical|patch\w*|compromise\w*|breach\w*|malware|attack\w*)\b",
    re.I,
)


def _ncsc_risk(kind: str, title: str) -> dict:
    hits = list(dict.fromkeys(m.lower() for m in _NCSC_URGENT.findall(title or "")))
    if hits:
        return _risk(70, "advisory", f"UK NCSC {kind} mentioning {', '.join(hits)}")
    return _risk(40, "advisory", f"UK NCSC {kind}")


async def fetch_ncsc(client: httpx.AsyncClient, limit: int = 25):
    async def _one(kind: str, url: str):
        r = await client.get(url, headers=HEADERS, timeout=TIMEOUT, follow_redirects=True)
        r.raise_for_status()
        return kind, ET.fromstring(r.content)

    results = await asyncio.gather(*(_one(k, u) for k, u in NCSC_FEEDS.items()), return_exceptions=True)
    errors = [f"{kind}: {res}" for kind, res in zip(NCSC_FEEDS, results) if isinstance(res, Exception)]
    if len(errors) == len(NCSC_FEEDS):
        raise RuntimeError("all NCSC feeds failed — " + "; ".join(errors))
    for e in errors:
        logger.warning(f"NCSC partial failure, continuing with other feed: {e}")

    seen, out = set(), []
    for res in results:
        if isinstance(res, Exception):
            continue
        kind, root = res
        for item in root.findall(".//item"):
            link = (item.findtext("link") or "").strip()
            title = (item.findtext("title") or "").strip()
            key = link or title
            if not key or key in seen:
                continue
            seen.add(key)
            pub_date = item.findtext("pubDate")
            try:
                ts = parsedate_to_datetime(pub_date).astimezone(timezone.utc).isoformat() if pub_date else None
            except Exception:
                ts = None
            description = re.sub(r"<[^>]+>", "", item.findtext("description") or "").strip()
            out.append({
                "id": key,
                "title": title,
                "detail": description[:300] or f"NCSC {kind}",
                "severity": kind,
                "source_url": link or None,
                "timestamp": ts,
                "risk": _ncsc_risk(kind, title),
            })
    out.sort(key=lambda i: i["timestamp"] or "", reverse=True)
    return out[:limit]


# ---------------------------------------------------------------------------
# Hacker News — recent security stories via Algolia search API (no auth)
# ---------------------------------------------------------------------------
async def fetch_hackernews(client: httpx.AsyncClient, limit: int = 20):
    url = "https://hn.algolia.com/api/v1/search_by_date"
    params = {
        "query": "security",
        "tags": "story",
        "hitsPerPage": limit,
    }
    r = await client.get(url, headers=HEADERS, params=params, timeout=TIMEOUT)
    r.raise_for_status()
    hits = r.json().get("hits", [])
    out = []
    for h in hits:
        oid = str(h.get("objectID", ""))
        points = h.get("points") or 0
        comments = h.get("num_comments") or 0
        external_url = h.get("url")
        hn_url = f"https://news.ycombinator.com/item?id={oid}"
        out.append({
            "id": oid,
            "title": h.get("title", ""),
            "detail": f"{points} points · {comments} comments · by {h.get('author', '')}",
            "severity": None,
            "source_url": external_url or hn_url,
            "timestamp": h.get("created_at"),
            "risk": _risk(20, "news", "Security news story (Hacker News)"),
        })
    return out


# ---------------------------------------------------------------------------
# urlscan.io — recent publicly-submitted URL scans tagged malicious
# Requires URLSCAN_API_KEY — unauthenticated search returns 403. The free
# plan also can't search `verdicts.overall.malicious` (paid-plan-only field,
# confirmed Oct 2026 — "Your current plan does not allow you to search field"),
# so this uses the community-tag field `task.tags` instead, which is free-tier
# accessible and the `verdicts` object isn't even present on the response.
# ---------------------------------------------------------------------------
async def fetch_urlscan(client: httpx.AsyncClient, limit: int = 25):
    api_key = os.environ.get("URLSCAN_API_KEY")
    if not api_key:
        raise RuntimeError("URLSCAN_API_KEY not set — free account at https://urlscan.io/")
    url = "https://urlscan.io/api/v1/search/"
    params = {"q": "task.tags:malicious", "size": limit}
    headers = {**HEADERS, "API-Key": api_key}
    r = await client.get(url, headers=headers, params=params, timeout=TIMEOUT)
    r.raise_for_status()
    data = r.json()
    results = data.get("results", [])
    results.sort(key=lambda i: i.get("task", {}).get("time", ""), reverse=True)
    out = []
    for i in results[:limit]:
        task = i.get("task", {})
        page = i.get("page", {})
        uuid = task.get("uuid", "")
        domain = page.get("domain", "")
        country = page.get("country", "")
        tags = task.get("tags") or []
        detail_parts = [f"Domain: {domain or 'unknown'}"]
        if tags:
            detail_parts.append(f"Tags: {', '.join(tags)}")
        if country:
            detail_parts.append(f"Country: {country}")
        out.append({
            "id": uuid,
            "title": (page.get("url") or task.get("url") or "")[:120],
            "detail": " | ".join(detail_parts),
            "severity": tags[0] if tags else "malicious",
            "source_url": f"https://urlscan.io/result/{uuid}/" if uuid else None,
            "timestamp": task.get("time"),
            "risk": _risk(
                65 if "phishing" in tags else 60,
                "phishing" if "phishing" in tags else "malicious-url",
                "Scan tagged " + (", ".join(tags) if tags else "malicious") + " (urlscan.io)",
                page.get("url") or task.get("url"),
            ),
        })
    return out


# ---------------------------------------------------------------------------
# DShield (SANS ISC) — today's top attack source IPs, geolocated for the map
# No auth required for /api/topips. ISC's own per-IP lookup (/api/ip/{ip}) is
# too fragile for bulk enrichment — confirmed Oct 2026: a single extra call
# right after a topips request tripped a shared "Too Many Requests... bots
# cranky" 300s cooldown, suggesting the per-IP endpoint is community-rate-
# limited and not meant for fanning out. Geolocation instead uses ipwho.is
# (free, HTTPS, no key, no documented hard limit). A module-level IP->geo
# cache keeps the volume low regardless: DShield's top-IPs list is dominated
# by the same handful of scanners day to day, so after the first couple of
# refreshes almost nothing new needs to be resolved.
# ---------------------------------------------------------------------------
_geo_cache: dict = {}  # ip -> geo dict, or None if lookup failed


async def _geolocate(client: httpx.AsyncClient, ip: str) -> dict | None:
    if ip in _geo_cache:
        return _geo_cache[ip]
    geo = None
    try:
        r = await client.get(f"https://ipwho.is/{ip}", timeout=TIMEOUT)
        data = r.json()
        if data.get("success"):
            geo = {
                "country": data.get("country"),
                "country_code": data.get("country_code"),
                "lat": data.get("latitude"),
                "lon": data.get("longitude"),
            }
    except Exception:
        pass
    _geo_cache[ip] = geo
    return geo


async def fetch_dshield_map(client: httpx.AsyncClient, limit: int = 20):
    r = await client.get(f"https://isc.sans.edu/api/topips/records/{limit}?json", headers=HEADERS, timeout=TIMEOUT)
    r.raise_for_status()
    rows = r.json()
    if not isinstance(rows, list):
        rows = []

    geos = await asyncio.gather(*(_geolocate(client, row.get("source", "")) for row in rows))

    out = []
    for row, geo in zip(rows, geos):
        ip = row.get("source", "")
        geo = geo or {}
        reports = row.get("reports") or 0
        targets = row.get("targets") or 0
        detail_parts = [f"{reports} reports / {targets} targets today"]
        if geo.get("country"):
            detail_parts.append(geo["country"])
        out.append({
            "id": ip,
            "title": ip,
            "detail": " | ".join(detail_parts),
            "severity": None,
            "source_url": f"https://isc.sans.edu/ipinfo.html?ip={ip}",
            "timestamp": None,
            "risk": _risk(50, "attacker-ip", f"Top attack source today: {reports} reports against {targets} targets (DShield)", ip),
            "lat": geo.get("lat"),
            "lon": geo.get("lon"),
            "country": geo.get("country"),
            "country_code": geo.get("country_code"),
            "reports": reports,
            "targets": targets,
        })
    return out


# ---------------------------------------------------------------------------
# Registry: key -> (display name, fetch function)
# ---------------------------------------------------------------------------
FEEDS = {
    "hackernews":  ("Hacker News — Security Stories",       fetch_hackernews),
    "cisa_kev":    ("CISA Known Exploited Vulnerabilities", fetch_cisa_kev),
    "nvd_recent":  ("NVD — Critical CVEs (Last 7 Days)",     fetch_nvd_recent),
    "sans_isc":    ("SANS ISC — Threat Diaries",            fetch_sans_isc),
    "ncsc":        ("UK NCSC — News & Threat Reports",      fetch_ncsc),
    "openphish":   ("OpenPhish — Active Phishing URLs",     fetch_openphish),
    "blocklist":   ("Blocklist.de — SSH Attackers",         fetch_blocklist_de),
    "threatfox":   ("ThreatFox — Recent Malware IOCs",      fetch_threatfox_recent),
    "urlhaus":     ("URLhaus — Recent Malicious URLs",       fetch_urlhaus_recent),
    "otx":         ("LevelBlue OTX — Threat Pulses",        fetch_otx),
    "crowdsec":    ("CrowdSec — SSH Attacker Reputation",    fetch_crowdsec),
    "urlscan":     ("urlscan.io — Malicious URL Scans",      fetch_urlscan),
    "dshield_map": ("DShield — Top Attack Sources (Live Map)", fetch_dshield_map),
}
