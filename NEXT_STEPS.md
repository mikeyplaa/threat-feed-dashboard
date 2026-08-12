# Ideas for Claude Code — what to ask it to build next

Drop `CLAUDE.md` in the repo root, open the project in Claude Code, and use
these as starting prompts. Roughly ordered by what unlocks the most value
next — not a strict sequence, pick what you actually want.

## 1. New feed sources

> "Add AlienVault OTX as a feed source. I have a free API key I'll set as
> an env var OTX_API_KEY. Follow the fetch_* pattern in feeds.py — pull
> recent pulses and normalise indicators into the standard item shape."

> "Add VirusTotal as an on-demand lookup rather than a scheduled feed —
> I want a search box in the UI where I can paste an IP/domain/hash and
> get VT's verdict, not a bulk pull (their free tier is 4 req/min)."

> "Add Microsoft MSRC security update feed and AWS Security Bulletins,
> since I run a 93-account AWS estate and Azure/M365 — these are more
> relevant to my actual environment than generic feeds."

## 2. Persistence & history

> "Right now the cache is in-memory and resets on restart. Add SQLite
> persistence so feed items survive restarts, and so I can see a 7-day
> history per feed rather than just the latest snapshot. Keep it a single
> file, no external DB service."

> "Add a simple trend view — count of new IOCs/CVEs per feed per day over
> the last 30 days, as a small chart on the dashboard."

## 3. Filtering & relevance to my stack

> "I want to filter the CVE/KEV feeds down to what's relevant to my
> environment: AWS, Azure, Microsoft 365, and [any specific products you
> run]. Add a keyword/vendor filter config and a toggle in the UI between
> 'all' and 'relevant to my stack'."

> "Add tagging — let me mark items as reviewed/ignored/actioned, persisted
> across refreshes, so the dashboard doesn't show me the same triaged item
> every day."

## 4. Alerting

> "Add an optional notification hook — when a new CISA KEV item appears,
> or a ThreatFox IOC matches [criteria], send a webhook to
> [Slack/Teams/ntfy/email]. Make the webhook URL an env var, off by
> default."

## 5. Auth & exposure

> "I want to put this behind a reverse proxy with basic auth so I can
> access it from outside my home network. Add a Caddy service to
> docker-compose.yml with basic auth and TLS via Let's Encrypt, in front
> of the existing dashboard container."

> "Alternative to the above: set this up to only be reachable over
> Tailscale rather than exposing a port publicly at all — what changes
> in docker-compose for that?"

## 6. Testing & reliability

> "Add pytest coverage for the fetch_* functions in feeds.py — mock the
> httpx responses (don't hit live APIs in tests), and cover the error
> path where a feed 403s or times out."

> "Add a GitHub Actions workflow that runs the test suite and a docker
> build on every push."

## 7. Polish

> "Add a dark/light theme toggle."

> "Add a compact/dense view toggle for the columns — right now each item
> takes a fair bit of vertical space."

> "Make the column layout configurable — let me pin/reorder/hide feed
> columns via a small settings panel, persisted in localStorage."

---

## Things to decide before asking for them (so Claude Code doesn't guess)

- **Persistence**: SQLite is the natural next step given the "single file,
  no extra service" constraint in CLAUDE.md — flag it if you want
  something else (Postgres, etc.) for a reason.
- **Exposure**: decide localhost-only vs. Tailscale vs. reverse-proxy
  *before* asking for auth work — it changes the shape of the answer.
- **Alerting destination**: pick Slack/Teams/ntfy/email now so you're not
  re-doing the webhook integration later.
