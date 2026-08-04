
**Wiestell Opensource free threat intelligence platform that aggregates, enriches, and scores IOCs from multiple feeds.**

![Next.js](https://img.shields.io/badge/Next.js-16-black?logo=next.js)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?logo=fastapi)
![MySQL](https://img.shields.io/badge/MySQL-8-4479A1?logo=mysql&logoColor=white)
![Redis](https://img.shields.io/badge/Redis-7_(optional)-DC382D?logo=redis)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker)
![TypeScript](https://img.shields.io/badge/TypeScript-5-3178C6?logo=typescript)
![Python](https://img.shields.io/badge/Python-3.11-3776AB?logo=python)
![License](https://img.shields.io/badge/License-MIT-green)


Wiestell is a production-grade, full-stack Threat Intelligence Platform (TIP) designed for SOC analysts, threat hunters, and cybersecurity professionals. It aggregates indicators of compromise (IOCs) from 11 open-source threat feeds, enriches them with WHOIS/DNS/GeoIP/Shodan data, calculates composite threat scores using a weighted algorithm, maps indicators to the MITRE ATT&CK framework, and presents everything through a tactical dark-themed SOC dashboard built with Next.js and TypeScript.

> **Project docs:** [PROJECT_SUMMARY.md](PROJECT_SUMMARY.md) — architecture and codebase analysis ·
> [SECURITY_REVIEW.md](SECURITY_REVIEW.md) — security review findings and remediation.

## Features

| Feature | Status |
|---------|--------|
| Multi-feed IOC ingestion (13 connectors) | Implemented |
| IOC search with advanced filtering | Implemented |
| Composite threat scoring (0-100) | Implemented |
| IOC enrichment (WHOIS, DNS, GeoIP) | Implemented |
| MITRE ATT&CK heatmap matrix | Implemented |
| Real-time dashboard with stats | Implemented |
| Feed health monitoring | Implemented |
| IOC relationship correlation | Implemented |
| Threat hunting workspace | Implemented |
| Report generation (daily brief + custom) | Implemented |
| STIX 2.1 / CSV / JSON export | Implemented |
| ~~Celery background task processing~~ | **Removed 2026-08-17** — the beat schedule was disabled and the one live caller dispatched into a broker that does not exist |
| Docker single-command deployment | Implemented |
| Geographic threat distribution | Implemented |

## Architecture

```
                        FRONTEND (Next.js 16)
  Dashboard | IOC Search | Feed Manager | Reports | ATT&CK Map
                           |
                        REST API
                           |
                     BACKEND (FastAPI)
  Feed Ingestion | Enrichment Engine | Scoring | Correlation
        |              |            |            |
     MySQL        Redis (opt.)              External
   + indexes      cache/limits   Workers    Threat Feeds
```

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | Next.js 16 (App Router), React 19, TypeScript 5, Tailwind CSS 4, Recharts, D3.js |
| Backend | FastAPI 0.115, Python 3.11, SQLAlchemy 2 (async), Pydantic v2 |
| Database | **MySQL** via `aiomysql` (async) + `pymysql` (Alembic, scripts). JSON columns are queried with `json_contains`; the PostgreSQL `ARRAY` operators do **not** work here |
| Cache / rate limits / queue | Redis 7 — optional; the code degrades to in-process fallbacks |
| Task Queue | None. Background work is driven by external cron against `POST /api/v1/feeds/sync-all`; enrichment runs in-request. Celery was deleted on 2026-08-17 |
| Containerization | Docker + Docker Compose (local); Render + Vercel in production |

## Quick Start

**`docker-compose.yml` does not start a database.** The Postgres service is commented out and the platform expects an external MySQL instance — production runs Hostinger MySQL with the API on Render and the frontend on Vercel. Provision MySQL first, then point `DATABASE_URL` at it.

```bash
# Clone the repository
git clone https://github.com/Garyson26/Wiestell_threatIntel_platform.git
cd Wiestell_threatIntel_platform

# Copy the environment file and fill it in.
# DATABASE_URL and SECRET_KEY are REQUIRED — there are no defaults, and the
# backend refuses to start in production without a strong SECRET_KEY.
cp .env.example .env
python -c "import secrets; print('SECRET_KEY=' + secrets.token_urlsafe(48))"

# Start frontend, backend, Redis and nginx (MySQL is external)
docker-compose up -d

# Apply migrations, then seed
docker-compose exec backend alembic upgrade head
docker-compose exec backend python /app/../scripts/seed_feeds.py   # feed registry
docker-compose exec backend python /app/../scripts/seed_mitre.py   # ATT&CK catalogue

# Generate sample data (optional, for demo)
docker-compose exec backend python /app/../scripts/generate_sample_data.py
```

Access the application:
- **Dashboard**: http://localhost:3000
- **API docs**: not served by default. Set `ENABLE_API_DOCS=true` (development only) to expose `/docs`, `/redoc` and `/openapi.json`; nginx returns 404 for those paths regardless.

### Running the tests

```bash
cd backend
pip install -r requirements.txt -r requirements-dev.txt
python -m pytest            # no database required
```

## Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `DATABASE_URL` | MySQL connection string (`mysql+pymysql://…`) | Yes — no fallback; startup fails without it |
| `DATABASE_ASYNC_URL` | Async MySQL DSN (`mysql+aiomysql://…`); derived from `DATABASE_URL` if unset | No |
| `SECRET_KEY` | JWT signing key. Min 32 random chars; **production refuses to start without it**. Generate: `python -c "import secrets; print(secrets.token_urlsafe(48))"` | Yes |
| `CORS_ORIGINS` | Comma-separated allowed browser origins. `*` is rejected (credentialed API) | Yes |
| `CRON_SECRET` | Shared secret for scheduler calls to `/feeds/sync-all` and `/enrichment/backfill/start`, sent as `X-Cron-Secret` | Recommended |
| `ENABLE_API_DOCS` | Serve `/docs`, `/redoc`, `/openapi.json`. Default `false` | No |
| `REDIS_URL` | Redis connection string (cache, distributed rate limits). Deliberately unset on Render — see the single-process invariant in CLAUDE.md | No |
| `RESEND_API_KEY` | Resend API key (sending access) — **required for OTP login to work** | Yes |
| `EMAIL_FROM` | Sender, e.g. `Wiestell <noreply@wiestell.com>` | No (has a default) |
| `OTX_API_KEY` | AlienVault OTX API key | No |
| `ABUSEIPDB_API_KEY` | AbuseIPDB API key | No |
| `SHODAN_API_KEY` | Shodan API key | No |
| `NVD_API_KEY` | NIST NVD key — raises the rate limit from 5 to 50 req/30s | No |
| `YARAIFY_API_KEY` | abuse.ch Auth-Key for YARAify; falls back to `MALWAREBAZAAR_API_KEY` | No |
| `CVEDETAILS_ACCESS_TOKEN` | CVE Details subscription token; the enricher is skipped without it | No |
| `GEOIP_DB_PATH` | Path to MaxMind GeoLite2 DB | No |

Most feed and enrichment API keys are optional. **Nine feeds need no key at all.**
URLhaus, ThreatFox and MalwareBazaar all read keyless CSV exports; an abuse.ch
Auth-Key is additive, widening which IOC types they contribute (see the feed table).
The platform works with 9 fully keyless feeds
(URLhaus, ThreatFox, MalwareBazaar, Feodo Tracker, Blocklist.de, Emerging Threats,
CISA KEV, eCrimeLabs Metasploit, MISP CERT-FR) plus keyless GeoIP/WHOIS/DNS/NVD
enrichment.

## API Documentation

FastAPI auto-generates interactive API documentation:

- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc

### Key Endpoints

```
GET    /api/v1/iocs                    # List IOCs (paginated)
GET    /api/v1/iocs/:id                # IOC detail with enrichment
POST   /api/v1/iocs/search             # Advanced search
POST   /api/v1/iocs/bulk               # Bulk IOC lookup
POST   /api/v1/iocs/export             # Export (STIX/CSV/JSON)
GET    /api/v1/feeds                   # List feeds
POST   /api/v1/feeds/:id/sync          # Trigger feed sync
GET    /api/v1/dashboard/stats         # Dashboard statistics
GET    /api/v1/attack/matrix           # ATT&CK matrix
GET    /api/v1/attack/heatmap          # ATT&CK heatmap
POST   /api/v1/reports/generate        # Generate report
GET    /api/v1/reports/daily-brief     # Daily threat brief
```

## Threat Feeds

| Feed | Type | Free | IOC Types |
|------|------|------|-----------|
| URLhaus | CSV | Partial — keyless CSV works; Auth-Key adds hash + domain exports | URL (keyless), + Hash, Domain (keyed) |
| ThreatFox | API + CSV | Partial — keyless CSV exports work; the JSON query API is 401 without a key | IP, Domain, URL, Hash |
| MalwareBazaar | CSV | Yes (no key) — keyless `bazaar.abuse.ch` export; Auth-Key adds the query API + certificate blocklist | Hash |
| Feodo Tracker | CSV | Yes (no key) | IP |
| Blocklist.de | CSV | Yes (no key) | IP |
| Emerging Threats | CSV | Yes (no key) | IP |
| CISA KEV | API | Yes (no key) | CVE |
| eCrimeLabs Metasploit | CSV | Yes (no key) | CVE |
| MISP CERT-FR | CSV | Yes (no key) | Hash (MD5) |
| AlienVault OTX | API | Yes (API key) | IP, Domain, Hash, URL |
| AbuseIPDB | API | Yes (API key) | IP |

**abuse.ch auth, verified live 2026-07-30.** abuse.ch requires an Auth-Key on its JSON
query APIs, but its CSV/download exports remain open. Tested per endpoint rather than
taken from the docs page:

| Endpoint | Used by | Unauthenticated result |
|---|---|---|
| `urlhaus.abuse.ch/downloads/csv_recent/` | URLhaus | **200**, 3.0 MB |
| `urlhaus.abuse.ch/downloads/csv_online/` | URLhaus | **200**, 3.9 MB |
| `urlhaus-api.abuse.ch/v2/files/exports/{KEY}/…` | URLhaus (keyed only) | 404 without the key segment |
| `threatfox.abuse.ch/export/csv/recent/` | ThreatFox | **200**, 1.4 MB |
| `threatfox.abuse.ch/export/csv/{sha256,md5,urls,ip-port}/recent/` | ThreatFox | **200** |
| `threatfox.abuse.ch/downloads/hostfile/` | ThreatFox | **200**, 1.7 MB |
| `threatfox-api.abuse.ch/api/v1/` (POST `get_iocs`) | ThreatFox | **401** `{"error":"Unauthorized"}` |
| `mb-api.abuse.ch/api/v1/` (POST `get_info`/`get_recent`) | MalwareBazaar feed + enricher | **401** `{"error":"Unauthorized"}` |
| `mb-api.abuse.ch/v2/files/exports/{KEY}/…` | MalwareBazaar (keyed only) | 404 without the key segment |

So all three **feeds** degrade rather than fail without a key. MalwareBazaar was the
exception until 2026-07-30, when its connector was switched to the keyless export at
`bazaar.abuse.ch/export/csv/recent/` — measured at 881 samples across a 47.78-hour
window, which is why its sync frequency is 1 hour (samples cannot slip between syncs
until the interval exceeds ~24 hours, half the window).

The MalwareBazaar **enricher** remains credential-gated, and that asymmetry is
deliberate: a bulk export cannot answer "tell me about this specific hash", and no
keyless endpoint serves arbitrary hash lookups. Without an abuse.ch key, hash
enrichment loses MalwareBazaar and YARAify.

**One key covers all three services.** An abuse.ch account Auth-Key from
<https://auth.abuse.ch/> works for URLhaus, ThreatFox, MalwareBazaar and YARAify. The code
reads *separate* config names (`URLHAUS_API_KEY`, `THREATFOX_API_KEY`,
`MALWAREBAZAAR_API_KEY`), so the same value goes in each; `YARAIFY_API_KEY` is the one that
falls back to `MALWAREBAZAAR_API_KEY` automatically.

**ThreatFox expires IOCs older than six months** (policy change 2025-05-01). Expired
indicators are absent from both the API and the CSV export, so a re-sync stops observing
them — `sighting_count` plateaus and `last_seen` stops advancing rather than the IOC being
deleted. Relevant to any sync-cadence design.

**Licensing.** The abuse.ch community API is free under fair-use principles; commercial or
for-profit use may require a paid subscription. This sits alongside the Vercel Hobby
non-commercial restriction — both bear on the same future commercialisation decision.

Feed slugs are registered in
`backend/app/services/feed_scheduler.py::FEED_CONNECTORS` and seeded by
`scripts/seed_feeds.py` — a feed row whose slug is absent from that map cannot sync.

## Enrichment Sources

| Source | Applies to | Key required |
|--------|-----------|--------------|
| GeoIP (MaxMind GeoLite2) | IP | No (local DB) |
| WHOIS | IP, Domain, URL, Email | No |
| DNS (forward + reverse) | IP, Domain, URL | No |
| Reputation (AbuseIPDB / OTX) | IP, Domain, URL, Hash | Per provider |
| Shodan | IP | Yes |
| MalwareBazaar | Hash | **Yes (abuse.ch)** — API is 401 without it, so the enricher is gated |
| NVD (CVSS, CWE, CPE, KEV flag) | CVE | Optional (raises rate limit) |
| CVE Details (multi-source CVSS, exploits) | CVE | Yes (paid) |
| YARAify (YARA/ClamAV, imphash, families) | Hash (SHA256 only) | Yes (abuse.ch) |

The last three are class-based enrichers registered in `backend/app/enrichers/__init__.py`;
an enricher whose credentials are missing is simply not registered.

## Scoring Algorithm

Wiestell calculates a composite threat score (0-100) using weighted factors:

```
Score = Base Reputation (30%) + Source Diversity (20%) + Recency (15%)
      + Sighting Frequency (15%) + Enrichment Risk (10%) + Context (10%)
```

| Score Range | Category | Color |
|-------------|----------|-------|
| 76-100 | Critical | Red |
| 51-75 | High | Orange |
| 26-50 | Medium | Yellow |
| 0-25 | Low | Green |

## Development

```bash
# Backend development
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000

# Frontend development
cd frontend
npm install
npm run dev
```

