```
  ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗     
  ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     
  ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║     
  ╚════██║██╔══╝  ██║╚═╝ ██║   ██║   ██║██║╚═╝ ██║██╔══╝  ██║     
  ███████║███████╗██║  ╚████║   ██║   ██║██║  ╚████║███████╗███████╗
  ╚══════╝╚══════╝╚═╝   ╚═══╝   ╚═╝   ╚═╝╚═╝   ╚═══╝╚══════╝╚══════╝
```

**Open-source threat intelligence platform that aggregates, enriches, and scores IOCs from multiple feeds.**

![Next.js](https://img.shields.io/badge/Next.js-14-black?logo=next.js)
![FastAPI](https://img.shields.io/badge/FastAPI-0.109-009688?logo=fastapi)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-336791?logo=postgresql)
![Redis](https://img.shields.io/badge/Redis-7-DC382D?logo=redis)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker)
![TypeScript](https://img.shields.io/badge/TypeScript-5-3178C6?logo=typescript)
![Python](https://img.shields.io/badge/Python-3.11-3776AB?logo=python)
![License](https://img.shields.io/badge/License-MIT-green)

---

SENTINEL is a production-grade, full-stack Threat Intelligence Platform (TIP) designed for SOC analysts, threat hunters, and cybersecurity professionals. It aggregates indicators of compromise (IOCs) from 10+ open-source threat feeds, enriches them with WHOIS/DNS/GeoIP/Shodan data, calculates composite threat scores using a weighted algorithm, maps indicators to the MITRE ATT&CK framework, and presents everything through a tactical dark-themed SOC dashboard built with Next.js 14 and TypeScript.

---

## Features

| Feature | Status |
|---------|--------|
| Multi-feed IOC ingestion (10 connectors) | Implemented |
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
| Celery background task processing | Implemented |
| Docker single-command deployment | Implemented |
| Geographic threat distribution | Implemented |

## Architecture

```
                        FRONTEND (Next.js 14)
  Dashboard | IOC Search | Feed Manager | Reports | ATT&CK Map
                           |
                        REST API
                           |
                     BACKEND (FastAPI)
  Feed Ingestion | Enrichment Engine | Scoring | Correlation
        |              |            |            |
   PostgreSQL      Redis Cache    Celery     External
   + indexes       + pub/sub     Workers    Threat Feeds
```

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | Next.js 14, TypeScript, Tailwind CSS, Recharts, D3.js |
| Backend | FastAPI, Python 3.11, SQLAlchemy, Pydantic |
| Database | PostgreSQL 16 with JSONB and GIN indexes |
| Cache | Redis 7 |
| Task Queue | Celery with Redis broker |
| Containerization | Docker + Docker Compose |

## Quick Start

```bash
# Clone the repository
git clone https://github.com/dev0558/sentinel-tip.git
cd sentinel-tip

# Copy environment file
cp .env.example .env

# Start all services
docker-compose up -d

# Seed feed sources
docker-compose exec backend python /app/../scripts/seed_feeds.py

# Load MITRE ATT&CK data
docker-compose exec backend python /app/../scripts/seed_mitre.py

# Generate sample data (optional, for demo)
docker-compose exec backend python /app/../scripts/generate_sample_data.py
```

Access the application:
- **Dashboard**: http://localhost:3000
- **API Docs**: http://localhost:8000/docs
- **API ReDoc**: http://localhost:8000/redoc

## Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `DATABASE_URL` | PostgreSQL connection string | Yes |
| `REDIS_URL` | Redis connection string | Yes |
| `SECRET_KEY` | Application secret key | Yes |
| `OTX_API_KEY` | AlienVault OTX API key | No |
| `ABUSEIPDB_API_KEY` | AbuseIPDB API key | No |
| `VT_API_KEY` | VirusTotal API key | No |
| `SHODAN_API_KEY` | Shodan API key | No |
| `PHISHTANK_API_KEY` | PhishTank API key | No |
| `GEOIP_DB_PATH` | Path to MaxMind GeoLite2 DB | No |

All feed API keys are optional. The platform works with 6 free feeds (URLhaus, ThreatFox, MalwareBazaar, Feodo Tracker, Blocklist.de, Emerging Threats) that require no API keys.

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
| URLhaus | CSV | Yes (no key) | URL, Domain |
| ThreatFox | API | Yes (no key) | IP, Domain, URL, Hash |
| MalwareBazaar | API | Yes (no key) | Hash |
| Feodo Tracker | CSV | Yes (no key) | IP |
| Blocklist.de | CSV | Yes (no key) | IP |
| Emerging Threats | CSV | Yes (no key) | IP |
| AlienVault OTX | API | Yes (API key) | IP, Domain, Hash, URL |
| AbuseIPDB | API | Yes (API key) | IP |
| PhishTank | API | Yes (API key) | URL |
| VirusTotal | API | Yes (API key) | Hash, IP, Domain, URL |

## Scoring Algorithm

SENTINEL calculates a composite threat score (0-100) using weighted factors:

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
cd sentinel/backend
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000

# Frontend development
cd sentinel/frontend
npm install
npm run dev
```

## License

This project is licensed under the MIT License. 

## Authors

Built by **Bhargav Raj Dutta**, **Taha Nagdawala** & **Uphar** — Dubai, UAE

- Bhargav Raj Dutta — [GitHub](https://github.com/dev0558) | [LinkedIn](https://www.linkedin.com/in/bhargav-raj-dutta-80251a1b4/)
- Taha Nagdawala — [GitHub](https://github.com/techtrail42) | [LinkedIn](https://www.linkedin.com/in/taha-nagdawala/)
- Uphar Jaiswal — [GitHub](https://github.com/uph3r) | [LinkedIn](https://www.linkedin.com/in/uphar-jaiswal/)

---

If you find this useful, give it a star on GitHub!
