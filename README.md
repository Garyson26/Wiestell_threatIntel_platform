<p align="center">
  <img src=".github/assets/banner.svg" alt="Wiestell — open-source threat intelligence platform" width="100%">
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg" alt="License: Apache 2.0"></a>
  <img src="https://img.shields.io/badge/Python-3.11+-3776AB?logo=python&logoColor=white" alt="Python 3.11+">
  <img src="https://img.shields.io/badge/FastAPI-009688?logo=fastapi&logoColor=white" alt="FastAPI">
  <img src="https://img.shields.io/badge/Next.js-16-black?logo=next.js" alt="Next.js 16">
  <img src="https://img.shields.io/badge/MySQL%20%2F%20MariaDB-4479A1?logo=mariadb&logoColor=white" alt="MySQL / MariaDB">
  <a href="CONTRIBUTING.md"><img src="https://img.shields.io/badge/PRs-welcome-brightgreen.svg" alt="PRs welcome"></a>
</p>

**Wiestell** is a free, open-source Threat Intelligence Platform (TIP) for SOC analysts and threat hunters. It collects indicators of compromise (IOCs) from open threat feeds, enriches them, scores them from 0 to 100, maps them to MITRE ATT&CK, and shows the results in a SOC dashboard.

## Features

- **Feed ingestion.** 11 open-source threat feeds, 9 of which need no API key.
- **Enrichment.** WHOIS, DNS, GeoIP, reputation (AbuseIPDB / OTX), MalwareBazaar, YARAify, NVD and more.
- **Threat scoring.** A weighted 0–100 score per IOC, bucketed into Critical, High, Medium and Low.
- **MITRE ATT&CK.** Technique mapping with a matrix and heatmap view.
- **Correlation and hunting.** Related-IOC correlation and a threat-hunting workspace.
- **Reports and export.** A daily brief, custom reports, and STIX 2.1 / CSV / JSON export.
- **Role-based access.** Admin, analyst and viewer roles, with email OTP sign-in.

## Architecture

```
                 Frontend — Next.js + TypeScript
     Dashboard · IOC search · Feeds · Reports · ATT&CK map
                              │  REST
                 Backend — FastAPI (async Python)
     Feed ingestion · Enrichment · Scoring · Correlation
           │                   │                  │
    MySQL / MariaDB      Redis (optional)   External threat feeds
```

| Layer | Technology |
|-------|-----------|
| Frontend | Next.js 16 (App Router), React 19, TypeScript, Tailwind CSS, Recharts, D3.js |
| Backend | FastAPI, SQLAlchemy 2 (async), Pydantic v2, Alembic |
| Database | MySQL 8 or MariaDB 11 |
| Optional | Redis for distributed rate limiting |

## Quick start

You need Docker with Compose, and Python 3.11+ on the host to run the seed scripts.

```bash
git clone https://github.com/Garyson26/Wiestell_threatIntel_platform.git
cd Wiestell_threatIntel_platform
cp .env.example .env
```

Edit `.env` and set at least these values:

```ini
# Points the backend container at the bundled database service
DATABASE_URL=mysql+pymysql://sentinel:sentinel@db:3306/sentinel_test
# Generate with: python -c "import secrets; print(secrets.token_urlsafe(48))"
SECRET_KEY=<at least 32 random characters>
CORS_ORIGINS=http://localhost:3000
# Required for OTP sign-in emails
RESEND_API_KEY=<your Resend API key>
```

Start the stack and apply the database migrations:

```bash
docker compose up -d
docker compose exec backend alembic upgrade head
```

Seed the feed registry and the ATT&CK catalogue from the host. The bundled database listens on `127.0.0.1:3307`.

```bash
# bash / zsh
pip install -r backend/requirements.txt
export DATABASE_URL="mysql+pymysql://sentinel:sentinel@127.0.0.1:3307/sentinel_test"
export SECRET_KEY="$(python -c 'import secrets;print(secrets.token_urlsafe(48))')"
python scripts/seed_feeds.py
python scripts/seed_mitre.py
```

```powershell
# PowerShell
pip install -r backend/requirements.txt
$env:DATABASE_URL = "mysql+pymysql://sentinel:sentinel@127.0.0.1:3307/sentinel_test"
$env:SECRET_KEY = python -c "import secrets; print(secrets.token_urlsafe(48))"
python scripts/seed_feeds.py
python scripts/seed_mitre.py
```

Open the dashboard at **http://localhost:3000**.

Interactive API docs are off by default. Set `ENABLE_API_DOCS=true` in development to serve `/docs` and `/redoc`.

## Configuration

Every variable is documented in [`.env.example`](.env.example). These are the main ones:

| Variable | Purpose | Required |
|----------|---------|----------|
| `DATABASE_URL` | MySQL/MariaDB connection string (`mysql+pymysql://…`) | Yes |
| `SECRET_KEY` | JWT signing key, at least 32 random characters | Yes |
| `CORS_ORIGINS` | Comma-separated list of allowed browser origins (`*` is rejected) | Yes |
| `RESEND_API_KEY` | Sends the OTP sign-in emails | Yes, for sign-in |
| `CRON_SECRET` | Shared secret for scheduled feed syncs (`X-Cron-Secret` header) | Recommended |
| `OTX_API_KEY`, `ABUSEIPDB_API_KEY` | Turn on the OTX and AbuseIPDB feeds and their reputation lookups | No |
| `URLHAUS_API_KEY`, `THREATFOX_API_KEY`, `MALWAREBAZAAR_API_KEY` | abuse.ch Auth-Key. One key covers all three; enter the same value in each | No |
| `NVD_API_KEY`, `SHODAN_API_KEY`, `CVEDETAILS_ACCESS_TOKEN` | Extra enrichment sources | No |

## Threat feeds

| Feed | IOC types | API key |
|------|-----------|---------|
| URLhaus | URL (plus hash and domain with a key) | Optional |
| ThreatFox | IP, domain, URL, hash | Optional |
| MalwareBazaar | Hash | Optional |
| Feodo Tracker | IP | None |
| Blocklist.de | IP | None |
| Emerging Threats | IP | None |
| CISA KEV | CVE | None |
| eCrimeLabs Metasploit | CVE | None |
| MISP CERT-FR | Hash | None |
| AlienVault OTX | IP, domain, URL, hash | Required |
| AbuseIPDB | IP | Required |

Feeds are synced by calling `POST /api/v1/feeds/sync-all` on a schedule, either with an admin token or the `X-Cron-Secret` header. See [`.github/workflows/feed-sync.yml`](.github/workflows/feed-sync.yml) for an example.

> The free abuse.ch community API is offered under fair-use terms. Commercial use may need a paid subscription, so check each feed's terms before using it commercially.

## Threat scoring

Each IOC gets a composite score from 0 to 100:

```
Score = Reputation (30%) + Source diversity (20%) + Recency (15%)
      + Sighting frequency (15%) + Enrichment risk (10%) + Context (10%)
```

CVEs use their own weighting that favours enrichment and context. The score maps to a severity bucket:

| Score | Severity |
|-------|----------|
| 76–100 | Critical |
| 51–75 | High |
| 26–50 | Medium |
| 0–25 | Low |

## Development

```bash
# Backend (from backend/)
pip install -r requirements-dev.txt
alembic upgrade head
uvicorn app.main:app --reload --port 8000
python -m pytest                 # fast test suite, no database needed

# Frontend (from frontend/)
npm ci
npm run dev
npm run lint
```

[CONTRIBUTING.md](CONTRIBUTING.md) covers the full workflow, including the database-backed test tier.

## Contributing

Bug reports, feature ideas and pull requests are all welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) before you start.

**Security issues:** please do not open a public issue. Report them privately through GitHub's [**Report a vulnerability**](https://github.com/Garyson26/Wiestell_threatIntel_platform/security/advisories/new) form.

## License

Wiestell is released under the [Apache License 2.0](LICENSE).
