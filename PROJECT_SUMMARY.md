# Wiestell Threat Intelligence Platform — Project Summary

**Repository:** `Wiestell_threatIntel_platform` (branch `Master`)
**Reviewed:** 2026-07-28
**Scope of review:** whole codebase — 182 tracked files: FastAPI backend, Next.js frontend, Docker/nginx/Render/Vercel deployment configuration, Alembic migrations and operational scripts.

Companion document: [SECURITY_REVIEW.md](SECURITY_REVIEW.md) — findings and remediation from the security review run alongside this analysis.

---

## 1. What the product does

Wiestell ("SENTINEL" internally) is a self-hosted Threat Intelligence Platform for SOC analysts. It:

1. **Ingests** indicators of compromise (IOCs) from 11 open-source threat feeds on a schedule.
2. **Deduplicates and normalises** them into a single `iocs` table keyed on `(type, value)`.
3. **Enriches** each indicator with WHOIS, DNS, GeoIP, reputation (AbuseIPDB / OTX), Shodan and MalwareBazaar data — and, for vulnerabilities and samples, NVD, CVE Details and YARAify.
4. **Scores** it 0–100 with a weighted composite algorithm.
5. **Correlates** indicators into a relationship graph and maps them to MITRE ATT&CK techniques.
6. **Presents** everything through a dark "tactical" SOC dashboard, with search, hunting, reporting, STIX/CSV/JSON export and a Groq-backed AI assistant.

---

## 2. Architecture

```
                   Browser (Next.js 16 App Router, React 19)
                              │  bearer token in localStorage
                              │  /api/* rewritten to the backend origin
                              ▼
                    FastAPI (Python 3.11, ASGI)
   ┌──────────────┬───────────────┬──────────────┬────────────────┐
   │ Feed         │ Enrichment    │ Scoring      │ Correlation    │
   │ ingestion    │ engine        │ engine       │ engine         │
   └──────┬───────┴───────┬───────┴──────┬───────┴────────┬───────┘
          ▼               ▼              ▼                ▼
     MySQL (SQLAlchemy 2 async / aiomysql)    External feed + enrichment APIs
     Redis (optional: cache, rate limits, Celery broker)
```

**Deployment reality vs. documentation.** The README describes PostgreSQL 16 + Docker Compose. The code targets **MySQL** (`mysql+aiomysql`, `json_contains`, naive-UTC datetimes, `INSERT IGNORE`), the Postgres service in `docker-compose.yml` is commented out, and the live deployment is a Hostinger MySQL instance with the API on Render/Vercel and the frontend on Vercel. Treat MySQL as the source of truth; the README's Postgres/Redis claims are stale.

**Three execution models coexist** for background work, which is a notable source of confusion:

| Mechanism | Location | Status |
|---|---|---|
| `asyncio` scheduler loop | `backend/app/services/feed_scheduler.py` | Implemented; **not started** — `lifespan()` deliberately skips it for serverless |
| Celery worker + beat | `backend/app/tasks/` | Wired up but the whole `beat_schedule` is commented out |
| HTTP-triggered cron | `POST /api/v1/feeds/sync-all` | **The one actually in use** (Vercel Cron / external scheduler) |

---

## 3. Technology stack

| Layer | Technology |
|---|---|
| Frontend | Next.js 16.1.6 (App Router), React 19, TypeScript 5, Tailwind CSS 4, Recharts 3, D3 7, lucide-react |
| Backend | FastAPI 0.115, Python 3.11, SQLAlchemy 2 (async), Pydantic v2, structlog |
| Database | MySQL (shared host) via `aiomysql` (async) + `pymysql` (sync/Alembic) |
| Cache / queue | Redis 7 (optional — the code degrades gracefully to in-process fallbacks) |
| Auth | Email + password → email OTP → JWT (HS256) bearer token |
| AI | Groq `llama-3.3-70b-versatile` |
| Migrations | Alembic (4 revisions, head `d4e5f6a70001`) |
| Deploy | Docker Compose + nginx (local), Render (`render.yaml`), Vercel (`vercel.json`) |

---

## 4. Repository layout

```
backend/
  app/
    main.py          FastAPI app, CORS, security headers, error handling, health, cron-status
    config.py        Pydantic Settings — all secrets sourced from env, validated at startup
    database.py      Sync + async engines, pool tuning, aiomysql transport patch
    api/
      deps.py        ← NEW: JWT decode, get_current_user, require_roles, cron secret, rate limit
      __init__.py    Router registration + router-level auth dependencies
      ioc.py         IOC list/detail/search/bulk/export/lookup, tags, enrich triggers
      feeds.py       Feed CRUD, per-feed sync, unified sync-all + enrichment cron job
      enrichment.py  Per-IOC enrichment, bulk backfill with live progress stats
      dashboard.py   Aggregate stats, timeline, geo, top threats, notifications, feed health
      attack.py      MITRE ATT&CK matrix, technique detail, heatmap
      reports.py     Report list/generate/daily-brief/download
      users.py       Register, login, OTP verify, password reset, profile, user admin
      ai.py          Groq-backed IOC analysis, chat, AI report
      contact.py     Public contact form + admin inbox
    models/          9 SQLAlchemy models (ioc, enrichment, feed, ioc_source,
                     ioc_relationship, attack_technique, report, user, otp)
    schemas/         Pydantic request/response contracts
    services/        feed_ingestion, feed_scheduler, enrichment_engine, scoring_engine,
                     correlation_engine, report_generator, groq_service
    feeds/           11 feed connectors over a common BaseFeed (fetch → parse → IOC dicts),
                     plus mitre_attack.py — a loader for seed_mitre.py, NOT a connector
    enrichers/       Registry + all 9 BaseEnricher subclasses: geoip, whois, dns,
                     reputation, shodan, malwarebazaar, nvd, cvedetails, yaraify
    tests/           pytest suite (271 tests, no database required)
    tasks/           Celery app + feed/enrichment tasks
    utils/           ioc_validator, stix_converter, rate_limiter, email_service,
                     db_retry, sanitize (← NEW: secret redaction)
  alembic/versions/  4 migrations
frontend/
  src/app/           Route groups: (bare) auth pages, (protected) all-roles app,
                     (analytics) analyst workspace, public marketing pages
  src/components/    auth guards, dashboard widgets, shared UI
  src/hooks/         useDashboardData, useIOCSearch, useWebSocket
  src/lib/           api.ts (single fetch client), auth.tsx (context), types, utils, cors
nginx/, scripts/, docker-compose.yml, render.yaml
```

---

## 5. Data model

| Table | Purpose | Notes |
|---|---|---|
| `iocs` | Core indicator store | `UNIQUE(type, value)`; JSON `tags`, `metadata`, `mitre_techniques`; indexes on `threat_score`, `last_seen` |
| `enrichments` | One row per (IOC, source) | JSON payload + `expires_at` TTL used as the enrichment cache |
| `feed_sources` | Feed registry | `slug` maps to a connector class; tracks `last_sync_at/status/error`, `ioc_count` |
| `ioc_sources` | IOC ↔ feed link | Drives the "source diversity" scoring factor |
| `ioc_relationships` | Correlation graph edges | `resolves_to`, `hosts`, `associated_with`, `shares_technique` |
| `attack_techniques` | MITRE ATT&CK catalogue | Seeded by `scripts/seed_mitre.py` |
| `reports` | Generated reports | JSON `content` blob |
| `users` | Accounts | `role` ∈ {admin, analyst, viewer}, bcrypt hash, `is_active` |
| `otps` | One-time codes | Now stores a **keyed hash** plus `purpose` and `attempts` (migration `d4e5f6a70001`) |

All IDs are `CHAR(36)` UUID strings. All datetimes are stored **naive UTC** to match MySQL `DATETIME`; `to_ist_str()` converts to IST for display.

---

## 6. Key subsystems

### Feed ingestion (`services/feed_ingestion.py`)
The most carefully engineered part of the codebase. IOCs are validated, normalised and de-duplicated in memory, then written in small chunks (default 30 rows) with:
- one lock-free `SELECT` to find existing rows,
- a single `INSERT ... IGNORE` for new IOCs (races with concurrent workers resolve silently),
- a single `executemany UPDATE` for existing rows so InnoDB row locks are held for one statement instead of the whole Python loop,
- a commit per chunk, and retry with exponential back-off on lock-wait timeout (1205) and deadlock (1213).

Both async and sync variants exist (API path and Celery path).

### Enrichment (`services/enrichment_engine.py` + `app/enrichers/`)
Per IOC type, applicable sources are selected, cached non-expired rows are reused, and the remainder run **concurrently** via `asyncio.gather`. Writes happen inside a savepoint so a duplicate-key race rolls back only the enrichment, leaving the request's outer transaction usable. Blocking WHOIS runs in a thread pool. Once the pass completes, `_rescore_from_enrichment` recomputes the IOC's threat score so the enrichment-risk weight is applied to real data instead of an empty list.

All nine enrichers are `BaseEnricher` subclasses in `app/enrichers/`, registered in `__init__.py::build_registry`. `supports()` decides applicability and `cache_ttl` decides freshness, so the engine contains no per-source knowledge: it orchestrates caching, concurrency, persistence and rescoring only. Registration is gated on credentials (Shodan excepted, which reports "key not configured" to preserve prior dashboard behaviour), and registration order is the attempt order — pinned by `tests/test_enrichers.py::TestEngineDispatch`.

GeoIP's "credential" is the MaxMind `.mmdb` file, so it is gated on that file existing (2026-07-31). The file is not committed and its build-time download fails open, so its absence is common — see §8 item 14.

### Scoring (`services/scoring_engine.py`)
Weighted composite of six terms, clamped to 0–100 and bucketed as critical ≥76 / high ≥51 / medium ≥26 / low. Weights come from a **per-type profile** in `WEIGHT_PROFILES`:

| Term | `default` | `cve` |
|---|---|---|
| reputation | 0.30 | 0.30 |
| source diversity | 0.20 | 0.05 |
| recency | 0.15 | 0.10 |
| sighting frequency | 0.15 | **0.00** |
| enrichment risk | 0.10 | 0.30 |
| context | 0.10 | 0.25 |

`default` reproduces the original global weighting exactly, so non-CVE scores are unchanged by the per-type work. Profiles are validated at import to sum to 1.0.

Reputation is resolved from evidence only, in order: `metadata.reputation_scores` → the `reputation` enrichment payload's `aggregate_score` (when at least one provider answered) → for CVEs, the NVD CVSS v3.1 base score scaled to 0–100 → a neutral 30. It must never read `threat_score`; see §8.

**Enrichment risk is `assessed risk / assessed capacity`, floored.** `RISK_SIGNALS` maps `(source, signal)` to a point weight and a scorer, and only signals the enricher *declares* as assessed enter either term — never inferred from key presence, which cannot distinguish "the source said nothing" from "the source said nothing was found". Enrichers declare this via `assessed`; see `app/enrichers/base.py`. Source maxima: `nvd` 6, `malwarebazaar` 6, `cvedetails` 4, `yaraify` 4, `whois` 3, `reputation` 3, `geoip` 2, `dns` 2. Shodan has no branch by choice (§8 item 11).

The denominator is `max(assessed_points, MIN_ASSESSED_POINTS)` with the floor at 3 — additive smoothing, because every scorer returns its own full weight or zero, so a lone assessed signal would otherwise always yield 100.0. Two consequences worth knowing: the zero-evidence branch resolves **before** the floor (otherwise every never-enriched IOC reads 0.0 instead of the 20.0 neutral), and `geoip`/`dns`, whose maxima are below the floor, can never reach 100.0 as sole evidence.

### Auth (`api/users.py` + `api/deps.py`)
Password → OTP → JWT. After this review the flow enforces: purpose-bound single-use OTPs (a reset code can no longer be redeemed for a session), hashed OTP storage, attempt limits, per-IP rate limits, and server-side role checks on every endpoint.

### Frontend
`lib/api.ts` is the single HTTP client — it attaches the bearer token, normalises error messages and drops a rejected token. `lib/auth.tsx` holds the session and re-validates it against `/users/me` on load. Route groups apply guards through layouts: `(protected)` → all roles, `(analytics)` → all roles, and `AdminRoute` on the user-management and contact-inbox pages. These are **UX guards**; enforcement now lives in the API.

---

## 7. Verification performed

| Check | Result |
|---|---|
| `python -m pytest` (backend/tests) | **302 passed** in ~6s |
| `python -m compileall` — backend, scripts, migrations | pass |
| Import `app.main` and enumerate the route table | pass — 62 API routes. `len(app.routes)` is 66 **only when the interactive docs are enabled**: FastAPI mounts four extra routes — `/openapi.json`, `/docs`, `/docs/oauth2-redirect` and `/redoc`. With `ENVIRONMENT=production ENABLE_API_DOCS=false` the count is exactly 62. (An earlier revision of this table attributed the four to "Starlette internals", which was wrong; `/docs/oauth2-redirect` is the one usually forgotten when reconciling 62 against 66.) |
| Route-guard audit (every route vs. an explicit public allowlist) | **62 routes = 53 guarded + 9 public, 0 unexpectedly public** |
| `npm ci` from a clean tree | pass (previously failed with `EUSAGE`) |
| `npm audit --omit=dev` | 3 high, all pinned inside Next.js's tree — see remaining issues |
| `tsc --noEmit` | pass |
| `next build` | pass — 26 routes generated |

---

## 8. Code quality observations (non-security)

**Strengths**
- Genuinely thoughtful concurrency and MySQL lock-contention handling in the ingestion path, with the reasoning documented in comments.
- Clean pluggable abstractions: `BaseFeed` for connectors, a source map for enrichers.
- Consistent structlog event-style logging.
- Broad, non-trivial feature coverage — STIX 2.1 export, ATT&CK heatmap, correlation graph, live backfill progress.

**Issues found and fixed during this review**
- **Broken ATT&CK endpoints.** `attack.py` filtered a MySQL JSON column with the PostgreSQL-only `ARRAY.any()` operator, so `/attack/matrix`, `/attack/heatmap` and `/attack/techniques/{id}` raised on every call. `correlation_engine.py` had the same defect with `.overlap()`. Both now use `json_contains`, matching the existing pattern in `ioc.py`.
- **Dead feed registry entry.** `FEED_CONNECTORS["mitre-attack"]` pointed at a `MitreAttackFeed` class that does not exist — `app/feeds/mitre_attack.py` only exposes a `load_attack_data()` function for `seed_mitre.py`. Syncing a feed row with that slug raised `AttributeError`. Entry removed, with a comment explaining why.
- **Enrichment risk was computed and discarded.** Nothing recomputed `threat_score` after enrichment, so the model's 10% enrichment-risk weight always evaluated against an empty list. Now closed by `_rescore_from_enrichment`.
- **Scoring fed its own output back in (fixed 2026-07-29).** `_base_reputation_score` fell back to `ioc_data["threat_score"]`, a computed column that ingestion and the rescore path both pass back in. 30% of each new composite was 30% of the previous one, so a fresh CISA KEV entry walked 46 → 51 → 53 → 53, converging on a value describing its enrichment history rather than the indicator. Now a pure function of evidence, with an idempotence test.
- **The reputation term was unreachable for every IOC type (fixed 2026-07-29).** It read only `metadata.reputation_scores`, which **no feed connector or enricher ever writes** — the reputation enricher stores `aggregate_score` in the `enrichments` table instead. So IPs with live AbuseIPDB verdicts scored as though they had no reputation data at all. `_base_reputation_score` now consumes the enrichment payload.
- **Provider silence was scored as evidence of cleanliness (fixed 2026-07-29).** The first version of the fix above treated "aggregate 0, three providers checked" as confirmed-benign (0.0) and only "0, none configured" as unknown. But AbuseIPDB is IP-only, so for a URL or a hash "providers checked" could mean OTX alone — and a fresh malware URL that OTX has never indexed is the *expected* state for a new indicator. Measured cost: a fresh feed-sourced malware URL scored **26** with silent providers versus **34** with none configured, an 8-point penalty applied to the newest and most actionable indicators. 0.0 now requires positive evidence — a corroborated harmless verdict from a provider covering the type, and no `ioc_sources` row from an enabled feed, since every feed here is a malicious-indicator feed and none is an allowlist. The reputation enricher gained a per-provider `providers` record to make this decidable; old cached payloads route to unknown and expire on the 6-hour TTL. With AbuseIPDB and OTX as the only providers the 0.0 branch is now unreachable and reputation ranges 30–100 — pinned by `TestZeroReputationIsUnreachable`, which fails if a provider with a clean-assertion channel is added.
- **A failed enricher made an indicator look safer (fixed 2026-07-29).** `_enrichment_risk_score` is `risk_signals / total_signals`, and it added a source's denominator contribution unconditionally — so an errored source, or a reputation payload with `sources_checked: 0`, contributed 0 risk against a non-zero denominator and pushed the score down. Same defect as the reputation one, in the same direction. Sources now contribute to neither term unless they reached a verdict. A *negative* verdict still counts: CVE Details reporting no public exploit is real evidence of lower risk, and dropping it would score an unchecked CVE identically to one confirmed clean.
- **Malformed feed metadata aborted ingest chunks (fixed 2026-07-29).** `reputation_scores` was dereferenced assuming a mapping of numbers; a list raised `AttributeError` and a `None`/`str`/`dict` value raised `TypeError`. Feed metadata is untrusted third-party input and scoring runs inside ingestion, so it now coerces and skips unusable entries.
- **"Source diversity" measured sighting volume, not diversity (fixed 2026-07-29).** Ingestion passed `source_count=max(new_sighting, 1)`, so a single feed re-publishing its catalogue five times scored as "5+ independent sources" (100.0). Diversity and sighting frequency — 35% of the composite between them — were two views of the same number. Both ingestion paths and the rescore path now count distinct `ioc_sources.feed_id` values.
- **Dead code in `_source_diversity_score`.** `ratio` was computed and never used, so `total_feeds` had no effect on any score (verified across 1/10/13/500). Parameter removed rather than silently made proportional, which would have moved every stored score.
- **Newly added connectors did not match the framework contract.** The three new feed connectors annotated `parse()` as returning `list[IOCCreate]` while returning `_make_ioc()` dicts, and set `source_url` instead of the `slug`/`feed_type`/`url` attributes the registry, scheduler and seed script read. Corrected, and the three new class-based enrichers relied on `supports()`/`cache_ttl` members that `BaseEnricher` did not declare — now part of the documented base contract.
- Debug `console.log` calls printed full API responses (including tokens and indicator data) into the browser console.
- `print()`-based logging in the email service, including OTP codes.
- Junk text committed into `README.md` and `render.yaml`.

**Issues remaining (recommended, not blocking)**
1. **Three competing schedulers** (asyncio loop, Celery beat, HTTP cron) with two of them dead code. Delete or clearly quarantine the unused paths.
2. **`postcss` and `sharp` advisories persist** — both are pinned inside Next.js's own dependency tree, so npm's only offered "fix" is downgrading Next to v9 (rejected). They resolve when Next ships updated transitives. Exposure is limited: postcss runs at build time, and `sharp`/libvips only processes images passing through `next/image` (currently a local logo and favicon).
3. **`iocs.manual_score_override` is not yet a column.** `calculate_threat_score` checks for it and returns it directly when present, so an analyst-set score can win outright — but the migration needs owner sign-off and does not ship with the scoring work. Until the column exists the hook is inert. This replaces the previous mechanism, which read back the computed `threat_score` field and so could not tell a human override from the engine's own last output. **Run-order note:** `scripts/rescore_corpus.py` recomputes unconditionally, so it probes `information_schema` for the column and adds `WHERE manual_score_override IS NULL` when it exists. Run the rescore *before* any override values are set, or those rows are simply skipped.
4. **Duplicated endpoint logic.** IOC detail assembly is copy-pasted across `lookup_ioc`, `get_ioc` and `search_iocs`; enrichment triggering is duplicated in `ioc.py` and `enrichment.py`. Extract shared helpers.
5. **N+1 queries.** `attack.py` issues one `COUNT` per technique (hundreds of round-trips); `dashboard.py:get_trends` issues 2 queries per day requested (up to 180). Both should be single `GROUP BY` queries.
6. **`enrichment.py` module-level mutable state** (`_backfill_running`, `_backfill_stats`) is per-process, so progress reporting is wrong behind multiple workers and the "only one backfill at a time" guarantee does not hold.
7. **Client-side analyst history** in `lib/userActivity.ts` lives in one shared `localStorage` key. It is now cleared on logout, but it belongs on the server if it is meant to be durable.
8. **`ioc_validator.py`** has an unreachable duplicate `return` (line 141) and an IPv6 regex that rejects compressed (`::`) forms; type detection falls through to `ipaddress`, so the effect is limited to the unused regex.
9. **`cvedetails_enricher._extract` defaults a missing field to a negative verdict.** `entry.get("exploitAvailable", False)` turns "the API did not return this field" into "no public exploit exists". The scoring engine now distinguishes verdicts from non-verdicts, but it cannot see through this: the payload has already collapsed the two. Same silence-as-evidence pattern, one layer lower. Fixing it needs a live CVE Details subscription to confirm what the API actually omits and when, which this deployment does not have.
0. **BLOCKER — there is no working way to create a fresh database.** Both schema-creation paths fail on MySQL 8 with `(1170, "BLOB/TEXT column 'value' used in key specification without a key length")`:
   - `alembic upgrade head` — the documented first-run command in this file, `CLAUDE.md` and `README.md`;
   - `Base.metadata.create_all()` — which `scripts/seed_feeds.py` calls on every run.

   Cause: `iocs.value` is `Text` and the table carries `UniqueConstraint("type", "value")`. MySQL and MariaDB both refuse to index a TEXT column without a prefix length. Found 2026-07-30 while standing up the local Docker harness; the container had never been started before, which is why this went unseen.

   It follows that **production's schema was not built by either documented path** — it must have been created manually, or predates `value` becoming `Text`. Resolving this needs `SHOW CREATE TABLE iocs;` against the Hostinger instance before anything is changed, because the fix depends on what is actually there. Options, once known:
   - `value` → `String(700)` with the constraint unchanged — simplest, but caps indicator length (long URLs exist);
   - keep `Text` and replace the constraint with `Index(..., unique=True, mysql_length={"value": 700})` — preserves the column type, but uniqueness becomes prefix-based, so two URLs sharing a 700-character prefix would collide;
   - a generated hash column with a unique index on it — exact uniqueness, more moving parts.

   **Full write-up, including the rejected options and the two blocking queries: [docs/superpowers/specs/2026-07-30-migration-chain-repair-design.md](docs/superpowers/specs/2026-07-30-migration-chain-repair-design.md).** Summary of the decision recorded there: the prefix-index option is **rejected as a live data-loss bug** — `feed_ingestion` dedupes via `INSERT ... IGNORE` against this constraint, so two distinct URLs sharing a 255-character prefix silently collide and the second is dropped, which for a URLhaus corpus is routine rather than exotic. `VARCHAR(n)` is rejected because InnoDB's 3072-byte key cap leaves only ~740 utf8mb4 characters and malware URLs exceed it. The adopted fix is a stored generated column, `value_sha256 CHAR(64) GENERATED ALWAYS AS (SHA2(value, 256)) STORED`, with the constraint on `(type, value_sha256)`: exact uniqueness on an unbounded value, 64 bytes of index, `INSERT ... IGNORE` unchanged.

   `tests/conftest_mysql.py` applies a **test-only** prefix-length adaptation so the `-m mysql` tier can run at all; it is labelled as a scaffold and must be deleted once the model is fixed.

0a. **FIXED 2026-07-30 — but read this before briefing UAT: the dashboard has been under-reporting threat levels.** This was not a latent defect; it was the live state of the product.

    The ingest re-read path recomputed and persisted `threat_score` **without passing `enrichment_data`** ([feed_ingestion.py:256](backend/app/services/feed_ingestion.py#L256) async, `:480` sync). Two terms collapsed, not one: `_enrichment_risk_score([])` fell to its 20.0 floor, and `_base_reputation_score` lost both the reputation payload *and* — for CVEs — the NVD CVSS score, because `_reputation_from_cvss` reads the same list. Measured on realistic fully-enriched payloads:

    | Case | enriched | after one re-read | band |
    |---|---|---|---|
    | IP — flagged reputation + geo RU + fast flux | 76 | 53 | critical → high |
    | URL — flagged reputation | 64 | 41 | high → medium |
    | **CVE — KEV 9.8 + public exploit** | 83 | **39** | **critical → medium** |
    | HASH — YARAify hit | 44 | 36 | medium → medium |

    The CVE case is worst because the `cve` profile draws 60% of its composite (30% reputation via CVSS + 30% enrichment risk) from `enrichment_data`. **An actively-exploited KEV CVE read as `medium` within six hours of ingest.**

    And the enriched value was not restored: the cron's enrichment selection is `WHERE Enrichment.id IS NULL`, so an IOC enriched even once is never re-enriched and `_rescore_from_enrichment` never fires for it again. Roughly **62,000 score-destructions per day** for URLhaus alone (15,524 rows × 4 syncs) against **≤100 one-shot restorations** per cron run — two orders of magnitude apart, and the restoration is not repeatable.

    Fixed by fetching each chunk's enrichment rows in one grouped query and passing them to the re-scoring call, for only the rows the re-read gate lets through.

    **The repair is partial and permanently so, which matters for how the rescore is reported.** The fix corrects what *future* re-reads write, so it only ever repairs rows still inside a rolling window. A URLhaus URL that has aged out past the measured 30.5-day window is never re-read again and keeps its corrupted score **indefinitely** — no amount of syncing clears it. Same for any IOC whose feed has stopped carrying it.

    So `scripts/rescore_corpus.py` is the **only** path that repairs the aged-out population, and the corpus will hold a permanent mix of three states until it runs: recently re-read and correct, aged-out and corrupted, and never-enriched. A naive before/after distribution table would attribute the whole difference to the scoring-model changes. Report the distribution at three points — now, after the fix has had a full sync cycle, and after the model changes — so the repair and the model are separable.

0c. **`ingest_iocs_sync` is dead code in production — recommend deleting it.** Its only caller is `app/tasks/feed_tasks.py:119`, reachable solely through Celery, whose `beat_schedule` in `celery_app.py` is entirely commented out and which neither `render.yaml` nor `vercel.json` starts. The live path is `POST /api/v1/feeds/sync-all` → `feed_scheduler.run_feed_sync` → the **async** `ingest_iocs`.

    It is not merely unused, it is actively costly: `_ingest_chunk` and `_ingest_chunk_sync` are two near-identical copies of the most intricate code in the repo, and they have drifted twice inside a single change set — a Section 0.5 unbound `enrichment_map` and a Section 3 `new_ioc_rows` NameError, both in the sync half, both invisible to `compileall`. Every future scoring or ingestion change has to be made twice and reviewed twice.

    Deleting it means removing `ingest_iocs_sync`, `_ingest_chunk_sync`, `_process_sync_chunk_with_retry`, `_distinct_feed_counts_sync`, `_already_linked_sync` and `_enrichments_for_sync`, plus the Celery feed task that calls them, and repointing `tests/test_ingest_write_volume.py` at the async path. Roughly 250 lines. Not done here because it is unrelated to scoring and deserves its own reviewed pass.

0d. **FIXED 2026-07-31 — the sighting-count inflation was untouched on 60% of records.** Section 3's re-read gate keys on the source's own timestamp advancing. Five connectors supply no per-record timestamps at all and are full-list exports — the whole list republished every sync:

    | Feed | type | records/sync |
    |---|---|---|
    | blocklist.de `all.txt` | ip | **23,112** |
    | eCrimeLabs Metasploit | cve | 3,195 |
    | MISP CERT-FR | hash | 2,277 |
    | CISA KEV | cve | 1,656 |
    | Emerging Threats | ip | 586 |
    | **total** | | **30,826** |

    Against 20,653 from the timestamped feeds — **59.9% of per-sync record volume**. Because `_make_ioc` defaults an absent timestamp to `now()`, these were indistinguishable downstream from genuinely fresh observations, so the gate could not fire and `sighting_count` incremented on every sync. At four syncs a day `_sighting_frequency_score` saturates at its 100.0 ceiling within about a day, pinning 15% of the composite at maximum across most of the corpus — the exact pathology the gate exists to remove.

    Fixed by `BaseFeed.full_list_kind`, an opt-in declaration alongside `rolling_window` — a connector knows what its own feed is even when the records do not say. **Two kinds, and the distinction matters more than the fact of being a full list:**

    | Kind | Feeds | `last_seen` | counter |
    |---|---|---|---|
    | `current-state` — list expires entries | blocklist.de, Emerging Threats | **advances** (presence re-asserts liveness) | frozen |
    | `cumulative` — list only grows | CISA KEV, eCrimeLabs, MISP CERT-FR | **frozen** | frozen |

    A cumulative catalogue still listing CVE-2021-44228 is not evidence it was observed today. Advancing `last_seen` for those would pin `_recency_score` at its 100.0 ceiling permanently — every KEV CVE would hold its day-0 score forever, undoing the monotone-non-increasing trajectory the `cve` weight profile depends on. It would also be the *third* count of one signal, alongside `_enrichment_risk_score`'s `nvd_in_kev` branch and the `cisa-kev` context tag. MISP CERT-FR was verified rather than assumed: its MISP manifest holds 18 events spanning 2020–2024 and the hashes CSV has no date column.

    Tests assert every timestamp-free connector declares **which** kind (not merely that it is a full list), that declared values are valid, and that recency still decays for a cumulative entry.

    **Write volume, corrected.** I first reported 30,826 × 4 = ~123,300 writes/day. That assumed every feed syncs every window; against Phase 4's real cadence and with cumulative catalogues now correctly frozen it is **23,698 writes/day — 19% of that figure** — and concentrated in one daily blocklist.de sync. So this does not bear on the spin-down blocker after all; the *read* volume (108,686 rows/day) does.

0e. **FIXED 2026-07-31 — the re-read gate was non-deterministic.** MySQL `DATETIME` with no fractional-seconds precision **rounds** what it is given: a source timestamp of `…:43.837451` is stored as `…:44`. The gate compared the unrounded source value against the rounded stored one, so whether it fired depended on the microsecond fraction — roughly 50/50, with no error either way, and a write-suppression predicate behaving that way would have been very hard to diagnose from production symptoms.

    Fixed by normalising **on write**, at both producers (`_now` and `_strip_tz`), so stored, written and compared values are identical by construction and MySQL never rounds anything. Truncation rather than rounding, deliberately: a normalised value is never *later* than the instant it represents, so "has the source advanced" cannot answer yes spuriously. A test sweeps eight microsecond fractions either side of the .5 boundary and asserts none produces a write on an unchanged re-read.

0b. **BLOCKER FOR THE RESCORE — `sighting_count` and `last_seen` count re-reads, not observations.** Both are written unconditionally in the existing-row branch of the ingest chunk ([feed_ingestion.py:241-276](backend/app/services/feed_ingestion.py#L241)): `sighting_count + 1`, and `last_seen = _now()` (ingest time). Neither consults the source-reported timestamp — and the **new-row** path at :294 *does* honour it, so the same indicator is dated one way when new and another when re-read.

    Scale comes from the measured windows: URLhaus `csv_recent` is 30.5 days holding 15,524 URLs, so each is re-read ~122 times; ThreatFox's exports span 176.5 days, ~706 re-reads. Two distinct failures, 30% of the default composite between them:
    - **sighting frequency (15%) inverts.** Measured for a URLhaus URL on identical evidence: day 0 → **36**, day 7 → 46, day 25 → **50**. A three-week-old URL scores 14 points above a brand-new one purely from time spent sitting in a file. Same shape as the CVE urgency inversion.
    - **recency (15%) goes dead.** `last_seen = _now()` means `_recency_score` returns 100.0 for every re-read row regardless of true age; it only discriminates once a feed *stops* republishing.

    Fix: gate both on the source timestamp advancing. **Must land before `scripts/rescore_corpus.py` runs** — the rescore reads these fields straight from the row, so running it first bakes the inflation into `threat_score`, and because the rescore is idempotent, re-running would not undo it. Repairing existing values is not mechanical (the true count is unrecoverable) and needs owner sign-off. Full analysis, including the InnoDB write-volume benefit: [docs/superpowers/specs/2026-07-30-sighting-count-and-recency-design.md](docs/superpowers/specs/2026-07-30-sighting-count-and-recency-design.md).

12. **Feed cadence drifts by one cron period when `sync_frequency` is a multiple of the cron interval.** `last_sync_at` is stamped at ingest *completion*, so smart mode's `(now - last) >= freq` check falls short by the sync's own duration and skips the intended firing. Measured on a 6-hour cron with a 10-minute sync: a 12h feed runs every 18h, a 24h feed every 30h, a 72h feed every 78h. The penalty is a fixed one period, not accumulating. The fix is to stamp the attempt's *start* time, and it must land in Spec 2 Phase 4 — whose §4.3 currently specifies `next_due_at = now() + interval` after each attempt and so reproduces the defect exactly. Interim workaround for MalwareBazaar only: keep `sync_frequency` strictly below the cron interval so every firing syncs. Full analysis and the Phase 4 column reconciliation: [docs/superpowers/specs/2026-07-30-phase4-scheduling-design-notes.md](docs/superpowers/specs/2026-07-30-phase4-scheduling-design-notes.md).
13. **`feed_sources.config` is written but never read.** `api/feeds.py:52` sets it on create; nothing consumes it. Dead JSON column. Relevant because it looks like a free home for machine-managed state such as `sync_cursor` — but `FeedUpdate` replaces it wholesale, so an operator editing config through the API would wipe that state silently. This is why the rolling-window watermark got a dedicated column.

16. **THE RESCORE IS A UAT BLOCKER, NOT HOUSEKEEPING.** `scripts/rescore_corpus.py` has never been run. Every scoring change since 2026-07-28 alters how a score is *computed* and none of them touch what is *stored*, because nothing re-scores an existing row: ingestion skips rows whose evidence has not changed, and the enrichment cron selects only never-enriched IOCs.

    `SCORING_MODEL_VERSION` is now **8**. Stored `threat_score` values were written under version 1 — or under whichever intermediate version happened to be live when a row was last touched — so **the corpus holds scores produced by at least four superseded models, and the dashboard ranks them against each other.** "Top threats", the critical-count tile, the ≥76 filter and every sort by `threat_score` are comparing numbers computed under different rules. That is not a stale-data inconvenience; it makes the primary triage surface unsound, and it cannot be demonstrated to a UAT audience as-is.

    What changed between versions, so the scale of the discrepancy is on the record:

    | Version | Effect on an unchanged indicator |
    |---|---|
    | 1 → 2 | reputation stopped reading back `threat_score`; a KEV CVE had been walking 46 → 51 → 53 to a fixed point describing its own history |
    | 2 → 3 | `sighting_count` and `last_seen` stopped counting re-reads; `enrichment_data` reached the re-read path (−44 on KEV CVEs before the fix) |
    | 3 → 4 | per-signal `assessed`: KEV-without-CVSS +15 composite, medium → high |
    | 4 → 5 | `MIN_ASSESSED_POINTS`: thin-evidence payloads smoothed; geoip-only and dns-only capped at 200/3 |
    | 5 → 6 | MalwareBazaar scored at all for the first time |
    | 6 → 7 | hash reputation reads family attribution: 44 → 62 at one feed, medium → high |
    | 7 → 8 | provider aggregation max not mean: a maximally-rated IP recovers 45 → 58, medium → high |

    **One rescore covers all of them** — the script recomputes unconditionally rather than diffing versions — so this is one action, not seven. But it is sequenced behind two things: the `iocs.scoring_model_version` column (blocked on the migration-chain repair) is what lets the script target stale rows rather than the whole table, and the run must happen **before** any `manual_score_override` values are set, or those rows are skipped permanently.

    **One caveat that a rescore alone does not fix.** The script recomputes from *stored* enrichment payloads, so anything baked into a stored field stays. `aggregate_score` was such a case — hence `_strongest_provider_score` recomputing the max from `details` so the version-8 fix does reach existing rows. Any future change to a stored enrichment field needs the same treatment or it will not land until the freeze trap (`WHERE Enrichment.id IS NULL`) is fixed and a full refresh cycle has run.

15. **LIVE, found 2026-07-31 — one OTX pulse scores an indicator *lower* than no OTX pulse at all.** The reputation enricher maps OTX to `min(pulse_count * 10, 100)`, so a single pulse yields `aggregate_score = 10` and two yield 20 — both **below `NEUTRAL_REPUTATION = 30`**, the value used when there is no reputation evidence whatsoever. Measured identically across `domain`, `ip`, `url` and `hash`:

    | OTX pulses | reputation | composite | bucket |
    |---|---|---|---|
    | 0 (silent) | 30.0 | 36 | medium |
    | 1 | **10.0** | **28** | medium |
    | 2 | **20.0** | **32** | medium |
    | 3 | 30.0 | 34 | medium |

    So an indicator that OTX has written up once reads 8 composite points *safer* than one OTX has never mentioned, and parity is only reached at three pulses. **Adding evidence of maliciousness lowers the score.** This is the same inversion class as the four already fixed, but located in the reputation term's *magnitude* rather than in its assessed/not-assessed decision — which is why the evidence-model work did not catch it: the verdict logic is correct, `malicious` with `corroboration: 1` is a genuine positive verdict, and it is the scale that is wrong.

    It is not hash-specific and it is not new — it predates all of the Spec 3–5 work. Surfaced by the hash design question, because a thin OTX verdict wins the reputation resolution order ahead of any other evidence.

    **Not fixed: this is reputation calibration and needs sign-off** (Spec 5 §6, alongside the hash proposal and the `MIN_ASSESSED_POINTS = 3` revisit). Owner direction 2026-07-31: **rescale rather than floor.** Flooring at `NEUTRAL_REPUTATION` fixes the inversion but flattens 1, 2 and 3 pulses to one value; rescaling fixes it and keeps pulse count monotonic. Shape: `NEUTRAL + min(pulse_count * k, 100 - NEUTRAL)`, with `k` set from the observed pulse-count distribution rather than picked.

    **`k` wants data, with a pre-committed fallback so it cannot block.** The query is `JSON_EXTRACT(data, '$.details.otx.pulse_count')` over `enrichments` where `source = 'reputation'`. But the sample may well be too thin to calibrate anything: enrichment has only ever selected never-enriched IOCs at ≤100 per run against a corpus of tens of thousands, and the OTX-with-a-pulse subset is a slice of that slice.

    **Decided in advance, 2026-07-31, so the section does not stall on a thin query:**

    - **Trust threshold: 200 rows with `pulse_count >= 1`.** Below that, stop treating the sample as a distribution. Rationale: `k` only has to place the 1–2 pulse case sensibly, so what is needed is a usable estimate of the low quantiles; a few dozen rows all clustered at 1–2 tell you the mode and nothing about the spread, which is precisely the shape that invites over-fitting to noise.
    - **Fallback `k = 20`**, from a stated judgement rather than from the data: **five pulses should read as certainly malicious.** Five independent write-ups is a well-documented indicator, and `NEUTRAL + min(pulses * 20, 70)` puts 1 pulse at 50, 2 at 70, 3 at 90 and 5+ at the 100 ceiling — so a single pulse sits meaningfully above the 30.0 neutral without being treated as conclusive, and monotonicity holds across the range that actually occurs. Anchored the same way `MIN_ASSESSED_POINTS = 3` was: a judgement stated as a judgement, with the reasoning recorded so it can be argued with rather than reverse-engineered.
    - Either way, **record which path was taken** in the version-history entry, so a later reader knows whether `k` is measured or asserted.

    **Blast radius is larger than anything in Sections 1–2** — it moves reputation for *every* OTX-flagged indicator across all four types, at a 30% weight, so it must be measured before sign-off rather than argued.

    **Aggregation FIXED 2026-07-31 (§6b): the aggregator is now max, not mean.** A mean over providers that each reached a *positive* verdict answers the wrong question — nobody is arguing the indicator is clean, so it only measured how loudly they agreed, and it dragged the strongest verdict toward the weakest. The maximally-rated IP below recovers from 45 (medium) to **58 (high)**. Max and mean are identical whenever only one provider is positive, which is the common case, so only the both-positive-and-disagreeing case moved. `SCORING_MODEL_VERSION` 8.

    Two consequences worth carrying:

    - **Rescaling would NOT have fixed this.** Measured with both providers rescaled to a comparable 30–100 scale at k=20, AbuseIPDB 100 with one OTX pulse still gave mean 75 → composite 50 (medium) against 100 → 58 (high) alone — still a lost bucket. The mean was an independent cause and the scale mismatch merely amplified it. An earlier note here claimed the rescale fixed both; it did not.
    - **`aggregate_score` is a *stored* field**, and enrichment rows are never refreshed, so changing the enricher alone would have left every existing row holding a mean permanently — a rescore would faithfully reuse it. `scoring_engine._strongest_provider_score` therefore recomputes the max from `details`, which is in the same stored JSON, so the fix reaches the existing corpus on rescore. It is one-sided and can only raise a stored value. Any future change to a stored enrichment field needs the same treatment; see item 16.

    **Provider corroboration is now measured nowhere in the composite, and that is an honest zero rather than a fix.** `source_count` counts distinct `ioc_sources.feed_id` — *feeds* that reported the indicator — and AbuseIPDB and OTX are enrichment providers, not feeds, so they never reach the diversity term. `sources_flagged` is written into the payload and read by nothing. Under max, two agreeing providers score exactly like one. Previously the gap was filled by an averaging artefact pointing the *wrong* way, so agreement lowered the score; an explicit zero is better than that. **§6 candidate, not built:** if agreement should count it wants to be a declared signal — `multi_provider_agreement` in `RISK_SIGNALS` reading `sources_flagged >= 2` — rather than an emergent property of the aggregator. Pinned by `TestProviderAggregation::test_provider_corroboration_is_measured_nowhere`, which fails if such a signal appears without this note being updated.

    **Max raises single-provider false-positive sensitivity**, but only in the both-positive case, since mean and max are identical when one provider is silent. OTX pulses are user-contributed, so OTX is the FP vector: a single mistaken pulse can no longer be averaged down by AbuseIPDB. Bounded — one provider's error moves the reputation term, not the bucket, unless the indicator is already near a threshold — and accepted as the cost of not letting corroboration lower a score.

    **The original question, for the record.** It was whether `aggregate_score` averaged a silent provider in as a zero.

    *Silence: already correct.* `scores.append(...)` executes only inside the `> 0` branches, so a silent or unconfigured provider contributes **nothing** to the list rather than a zero. AbuseIPDB at 100 with OTX silent reads **100**, not 50. Non-issue, and now pinned by a test so it cannot regress into a mean-over-all-providers.

    *Weak positives: a real dilution, same family, one level up.* The mean is taken over **incommensurable scales**. AbuseIPDB reports a calibrated 0–100 confidence; OTX reports `pulse_count * 10`. Averaging them means a single OTX pulse drags a maximal AbuseIPDB verdict down hard:

    | AbuseIPDB | OTX | aggregate | reputation | composite | bucket |
    |---|---|---|---|---|---|
    | 100 | not configured | 100 | 100.0 | 66 | high |
    | 100 | silent | 100 | 100.0 | 66 | high |
    | 100 | **1 pulse** | **55** | 55.0 | **45** | **medium** |
    | 100 | 2 pulses | 60 | 60.0 | 47 | medium |
    | 100 | 7 pulses | 85 | 85.0 | 61 | high |
    | 100 | 10 pulses | 100 | 100.0 | 66 | high |

    So an IP that AbuseIPDB rates 100/100 **loses a bucket** — high to medium, −21 composite — because OTX also flagged it once. Corroborating evidence lowers the score. This lands on IPs, the largest population, and it is a consequence of the same pulse-count scale as item 15's inversion, so **rescaling OTX fixes both** — which is the strongest argument for rescale over floor. Whether the mean should also be weighted by provider confidence is a separate §6 question; fixing the scale first may make it unnecessary.

14. **The GeoIP database is fetched by a build step that fails open, and nothing surfaces its absence.** `render.yaml:18` and `backend/render-build.sh:11` both run `python download_geolite2.py || echo "⚠️ GeoLite2 download failed - continuing anyway"`, and that script requires `MAXMIND_ACCOUNT_ID` and `MAXMIND_LICENSE_KEY`. The `.mmdb` is not committed. So a deploy without those credentials starts normally and **loses country and ASN enrichment for the entire IP population**, with no error, no failed health check and no dashboard indication — only a per-IOC `{"error_city": "GeoIP city database not available"}` row buried in the `enrichments` table.

    **Partly fixed 2026-07-31:** the enricher is now credential-gated on the file existing (`app/enrichers/__init__.py::_geoip_database_available`), under the existing rule that an unconfigured source must not be registered — so it no longer writes an error row against every IP, and it logs `geoip_database_missing` once at registry build. Gating does not change any score: an unregistered source and one that assessed nothing both contribute to neither term of the risk ratio.

    **Still open, for Phase 6 alongside the build-command work:**
    - decide whether a missing database should **fail the build** rather than warn — it is a silent capability loss, which is the same class of problem as the `|| echo` on the migration step;
    - expose GeoIP availability in `/health`, so the degraded state is visible without reading logs;
    - **owner decision: provision `MAXMIND_ACCOUNT_ID` / `MAXMIND_LICENSE_KEY`, or accept IP enrichment without geo permanently.** GeoLite2 is free but requires an account. If accepted permanently, `high_risk_country` should be dropped from `RISK_SIGNALS` rather than left as a signal nothing can ever assess.

    Whether this is latent or the live state is settled by one query — see §5.5 of [the migration-chain design](docs/superpowers/specs/2026-07-30-migration-chain-repair-design.md). It also bears directly on the Spec 5 §1 saturation estimate: if geo has never resolved in production, every IP has been scored on WHOIS alone, which is the thin-evidence case `MIN_ASSESSED_POINTS` exists to smooth.

11. **Hash IOCs are now the least-served type in the platform.** Three changes composed, none wrong individually:
    - VirusTotal was removed (2026-07-29), and it was one of only two reputation providers covering hashes;
    - the remaining hash provider is **OTX alone**, and OTX has no corroboration channel, so under the evidence model it can only ever return `malicious` or `silent` — never a corroborated harmless verdict;
    - the MalwareBazaar **enricher** is credential-gated (2026-07-30), because abuse.ch's query API now returns 401 unauthenticated.

    So with no abuse.ch key configured, a hash IOC receives `reputation` and nothing else, and that reputation is either "flagged by OTX" or "unknown". YARAify is also gated on the same key. Meanwhile MalwareBazaar and Shodan have **no branch in `_enrichment_risk_score`**, so even when a key *is* set and MalwareBazaar confirms a hash as a named malware family, that confirmation contributes nothing to the score.

    This strengthens two Spec 5 items: adding the MalwareBazaar scoring branch, and **re-measuring hashes afterwards** before concluding that no `hash` weight profile is needed. The earlier measurement of a confirmed-malicious hash at 39 from a single feed is partly an artefact of the enricher that confirmed it being unscored, not a property of the indicator. The feed-side keyless switch does not help here: it improves hash *ingestion*, not hash *enrichment*.

    **Branch landed and re-measured 2026-07-31 (Spec 5 §2) — the answer is that a `hash` weight profile IS needed.** MalwareBazaar now scores `family_attribution` (3), `sample_present` (2) and `vendor_detections` (1), source maximum 6. That lifts the enrichment term for a hash confirmed as a named family from the 20.0 no-evidence default to 100.0 — but **the composite moves only 36 → 44 and stays `medium`**, because under the `default` profile a hash cannot move 65% of its own score:

    | Term | Value | Weight | Why it cannot move for a hash |
    |---|---|---|---|
    | `reputation` | 30.0 (neutral) | 30% | OTX is the only remaining hash provider and has no corroboration channel, so it returns `malicious` or `silent` — never a scored verdict in between |
    | `diversity` | 30.0 | 20% | few hash feeds exist; corroboration cannot accumulate |
    | `frequency` | 10.0 | 15% | a hash reappearing in a MalwareBazaar dump is re-sync noise, exactly as for a CVE |

    So a sample that MalwareBazaar names as AgentTesla *and* YARAify matches by rule *and* ClamAV detects reads **medium**. This is the same argument that justified the `cve` profile, with the same shape: weight sitting on terms that describe network-indicator corroboration, applied to an object that is not a network indicator. A profile shaped like `cve` (enrichment 0.30, diversity 0.05, frequency 0.00) puts the same indicator at **58 — `high`**.

    **SUPERSEDED 2026-07-31 by design B' — no hash weight profile is needed.** The conclusion above was correct only for the design it assumed: leaving reputation at its neutral and weighting family attribution inside the enrichment term. Under B' the reputation term *takes* the identification (`_reputation_from_malwarebazaar`: named + vendor 90, named 80, held-unattributed 55) and `family_attribution` moves out of `RISK_SIGNALS`, so MalwareBazaar's source maximum drops 6 → 3. Reputation takes identity, enrichment keeps corroboration — the same split as NVD, so nothing is double-counted.

    Measured on a sample named AgentTesla with vendor intel and a YARAify hit, under the **unchanged `default` profile**: **44 → 62 at one feed, 54 → 72 at four — medium → high.** The `reputation` term was the binding constraint all along, not the weights; fixing the term made the profile unnecessary. Pinned by `TestMalwareBazaarSignals::test_a_confirmed_family_now_reaches_high`.

    Design A was rejected on a measured ordering inversion: with reputation stuck at neutral, `OTX-flagged-only` reached 78 (critical) while `confirmed-and-named` stopped at 72 (high) — one OTX pulse outranking a named family with vendor corroboration and YARAify hits, because OTX was the only evidence able to reach the reputation term. Adding weight to enrichment could not fix that and made it worse.

    The underlying gap is unchanged and still open: no configured provider can return a *corroborated harmless* verdict for a hash, so the 0.0 branch stays unreachable for hashes as for everything else.

    **Shodan remains unscored — recommendation only, deliberately not implemented.** Its payload describes *exposure* (open ports, banners, detected services), not maliciousness, and every scorer in `RISK_SIGNALS` returns a risk verdict. An open RDP port on an IP already in a botnet feed is corroborating context; on an arbitrary IP it is a property of the internet. Scoring it as risk would mean every well-connected host reads dangerous, which is a precision loss, and the natural weight is small enough that the branch would not change buckets. If it is ever added, the honest signal is a narrow one — a service banner matching a known C2 family — not port count. `tests/test_enrichers.py::TestAssessedContract::test_every_scored_source_has_a_registry_entry` now pins the unscored set as exactly `{shodan}`, so this stays a decision rather than an oversight.

10. **`feed_sources` rows for `virustotal` and `phishtank` are soft-disabled, not deleted** (revision `e5f6a7b80002`), because `ioc_sources` still links them to indicators they contributed and deleting the rows would cascade those links away, silently lowering `source_count` and therefore the diversity term. Any future cleanup has to rescore the affected indicators in the same change. Note also that the planned `feed_sources.enabled` column is **not needed** — `is_enabled` has existed since the initial schema and is what every consumer filters on; that revision only added the missing `NOT NULL`.

*(The previous entry here — "the README's stack table, quick-start and repository URL do not match the deployed MySQL/Vercel/Render reality" — is resolved. Verified 2026-07-29: the badge, stack table, architecture diagram and quick-start all say MySQL and note that `docker-compose` starts no database, and the clone URL matches `git remote`.)*

---

## 9. Operating the platform after this review

Two configuration items are now **mandatory** — the application refuses to start in production without them:

| Variable | Requirement |
|---|---|
| `DATABASE_URL` | Required always. There is no hardcoded fallback any more. |
| `SECRET_KEY` | Required in production, ≥32 random chars. Generate with `python -c "import secrets; print(secrets.token_urlsafe(48))"`. In development an ephemeral key is generated per process. |

Recommended additions:

| Variable | Purpose |
|---|---|
| `CRON_SECRET` | Lets a scheduler call `POST /api/v1/feeds/sync-all` and `POST /api/v1/enrichment/backfill/start` with an `X-Cron-Secret` header instead of an admin token. |
| `CORS_ORIGINS` | Explicit frontend origins. `*` is now stripped — a wildcard cannot be combined with credentialed requests. |
| `ENABLE_API_DOCS` | Defaults to `false`; `/docs`, `/redoc` and `/openapi.json` are not served in production unless set. |
| `ADMIN_EMAIL`, `ENABLE_ERROR_EMAILS` | Error-alert emails are now opt-in and carry redacted request context. |
| `NVD_API_KEY` | Optional. NVD enrichment works unauthenticated at 5 req/30s; a key raises it to 50 req/30s. |
| `YARAIFY_API_KEY` | abuse.ch Auth-Key for YARAify hash enrichment. Falls back to `MALWAREBAZAAR_API_KEY`; the enricher is unregistered if neither is set. |
| `MALWAREBAZAAR_API_KEY` | abuse.ch Auth-Key. **Required as of 2026-07-30**, not optional: `mb-api.abuse.ch/api/v1/` returns 401 unauthenticated, so the enricher is credential-gated and hash enrichment loses MalwareBazaar without it. Same account key as `URLHAUS_API_KEY` / `THREATFOX_API_KEY` / `YARAIFY_API_KEY`. |
| `CVEDETAILS_ACCESS_TOKEN` | Paid CVE Details subscription. The enricher is unregistered without it. |

Apply the new migration before starting the updated backend:

```bash
cd backend && alembic upgrade head        # d4e5f6a70001_harden_otp_table
```

`docker-compose.yml` and `render.yaml` no longer contain credentials; both read from the environment. See [.env.example](.env.example) for the full list.
