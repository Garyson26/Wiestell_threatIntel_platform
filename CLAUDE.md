# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Wiestell (internally "SENTINEL") is a Threat Intelligence Platform: a FastAPI backend that ingests IOCs from 10+ open-source threat feeds, enriches them (WHOIS/DNS/GeoIP/reputation/Shodan/MalwareBazaar), scores them 0–100, correlates them and maps them to MITRE ATT&CK — plus a Next.js SOC dashboard.

Deeper docs written for this repo: [PROJECT_SUMMARY.md](PROJECT_SUMMARY.md) (architecture + known issues) and [SECURITY_REVIEW.md](SECURITY_REVIEW.md) (threat model, findings, residual risk). Read the residual-risk section before touching auth.

## Commands

```bash
# Backend (from backend/)
pip install -r requirements.txt
alembic upgrade head                       # required before first run
uvicorn app.main:app --reload --port 8000
alembic revision -m "description"          # new migration (autogenerate is NOT used here)
python -m compileall -q app alembic        # fast syntax check

# Frontend (from frontend/)
npm install          # NOT `npm ci` — the lockfile is out of sync and ci fails with EUSAGE
npm run dev
npm run build
npm run lint
npx tsc --noEmit     # typecheck

# Full stack
docker-compose up -d

# Seed data (from repo root, against a running backend)
python scripts/seed_feeds.py      # feed registry rows — slugs must match FEED_CONNECTORS
python scripts/seed_mitre.py      # ATT&CK technique catalogue
```

### Tests

```bash
cd backend
pip install -r requirements-dev.txt               # pulls in requirements.txt too
python -m pytest                                  # default tier (~5s, no database needed)
python -m pytest tests/test_enrichers.py          # one file
python -m pytest -k "cvss or kev"                 # by name
python -m pytest tests/test_access_control.py -v  # verbose
```

**Two tiers.** `pytest.ini` sets `-m "not mysql"`, so the default run needs no
database and stays around five seconds. The MySQL tier is opt-in:

```bash
docker compose up -d db                           # MySQL 8 on 127.0.0.1:3307
cd backend && python -m pytest -m mysql           # ~80s
```

It covers what a mocked session structurally cannot: `json_contains` filters
against the JSON columns (the bug class that broke `/attack/*` and the correlation
engine), naive-UTC datetime semantics, the `INSERT ... IGNORE` / `executemany`
ingestion statements, a real 1205 lock-wait timeout forced from two transactions,
`begin_nested()` savepoint isolation, and connection recovery after the container's
deliberately short `wait_timeout=30` fires. Skips with an actionable reason when the
container is not running, so a developer without Docker still gets a green default
run.

`tests/test_query_budget.py` counts statements per request via a
`before_cursor_execute` listener and asserts per-endpoint ceilings. Three are
`xfail(strict=True)` because the N+1s they describe are not fixed yet — measured
today: `attack/matrix` 41, `attack/heatmap` 41, `dashboard/trends?days=30` 60,
`dashboard/stats` 3. Fixing an endpoint turns its XFAIL into an XPASS, which fails
the run and prompts you to delete the marker. Counting statements rather than timing
is deliberate: local latency to a container is ~0.1 ms against 50-300 ms from Render
to Hostinger, so an N+1 is invisible locally and fatal in production.

**`docker compose` gotchas.** Host ports are configurable (`BACKEND_PORT`,
`DB_PORT`, `FRONTEND_PORT`, `NGINX_PORT`, `REDIS_PORT`) so the stack can coexist
with others. `DB_IMAGE` defaults to `mysql:8.0` and **must be changed to the
matching MariaDB tag if production turns out to be MariaDB** — their JSON function
semantics differ, and testing MySQL 8 behaviour against a MariaDB host is worse than
not testing. The backend service carries Render free-instance limits
(`mem_limit: 512m`, `cpus: 0.1`); both the legacy top-level keys and the
`deploy.resources.limits` block are present, and Compose v5.1.2 honours them — 
verified via `docker inspect` (`Memory=536870912`, `NanoCpus=100000000`).

`tests/conftest.py` sets the required env vars **before** importing `app` (config raises on a missing `DATABASE_URL` or a placeholder `SECRET_KEY`), and provides a `FakeSession` stub plus an `as_role("admin"|"analyst"|"viewer")` fixture that mints a token and overrides `get_db`. No test touches a real database — authorization resolves before any handler body runs, so 401/403 paths need no DB at all.

What the suite pins down, i.e. what will break loudly if regressed: every route is guarded unless explicitly allowlisted; role boundaries; token forgery/`alg:none`/expiry/type; OTP hashing and purpose-binding; password policy; production `SECRET_KEY` refusal; wildcard-CORS stripping; secret redaction; the `api_key_env` allowlist (including the scheduler-level check); feed parsing and registry resolution; per-type enrichment sources; CSV formula escaping; AI prompt-role validation.

## Required environment

`DATABASE_URL` has **no default** — importing `app.config` raises without it, deliberately (a hardcoded production DSN used to live there). `SECRET_KEY` must be ≥32 random chars or startup fails when `ENVIRONMENT` is production/staging; in development an ephemeral key is generated per process, so tokens do not survive a restart. See [.env.example](.env.example).

Any local script or one-off check needs at least:
```bash
DATABASE_URL="mysql+pymysql://u:p@localhost/db" SECRET_KEY="$(python -c 'import secrets;print(secrets.token_urlsafe(48))')" python ...
```

## Database gotchas (these cause real bugs)

**It is MySQL, not PostgreSQL.** The README badges and `.env.example` history say Postgres; the code targets MySQL (`mysql+aiomysql` async, `mysql+pymysql` sync/Alembic) against a shared host. Consequences:

- `tags`, `metadata`, `mitre_techniques` are **`JSON` columns**, not `ARRAY`. The PostgreSQL comparators `.any()` and `.overlap()` do not exist on them — using them was a live crash in `api/attack.py` and `services/correlation_engine.py`. Filter with `func.json_contains(col, func.json_quote(value)) == 1`.
- All datetimes are stored **timezone-naive UTC** to match MySQL `DATETIME`. Write `datetime.now(timezone.utc).replace(tzinfo=None)`. **Corrected 2026-07-30:** an earlier version of this note said comparing a naive column against an aware value raises `TypeError`. In a *query* it does not raise at all — pymysql formats the value and MySQL compares the wall-clock reading, **silently discarding the offset**, so an aware `11:00+05:30` matches as though it were `11:00`. This project renders IST (+05:30), so that is the offset in play and the failure mode is wrong rows rather than a stack trace. The `TypeError` is real but comes from Python-side arithmetic on a value read back from a naive column. Both behaviours are pinned in `tests/test_mysql_integration.py::TestNaiveUTCDatetimes`. `utils.to_ist_str()` converts to IST for display only.

  **The ORM now enforces this; raw `sa.text()` does not.** Since 2026-07-31 every
  `DateTime` column in `app/models/` is `models/types.py::NaiveUTCDateTime`, which
  coerces an aware value to naive UTC in `process_bind_param`. That hook fires on
  **comparison operands** as well as inserts — per bind parameter, so it also covers
  `IN`, `BETWEEN` and `case()` — so all six audited sites below are now correct by
  construction rather than by the offset happening to be zero. It has **no**
  `process_result_value`: reads stay naive, because `to_ist_str()` assumes naive input.
  No stored data changed and the emitted DDL is still `DATETIME`, so no migration is
  implied.

  **The gap is raw SQL.** `sa.text()` with bound parameters has no column type in play,
  so the value goes straight to the driver and the offset is discarded exactly as
  before. `scripts/rescore_corpus.py` is built entirely on `text()` — it passes no
  datetimes today, but it is one edit from doing so. Pass naive UTC explicitly there.
  Both the coercion and the gap are pinned in `tests/test_naive_utc_type.py`.

  **Audit of aware datetimes reaching the database (2026-07-30).** Each site below was
  *correct* only because UTC's offset is zero — the wall-clock reading of an aware UTC
  value equals the naive UTC value. All six go through the ORM, so the decorator now
  covers them; the list is retained because it is the inventory to re-check if any of
  them moves to raw SQL.

  | Site | Aware value | Reaches |
  |---|---|---|
  | `api/dashboard.py:20` | `yesterday` | `IOC.created_at >= yesterday` inside `case()` |
  | `api/dashboard.py:174` | `cutoff` | `IOC.created_at >= cutoff` |
  | `api/dashboard.py:238` | `day_start` / `day_end` | `IOC.created_at >=` / `<` — **the Phase 5 trap** |
  | `api/ai.py:151` | `yesterday` | `IOC.created_at >= yesterday` |
  | `services/report_generator.py:18` | `yesterday` | `IOC.created_at >=`, `IOC.last_seen >=` |
  | `services/report_generator.py:162` | `generated_at=` | a **write** of an aware value into a naive column |

  Not affected: `api/deps.py:43` (JWT expiry, no column), `feeds/base.py:116-117`
  (ingestion passes both through `_strip_tz`), `scoring_engine.py:414,567` and
  `feeds/threatfox.py:388` (Python-side arithmetic on parsed feed values),
  `utils/stix_converter.py` and `main.py:178` (output formatting only).

  **⚠ Phase 5 caution — read before rewriting `get_trends`.** Turning
  `dashboard.py::get_trends` into a single `GROUP BY` means computing day boundaries
  in SQL or in Python, and this platform renders IST (`utils.to_ist_str`), so an
  IST-aware boundary is the natural thing to reach for. Measured behaviour: the
  offset is discarded on **both** comparison and insertion, so `12:00+05:30` (06:30
  UTC) is treated as `12:00` — a 5.5-hour shift, with no exception and no warning. A
  "day" would silently start at 18:30 the previous day. Build boundaries as naive UTC
  and convert to IST only for display. Pinned by
  `tests/test_mysql_integration.py::TestNaiveUTCDatetimes`.

  **Reduced but not eliminated by the decorator.** If the rewrite computes boundaries in
  Python and filters through the ORM, `NaiveUTCDateTime` coerces them and an IST-aware
  boundary is now merely redundant rather than wrong. Two routes are still unprotected:
  computing boundaries **in SQL** via `sa.text()`, and `func.date()`/`DATE_FORMAT`
  grouping, which operates on the stored naive value and so groups by UTC day.
  Design note: [docs/superpowers/specs/2026-07-30-naive-utc-typedecorator-design.md](docs/superpowers/specs/2026-07-30-naive-utc-typedecorator-design.md).

  **Audited 2026-07-31 — the current endpoints are self-consistent, so this is a
  constraint on the rewrite rather than a live bug.** `get_stats` groups with
  `func.DATE(IOC.created_at)` (UTC day) and keys the Python side off
  `datetime.now(timezone.utc)` (UTC date), so bucket and label agree; `get_trends`
  builds midnight-UTC boundaries and labels with the UTC date, likewise agreeing — and
  it has no frontend caller at all (`getTrends` is exported from `lib/api.ts` and never
  invoked). `StatsCards` renders the sparkline as unlabelled bars, so no date is shown
  to a user today. Nothing is currently mislabelled.

  **What that leaves is latent and specific.** Every *other* timestamp the UI shows goes
  through `to_ist_str`, so the moment date labels or an axis are added to a trends chart,
  the natural move is to render the `date` field as-is — a UTC date beside IST
  timestamps. An IOC created 03:00 IST on 31 Jul (21:30 UTC on 30 Jul) then counts in the
  "30 Jul" bar while its own row reads 31 Jul. The 00:00–05:30 IST window is ~23% of each
  day's ingests, so it is not a rounding-error-sized discrepancy. **Decide the bucket
  timezone explicitly in the rewrite and label it to match.**

  **If you group by IST day, use the offset form, not the zone name.** Measured against
  the local MySQL 8.0 container:

  | Expression | Result |
  |---|---|
  | `DATE('2026-07-30 21:30:00')` | `2026-07-30` (UTC day) |
  | `DATE(CONVERT_TZ(…,'+00:00','+05:30'))` | `2026-07-31` — correct, needs no tz tables |
  | `CONVERT_TZ(…,'UTC','Asia/Kolkata')` | correct **here** — `mysql.time_zone_name` has 1795 rows |
  | `CONVERT_TZ(…,'UTC','No/Such_Zone')` | **NULL, silently** — no error, no warning |

  The named form depends on the timezone tables being populated, which they are in the
  `mysql:8.0` image and frequently are **not** on shared hosting. When they are absent
  `CONVERT_TZ` returns NULL for every row, `DATE(NULL)` is NULL, and every bucket
  collapses into one NULL group — which reads as "no data" rather than as a failure. That
  is a defect that passes locally and breaks only in production, the same trap as the
  `DB_IMAGE`/MariaDB note above. India observes no DST, so `'+05:30'` is a fixed offset
  year-round and the offset form is not merely safer but fully correct.

  **Better still, avoid the dependency entirely:** `DATE(col + INTERVAL 330 MINUTE)` is
  pure arithmetic, needs no timezone tables, and behaves identically on MySQL and
  MariaDB — which matters because `DB_IMAGE` may have to change if production turns out
  to be MariaDB. Whichever form is used, **put the offset behind one named constant**
  rather than repeating `330` or `'+05:30'` at each call site.

  **Answer the prior question first: is IST-day bucketing actually required?** Nothing
  labels the buckets today, so grouping by UTC day and formatting in Python is simpler
  and needs no SQL timezone handling at all. Only reach for in-SQL conversion if the
  buckets must align with IST calendar days for a stated reason. **Decide this before
  Phase 5 writes the `GROUP BY`** — retrofitting a bucket timezone means rewriting the
  query and invalidating any cached series.
- IDs are `CHAR(36)` UUID **strings**, not UUID objects — path params are typed `str`.
- `database.py` patches `aiomysql.Connection.ensure_closed` to swallow dead-transport errors from the shared host's `wait_timeout`; pool settings (`pool_recycle=280`, `pool_pre_ping`) are tuned around that. Don't "clean this up" without understanding the failure it prevents.

**Transaction ownership:** `get_db()` commits when the request handler returns. Handlers therefore call `await db.flush()`, not `commit()` — an inner `commit()` breaks the outer unit of work. `enrichment_engine.enrich_ioc` writes inside `session.begin_nested()` so a duplicate-key race rolls back only the enrichment and leaves the request's transaction usable.

## Authorization model

Authentication is enforced **server-side, at router registration** in `app/api/__init__.py`, with role dependencies on individual routes. The React guards (`components/auth/*Route.tsx`) are UX only — never rely on them.

`app/api/deps.py` is the single source of truth: `get_current_user`, `require_roles(...)`, `require_admin`, `require_analyst`, `require_admin_or_cron` (admin token **or** `X-Cron-Secret`), `rate_limit(bucket, max, window)`, and `create_access_token`.

Roles are `admin` > `analyst` > `viewer`. Reads are authenticated; IOC/report mutations need analyst; feed CRUD, user administration, the contact inbox and `/cron-status` need admin; `feeds/sync-all` and `enrichment/backfill/start` accept the cron secret.

**When adding an endpoint:** it inherits its router's dependency, so it is authenticated by default — except on `/users` and `/contact`, whose routers are intentionally unguarded because they mix public and private routes. Add the dependency explicitly there. Public routes must be added to the allowlist in whatever route-guard check you run.

Other invariants to preserve:
- OTPs are stored as a `SECRET_KEY`-keyed, email-bound SHA-256 HMAC with a `purpose` (`login`/`signup`/`password_reset`) and an `attempts` counter. Never log or return a code; never accept a code across purposes.
- Anything that persists or returns an exception string must pass through `utils/sanitize.redact_secrets()` — driver errors embed the connection URI. `redact_headers()` for header dumps. `feed_sources.last_sync_error` is served to clients, so it is redacted on write *and* in the `FeedResponse` serializer.
- JWTs use PyJWT with an explicit `algorithms=[...]` allowlist and `type: "access"`; `python-jose` was removed and should not come back.
- `feed.api_key_env` is restricted to `config.ALLOWED_FEED_API_KEY_ENVS`, enforced in the schema *and* at read time in `feed_scheduler` — the value is forwarded to third-party APIs, so an unrestricted name is a secret-exfiltration primitive.
- **Four subsystems assume one process per instance, so the uvicorn worker count is part of the security model, not a throughput dial.** `--workers 1` is declared in `render.yaml` and `backend/start.sh`, refused at startup by `main.py::_assert_single_worker` (overridable with `ALLOW_MULTIPLE_WORKERS=true`), and pinned by `tests/test_process_model.py`. At N workers: the in-memory rate limiter becomes N independent budgets, so the effective limit is N × `AUTH_RATE_LIMIT_MAX` — this is what makes the residual-risk #5 narrowing valid; the database pool is per process, so 2 + 3 becomes 5N connections against a **shared** MySQL account allowance; `enrichment_engine`'s module-level semaphore becomes 5N third-party calls in flight; and any in-process cache becomes N inconsistent caches. Each degrades silently. The check is at runtime as well as in a test because Render's dashboard can override the start command without touching a file. Raising the count means revisiting all four together — Redis for the limiter and any cache, a smaller `pool_size`, and a shared bound for enrichment.
- **A guard whose failure mode is silence needs its *extraction* verified, not just its assertion.** Several checks here do not compare two values directly — they first gather something (AST nodes, log records, registry contents, declared signal names) and then assert over what they gathered. If the gathering step silently returns nothing, the assertion passes vacuously and the guard is decorative. This has bitten four times: the `SCORING_MODEL_FINGERPRINT` hash omitted `WEIGHT_PROFILES` because it is an `ast.AnnAssign` and the walker only handled `ast.Assign`; the `assessed` name-match extractor missed four dict-construction styles, then over-matched a ternary condition; and the GeoIP missing-database test asserted over `caplog.records`, which is always empty because structlog renders straight to stdout. So: **mutate the thing being guarded and confirm the test fails.** Delete the log line, rename the signal, neuter the constant — if the suite stays green, the guard never worked. Assert non-emptiness of whatever was extracted, and prefer `capsys` over `caplog` for structlog output.

## Architecture notes worth knowing before editing

**Feed ingestion (`services/feed_ingestion.py`) is deliberately intricate.** It exists in async and sync variants and is tuned against InnoDB lock contention on a shared host: one lock-free `SELECT`, a single `INSERT ... IGNORE` for new rows, a single `executemany UPDATE` for existing rows (so locks are held for one statement rather than the whole Python loop), a commit per ~30-row chunk, and retry with exponential back-off on lock-wait timeout (1205) / deadlock (1213). The comments explain each choice. Rewriting this as straightforward ORM code reintroduces the timeouts it was built to fix.

**Feed connectors** subclass `feeds/base.py::BaseFeed` (`fetch()` → `parse()` → list of `_make_ioc()` dicts). Registration is by **slug** in `services/feed_scheduler.py::FEED_CONNECTORS`, which includes alias slugs (`urlhaus` and `urlhaus-feed`) because DB rows disagree with canonical names. A feed row whose slug is not in that map cannot sync. `BaseFeed.run()` intentionally lets exceptions propagate so `run_feed_sync` can record `last_sync_status='failed'` rather than a misleading `no_data`.

Adding a feed means four things, all required: the connector class (with `slug`, `feed_type`, `url`, `name` set), a `FEED_CONNECTORS` entry, a row in `scripts/seed_feeds.py`, and — only if it needs a key — an entry in `config.ALLOWED_FEED_API_KEY_ENVS`. Note that `parse()` must return **plain dicts** from `_make_ioc()`; `feed_ingestion._normalize_batch` does `raw.get("type")`, so returning `IOCCreate` models raises `AttributeError`. `app/feeds/mitre_attack.py` is *not* a connector — it is a `load_attack_data()` loader used by `scripts/seed_mitre.py`, and deliberately has no registry entry.

**Enrichers all live in `app/enrichers/`** as `BaseEnricher` subclasses registered in `__init__.py::build_registry`. `supports()` drives applicability, `cache_ttl` drives caching, and `enrichment_engine` holds no per-source knowledge — it only orchestrates caching, concurrency, persistence and rescoring. **Adding an enricher is one line in `build_registry`.** Rules:

- `enrich()` must never raise. Return a dict, `None` to mean "not applicable to this specific value" (YARAify does this for non-SHA256 hashes, so nothing is stored or cached), or `{"error": ...}`.
- Gate registration on the credential so an unconfigured source never appears applicable and never stores an `{"error": "no api key"}` row against every IOC. Shodan is the deliberate exception — it stays registered and returns an explanatory payload, preserving pre-existing dashboard behaviour.
- **Registration order is the attempt order**, and `tests/test_enrichers.py::TestEngineDispatch` pins the per-type source table. Reordering `build_registry` changes that contract.
- Blocking libraries must go through `run_in_executor` (see `whois_enricher`) — a synchronous network call stalls the whole event loop. There's a test asserting WHOIS runs off the loop thread.

**Three background-work mechanisms coexist and only one runs:**
| Mechanism | State |
|---|---|
| `services/feed_scheduler.py::feed_scheduler_loop` (asyncio) | implemented, **never started** — `lifespan()` skips it for serverless |
| `tasks/celery_app.py` beat schedule | wired up, entire schedule commented out |
| `POST /api/v1/feeds/sync-all` | **the live path**, driven by external cron |

Don't assume a change to the scheduler or Celery affects production.

**Enrichment** picks sources per IOC type (`_get_applicable_sources`), reuses non-expired cached rows from the `enrichments` table (one row per IOC×source, TTL in `expires_at`), and runs the remainder concurrently with `asyncio.gather`. Blocking WHOIS is offloaded to a thread pool. Enrichers degrade to `{"error": ...}` rather than raising when an API key is absent.

**Scoring** (`services/scoring_engine.py`) is a weighted composite, with weights from a per-type profile in `WEIGHT_PROFILES` — `default` is reputation 30%, source diversity 20%, recency 15%, sighting frequency 15%, enrichment risk 10%, context 10%; `cve` reweights to 30/5/10/0/30/25. Profiles are asserted at import to sum to 1.0. Buckets are critical ≥76 / high ≥51 / medium ≥26 / low. Frontend badges assume those thresholds — change both together. Ingestion scores an IOC *before* any enrichment exists, so `enrichment_engine._rescore_from_enrichment` recomputes the score at the end of every enrichment pass — otherwise the enrichment-risk weight is always evaluated against an empty list.

Two rules for the enrichment-risk term specifically:

- **A new enricher that produces a risk signal needs an entry in `RISK_SIGNALS`** — `(source, signal) → (points, scorer)` — or its data contributes to neither term and is scored as neutral. `tests/test_enrichers.py::TestAssessedContract` pins the unscored set as exactly `{shodan}`, so a source added without a branch fails loudly.
- **Never infer "was this assessed" from key presence.** The enricher declares it: `enrich()` returns `assessed`, the list of signal names it actually evaluated, and only those enter the denominator. A key can be absent because the source said nothing or present-but-empty because it said "nothing found" — opposite answers, identical shape. Five defects came from guessing, all making unexamined indicators look safe. Signal names must match `RISK_SIGNALS` exactly; a typo silently zeroes the term. Payloads without `assessed` fall back to `_legacy_assessed`, which is **permanent** — cached rows are never refreshed, so they never age out.

The denominator is floored at `MIN_ASSESSED_POINTS` (3), since each scorer returns its own full weight or zero and a lone assessed signal would otherwise always read 100.0. The zero-evidence guard must stay **before** the floor, or every never-enriched IOC reads 0.0 rather than the 20.0 neutral. **Bumping `SCORING_MODEL_VERSION` is an acceptance criterion for any change that moves scores**, not a judgement call — the fingerprint guard cannot see changes inside an enricher.

**Frontend** funnels every request through `lib/api.ts::fetchAPI`, which attaches the bearer token from `localStorage`, drops the token on a 401 and flattens FastAPI validation arrays into readable messages. Add new calls there rather than using raw `fetch()`, or the request goes out unauthenticated. `lib/auth.tsx` holds the session and re-validates against `/users/me` on load. Route groups map to access levels: `(bare)` = auth pages, `(protected)` / `(analytics)` = signed-in app, with `AdminRoute` on the user-management and contact-inbox pages.

Response bodies and search parameters must not be logged client-side — they carry tokens and indicator data.

## Known rough edges (documented, not yet fixed)

`api/enrichment.py` keeps backfill progress in module-level globals, so its stats and its "one job at a time" guarantee are per-process. `api/attack.py` issues one `COUNT` per technique and `dashboard.py::get_trends` two queries per day requested — both should become single `GROUP BY` queries. IOC-detail assembly is duplicated across `lookup_ioc`, `get_ioc` and `search_iocs`. Full list in [PROJECT_SUMMARY.md](PROJECT_SUMMARY.md) §8.
