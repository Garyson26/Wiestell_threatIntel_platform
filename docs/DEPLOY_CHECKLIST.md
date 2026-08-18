# Deploy checklist

**Status:** Phase 6 draft, 2026-07-31. Written before the first deploy of this change set,
which is the point — several steps exist because getting the *order* wrong is unrecoverable
or expensive, and that is not discoverable while deploying.

Ordering constraints, stated once so the steps below make sense:

| Because | This must precede this |
|---|---|
| the rescore script skips rows holding an override | first rescore → any `manual_score_override` |
| the seed script writes `feed_sources` rows, so the table must exist | **`alembic upgrade head` → `seed_feeds.py`** |
| feed slugs must resolve to connectors before a sync can do anything | `seed_feeds.py` → first sync |
| scoring changes reach stored rows only via the rescore | deploy code → rescore |
| a rescore reads *stored* enrichment payloads | see §6 — this one is a **decision**, not an order |

---

## 0. Before touching anything

> ### THE FREE PLAN HAS NO SHELL. Read this before planning any step.
>
> Confirmed 2026-08-17: the backend runs on Render's **free** plan (`plan: free`). That is
> not only a cost choice — it removes a capability the rest of this document has to work
> around:
>
> * **No shell, no `render exec`, no one-off jobs.** There is no way to run `alembic`, a
>   seed script, a repair query or a one-line diagnostic *on the instance*. Everything in
>   §2, §3 and §6 runs **from a developer machine against the production DSN**.
> * **No Render cron jobs** — they are a paid feature. That is precisely why the one live
>   background path is an external GitHub Actions schedule calling
>   `POST /api/v1/feeds/sync-all` with `X-Cron-Secret` (§5), rather than a `jobs:` block.
> * **There is no fallback if the developer-machine path fails.** If your workstation
>   cannot reach Hostinger — firewall, IP allowlist, VPN — you cannot migrate or seed at
>   all, and there is no in-service alternative to fall back to. **Verify connectivity
>   before the deploy window**, not during it: a `SELECT 1` against the production DSN is
>   the whole test.
> * **Spin-down applies.** Free instances sleep after ~15 minutes without inbound HTTP,
>   and cold starts are slow. §2.8 of the Phase 4 notes measured that a single URLhaus
>   sync can exceed the idle window on its own — re-derive after deploy with real latency
>   (Phase 6).
> * **750 instance-hours per month, account-wide.** Previews are declared off
>   (`previewsEnabled: false`) for that reason: every preview service drawn from the same
>   pool is time the production service does not get.

- [ ] **Verify you can reach the production database from the machine you will deploy
      from.** `SELECT 1` against the DSN. Everything in §2/§3/§6 depends on it and there
      is no alternative path.
- [ ] **Rotate the credentials still in git history**, if not already done. `9107d1c`
      carries a literal `EMAIL_PASSWORD`; SECURITY_REVIEW.md lists a MySQL and an SMTP
      password, plus two API keys the review never knew about. Rotation is the mitigation;
      the history purge is tracked separately as still-open and is **not** a deploy
      blocker (the repo is private and everything is rotated).
- [ ] ~~Run the owner queries in one sitting~~ **DONE 2026-08-17.** All answered:
      MariaDB 11.8.8; `uq_ioc_type_value` spans the full `(type, value)` with
      `SUB_PART NULL`; `alembic_version` = `c3d4e5f67890`; 217,485 IOCs; 8 feed rows;
      48,058 enrichment rows. The only one outstanding is the GeoIP `error_city` count,
      which is no longer load-bearing.
- [ ] ~~Confirm `alembic upgrade head` cannot run yet~~ **CANCELLED — it runs clean.**
      Error 1170 was a MySQL-8-only restriction and the test container had been on the
      wrong engine. Verified end to end on MariaDB 11.8: empty database → 7 revisions →
      seed → 11 feeds, 11 enabled. The migration-chain repair is not needed.

## 1. Decisions to make, not discover

Each of these has a recommendation with reasoning recorded; none should be settled by
whatever happens first.

- [ ] **MaxMind credentials** — provision `MAXMIND_ACCOUNT_ID` / `MAXMIND_LICENSE_KEY`, or
      accept IP enrichment with no geo data permanently. If accepting, drop
      `high_risk_country` from `RISK_SIGNALS` rather than leaving a signal nothing can
      assess. (§8 item 14)
- [ ] **Rescore now or after Phase 4** — recommendation: now. (§5.4.2 of the migration
      design; see §6 below)
- [ ] **`TRUSTED_PROXY_HOPS`** — leave at 0 until measured in §4. A wrong non-zero value is
      worse than 0 (and note the direction: **too high** is the spoofable one — see R-03).
      **But 0 is not free on Render.** The socket peer is Render's edge, so every caller
      buckets under one address and every per-IP budget becomes a GLOBAL budget: 10 login
      attempts per 5 minutes for the whole world, one user able to exhaust the AI assistant
      for everyone. That is an availability problem arriving on day one of UAT, not a
      misconfiguration — so the §4 measurement is **higher priority than it looks**, and the
      per-account counter (SECURITY_REVIEW item 8) is what would let the IP budget be
      loosened safely. See R-06.
- [ ] **Bucket timezone for trends** — UTC (current, self-consistent) or IST. Decide before
      anyone adds date labels to the chart. (CLAUDE.md, Phase 5 caution)
- [ ] **`k` for the OTX rescale** — measured from the pulse distribution if ≥200 rows carry
      `pulse_count >= 1`, otherwise the pre-committed `k = 14`. Record which. (§8 item 15)
- [ ] **abuse.ch API key** — free signup at `auth.abuse.ch`. The MalwareBazaar *feed*
      connector is keyless, so ingestion needs nothing; but the MalwareBazaar and YARAify
      **enrichers** are both credential-gated, and without the key a hash IOC receives
      `reputation` and nothing else — from OTX alone, which has no corroboration channel
      and so can only ever return `malicious` or `silent`, never a scored verdict in
      between. **Hash enrichment is effectively dead in UAT without this**, and the §6a
      work that made a confirmed sample reach `high` cannot fire at all. Sets
      `MALWAREBAZAAR_API_KEY`; `YARAIFY_API_KEY` falls back to the same value.
      (§8 item 11)
- [ ] **Email provider** — `EMAIL_USER` / `EMAIL_PASSWORD` / `SMTP_HOST`. Without them
      `send_*_email` returns early, so **OTP delivery fails and nobody can log in**. Note
      the OTP is no longer returned in the response body when delivery fails (that was
      C-04), so a missing provider is a hard login block rather than a degraded one.
- [ ] **Render region** — `render.yaml` says `oregon`. There is **no India region**, which
      is the reason the query-budget work counts statements rather than timing them: every
      round trip to Hostinger carries 50–300 ms. Pick the region closest to the database,
      not to the users, since the app is far chattier with MySQL than with the browser.
- [ ] **Free versus Starter instance** — free is capped at `cpus: 0.1` / 512 MB **and spins
      down when idle**, so the first cron firing after a quiet period pays a cold start
      inside the sync's own timeout. The `/attack/*` measurement in §8 item 17 (~2 s at
      50,000 tagged IOCs) is a *0.1 CPU* figure and improves roughly linearly with CPU.
- [ ] **The four cron firing times.** `.github/workflows/feed-sync.yml` currently has
      `17 */6 * * *` as a placeholder. **They must be EVENLY SPACED**, because
      `tests/test_deploy_config.py` reduces the cron expression to a single interval and
      compares it against `_GOVERNING_SYNC_INTERVAL_SECONDS`; a non-uniform schedule does
      not reduce, and the test raises rather than guessing. So:

      | Expression | Result |
      |---|---|
      | `17 */6 * * *` | fine |
      | `17 0,6,12,18 * * *` | fine — the enumerated form is accepted too |
      | `0 0,6,12 * * *` | **fails** — looks 6-hourly but the overnight gap is 12h |
      | `0 9,17,21,23 * * *` | **fails** — genuinely uneven, no single interval |

      The check derives the firing hours, diffs them **including the midnight wraparound**,
      and requires the gaps to be equal — so it is the worst-case-gap comparison, and both
      the `*/N` and enumerated forms reduce identically. The `0,6,12` row is why the
      wraparound matters: within the day its gaps look like 6h, but 12:00 → 00:00 is 12h,
      and calibrating the window check against half the true gap would silently
      under-report exactly what it exists to catch.

      Stated here so the times are chosen knowing the constraint rather than discovered from
      a red build. If uneven spacing is ever genuinely wanted (aligning each sync to a
      different feed's publish time, say), change `_GOVERNING_SYNC_INTERVAL_SECONDS` to
      describe the **worst-case** gap and compare against that — the failure message names
      the largest gap so the value is to hand.

## 2. Schema

**REWRITTEN 2026-08-17 after Phase 4 A–E, and after rehearsing the whole sequence on a
fresh MariaDB 11.8. Most of what this section used to say was wrong.**

> **RUN §2 AND §3 FROM A DEVELOPER MACHINE, AGAINST THE PRODUCTION DSN.** Not on Render:
> free instances have no shell and no one-off jobs, so there is nowhere to run `alembic`
> or a seed script. Same constraint as the rescore in §6.
>
> **ORDER IS §2 THEN §3, AND IT IS NOT INTERCHANGEABLE.** `seed_feeds.py` writes
> `feed_sources` rows, so the table must exist first. Verified as one unbroken pass on
> 2026-08-17 — empty database → 7 revisions → seed → **11 feeds, 11 enabled**.
>
> ```bash
> # bash / zsh
> cd backend
> DATABASE_URL="mysql+pymysql://user:pass@host/db" python -m alembic upgrade head
> cd ..
> DATABASE_URL="mysql+pymysql://user:pass@host/db" python scripts/seed_feeds.py --dry-run
> ```
>
> ```powershell
> # PowerShell — the owner's shell. `VAR=value cmd` is a PARSE ERROR here.
> $env:DATABASE_URL = "mysql+pymysql://user:pass@host/db"
> cd backend
> python -m alembic upgrade head
> cd ..
> python scripts\seed_feeds.py --dry-run
> ```
>
> Note `python -m alembic`, not `alembic`: the bare entry point is not always on PATH
> under Git Bash on Windows (measured — it fails with "Permission denied").

The migration-chain repair is **cancelled**: `alembic upgrade head` runs clean from empty
on MariaDB 11.8, all seven revisions. Error 1170 was a MySQL-8-only restriction, and the
tier had been running against `mysql:8.0` — the schema was never broken, the container
was. The test-only prefix-length scaffold is already deleted.

- [ ] `alembic upgrade head`. Verified end to end on 2026-08-17 from an empty database:

      56fe08259401 → b97d3e9a80e4 → c3d4e5f67890 → d4e5f6a70001
                   → e5f6a7b80002 → f6a7b8c90003 → a7b8c9d00004

- [ ] Production sits at `c3d4e5f67890`, so **three revisions apply**: `d4e5f6a70001`
      (OTP hardening), `e5f6a7b80002` (soft-disable removed feeds) and `f6a7b8c90003`
      (rolling-window continuity) — plus `a7b8c9d00004` (Phase 4 scheduling columns).
      Rehearsed against a replica of production's exact 8 feed rows: all four apply, every
      `is_enabled` stays 1, `e5f6a7b80002` matches zero rows and is a clean no-op.
- [ ] `a7b8c9d00004` **backfills `last_attempt_at` from `last_sync_at`**. Confirm it ran:
      without it every feed reads as never-attempted and the first cron fires all 11 at
      once against a shared host.
- [ ] `iocs.scoring_model_version` and `iocs.manual_score_override` are **still not
      columns**, and still need owner sign-off. The rescore probes `information_schema`
      for the override and adapts; the version constant lives in code only.
- [ ] The §2.1 / §3.2 diagnostic queries are **no longer prerequisites** — they belonged
      to the cancelled chain repair. Run them if you want the numbers; nothing waits on
      them.

## 3. Seed

**Runs AFTER §2, from a developer machine.** The script writes `feed_sources` rows, so
the migrations must have created the table; and Render free instances have no shell to run
it from. It no longer calls `create_all()` as a fallback — depending on that was how the
ordering used to be stated, and it hid the real dependency.

- [ ] `python scripts/seed_feeds.py --dry-run` **first**. It now upserts by alias group
      rather than skipping on an exact slug match, and the dry run prints exactly what it
      would insert and update. Against production's 8 rows it reports **3 inserts, 8
      cadence updates, 0 duplicates**.
- [ ] Then `python scripts/seed_feeds.py`. It is idempotent — a second run reports
      `0 inserted, 0 updated, 11 unchanged`.

      **Why the rewrite mattered:** three production rows use ALIAS slugs
      (`urlhaus-feed`, `emerging-threats-feed`, `feodo-tracker-feed`). The old exact-match
      logic found no row for the canonical names and would have **inserted three
      duplicates** — and `COUNT(DISTINCT feed_id)` over `ioc_sources` is the
      source-diversity term, so every indicator later ingested by both rows would have
      scored as two independent sources.
- [ ] It preserves `is_enabled`, `last_sync_at`, `last_attempt_at`, `consecutive_failures`,
      `sync_cursor`, `http_etag`, `http_last_modified`, `ioc_count`, watermarks and `slug`.
      **Concrete near-miss:** `seed_feeds.py` declares `otx-alienvault` as
      `is_enabled=False`, and production has it ENABLED with 9,800 IOCs. A seeder that
      wrote that column would have switched off a working feed.
- [ ] `url` drift is **reported, not written**. Expect three lines (malwarebazaar,
      feodo-tracker-feed, otx-alienvault). Decide each explicitly; the column is
      descriptive only — no connector reads it, so a drift misinforms an operator rather
      than misrouting a fetch.
- [ ] `python scripts/seed_mitre.py` — the ATT&CK catalogue. `/attack/*` returns empty
      without it.
- [ ] Confirm a fresh seed reports **11 inserted** and all 11 `is_enabled = 1`.

      `otx-alienvault` and `abuseipdb` used to seed as `is_enabled = 0`, giving 9 of 11 —
      found by the 2026-08-17 rehearsal and **fixed, not documented around**. The default
      dated from when a keyed feed could not work without credentials at seed time; it had
      become a real cost, because OTX is the only reputation provider covering hashes at
      all after VirusTotal's removal, and OTX + AbuseIPDB are the only pair that can
      corroborate an IP verdict. Production was unaffected either way — `is_enabled` is
      preserved on existing rows — but a fresh environment silently lost both.
- [ ] Verify `virustotal` and `phishtank` are `is_enabled = 0` **if they exist at all**.
      Production has neither — its 8 rows are all canonical — so `e5f6a7b80002` matches
      nothing and that is expected, not a failure.

## 3.5 Environment variable reference — AUTHORITATIVE

Generated 2026-08-17 **from `backend/app/config.py` and `render.yaml` directly**, not from
any spec. The lists in the handback documents were reconstructed and several were stale.

Render exposes a service's `envVars` to **both** the build command and the runtime, so
there is no separate build-time section to fill in — the build-time flag below marks
variables that are only *read* during the build, not variables that live elsewhere.

### 3.5.1 Must set, or the service will not start

| Variable | Default | Handling | What breaks without it |
|---|---|---|---|
| `DATABASE_URL` | **none** (`Field(...)`) | `sync: false` | **Import-time crash.** `app.config` raises `ValidationError` before FastAPI starts; the deploy fails at boot, not at first request. Deliberate — a hardcoded production DSN used to live here. |
| `SECRET_KEY` | `""` | **`generateValue: true`** | **Refuses to boot in production.** `model_post_init` raises if the value is <32 chars or in `INSECURE_SECRET_KEYS` while `ENVIRONMENT` is production/staging. Render generates it — **do not set it by hand**, and note that regenerating it invalidates every issued JWT and every outstanding OTP. |
| `ENVIRONMENT` | `development` | `value: production` | Not a crash, but leaving it `development` **disables the `SECRET_KEY` refusal above** and mints an ephemeral key per process, so tokens stop surviving a restart. |

> **`DATABASE_URL` MUST BE WRITTEN `mysql+pymysql://…`.** Measured, not assumed:
> `DATABASE_ASYNC_URL` is derived by `model_post_init` as a literal string replace of
> `mysql+pymysql://` → `mysql+aiomysql://`. Anything else passes through **unchanged**:
>
> | `DATABASE_URL` | derived `DATABASE_ASYNC_URL` | |
> |---|---|---|
> | `mysql+pymysql://u:p@h/db` | `mysql+aiomysql://u:p@h/db` | correct |
> | `mysql+pymysql://…?ssl_ca=…` | `mysql+aiomysql://…?ssl_ca=…` | correct, query string preserved |
> | `mysql://u:p@h/db` | `mysql://u:p@h/db` | **BROKEN** — async engine gets a sync driver |
> | `mysql+mysqldb://u:p@h/db` | `mysql+mysqldb://u:p@h/db` | **BROKEN** |
>
> The failure is at first async query, not at boot. `render.yaml` also declares
> `DATABASE_ASYNC_URL` as `sync: false`, so you may set it explicitly instead — do that if
> Hostinger hands you a bare `mysql://` DSN rather than editing the prefix by hand.

### 3.5.2 Should set

| Variable | Default | Handling | Consequence if unset |
|---|---|---|---|
| `CORS_ORIGINS` | `https://wiestell.com,https://www.wiestell.com` | literal in `render.yaml` | Browser calls from any other origin fail preflight. **Format: comma-separated, no spaces required** (`config.py:179` strips each). A bare `*` entry is **stripped**, not honoured. Currently declares `wiestell.com`, `www.wiestell.com`, `wiestell.vercel.app`. **Vercel preview deployments get per-deploy subdomains and are NOT covered.** Decision 2026-08-17: **not covering them for now** — so preview deploys cannot call the API and every functional test must run against the production frontend origin. A preview will render and then fail on its first API call, which looks like a backend outage rather than a CORS decision; know that before debugging one. |
| `CRON_SECRET` | `""` | **`generateValue: true`** | `feeds/sync-all` and `enrichment/backfill/start` accept it via `X-Cron-Secret` as an alternative to an admin token. Unset means the GitHub Actions feed-sync workflow cannot authenticate and **the only live background path stops running**. Render generates it; copy it into the workflow's repository secret. |
| `RESEND_API_KEY` | `""` | `sync: false` | **Nobody can log in, including you.** Auth is password → email OTP → JWT. Without it `_issue_otp` raises 503 on login; on password reset the 503 is swallowed (C-04), so it silently does nothing. |
| `ADMIN_EMAIL` | `""` | `sync: false` | Only used when `ENABLE_ERROR_EMAILS` is true. Harmless unset. |
| `ENABLE_ERROR_EMAILS` | `False` | `value: false` | Leave false. Error emails carry request context. |
| `TRUSTED_PROXY_HOPS` | `0` | `sync: false` | **Set this to `1` on Render.** At `0`, `deps.py::_client_ip` ignores `X-Forwarded-For` entirely and every request appears to come from Render's proxy — so the per-IP auth rate limiter becomes one global bucket shared by all users. Setting it too high is worse: a client-supplied header value gets trusted and an attacker rotates their own bucket. |
| `ENABLE_API_DOCS` | `False` | `value: false` | Leave false in production; `/docs` exposes the full schema. |
| `LOG_LEVEL` | `INFO` | `value: INFO` | — |
| `PORT` | `8000` | `value: 8000` | Render sets its own; the declared value matches. |

### 3.5.3 Feed and enrichment credentials — all optional

Every one is optional. What differs is **how the system degrades**.

| Variable | Feeds it | Degradation if unset |
|---|---|---|
| `OTX_API_KEY` | `otx-alienvault` feed **and** the reputation enricher | Feed fetch raises `ValueError` → `last_sync_status='failed'`. **And** OTX is the only reputation provider covering **hashes** (`_OTX_TYPES` includes `hash`; `_ABUSEIPDB_TYPES` is `{"ip"}`), so hash reputation disappears entirely. |
| `ABUSEIPDB_API_KEY` | `abuseipdb` feed **and** the reputation enricher | Feed fails. The provider is recorded `configured: false` rather than erroring, so IP reputation rests on OTX alone with nothing to corroborate it — reputation aggregates as **MAX** across providers. |
| `GROQ_API_KEY` | `api/ai.py` — **this is the name you asked for** | All three AI endpoints return **503 "AI service not configured. Set GROQ_API_KEY."** (`api/ai.py:73,119,152`). Nothing else is affected. |
| `NVD_API_KEY` | NVD enricher | **Not declared in `render.yaml`** — add it if you want it. Unauthenticated NVD works at 5 req/30 s; a key raises it to 50. Without it CVE enrichment throttles rather than fails. |
| `SHODAN_API_KEY` | Shodan enricher | **Currently irrelevant** — as of 2026-08-17 the enricher is gated on the `shodan` library being importable, and it is commented out of `requirements.txt`. Setting the key alone will **not** register it. |
| `CVEDETAILS_ACCESS_TOKEN` | CVE Details enricher | **Not declared in `render.yaml`.** Paid subscription; the enricher is not registered without it. |

**The abuse.ch key mapping — one account key, four variables.** abuse.ch issues a single
Auth-Key per account. These all take **the same value**:

| Variable | Reader |
|---|---|
| `MALWAREBAZAAR_API_KEY` | `malwarebazaar` feed + the MalwareBazaar **enricher** (which is registration-gated on it) |
| `THREATFOX_API_KEY` | `threatfox` feed |
| `URLHAUS_API_KEY` | `urlhaus` feed |
| `YARAIFY_API_KEY` | YARAify enricher — **falls back to `MALWAREBAZAAR_API_KEY`** (`enrichers/__init__.py:168`), so you can leave it unset. **Not declared in `render.yaml`.** |

So: paste the one abuse.ch key into `MALWAREBAZAAR_API_KEY`, `THREATFOX_API_KEY` and
`URLHAUS_API_KEY`; skip `YARAIFY_API_KEY` and let the fallback handle it.

### 3.5.4 Build-time

| Variable | Handling | Notes |
|---|---|---|
| `MAXMIND_ACCOUNT_ID` | `sync: false` | **Declared — the earlier finding IS fixed.** Read by `download_geolite2.py` during `buildCommand`. |
| `MAXMIND_LICENSE_KEY` | `sync: false` | Same. |
| `PYTHON_VERSION` | `value: 3.11.9` | — |
| `GEOIP_DB_PATH` | `value: /opt/render/project/src/backend/data/GeoLite2-City.mmdb` | Must match the `disk.mountPath` (`geolite-data`, 1 GB). If they diverge the file is downloaded to a path nothing reads. |

> **UPDATED 2026-08-17.** `alembic upgrade head` has been **removed** from the build —
> it was redundant (§2 runs migrations from a developer machine) and it carried
> `|| echo "continuing"`, so a failed migration produced a *successful* deploy against an
> unmigrated database. A redundant line that swallows failures is worse than an absent
> one. `test_the_migration_is_not_run_from_the_build_command` keeps it out.
>
> **GeoLite2 still fails open, deliberately** — a missing geo database must degrade
> enrichment rather than block a deploy — but the warning is now banner-framed so it is
> not lost in pip output. Verified rather than assumed: with the file absent,
> `build_registry()` gates geoip out and `/cron-status` reports `geoip_database_missing`.
>
> **Original note, retained for the reasoning:**
> ```
> python download_geolite2.py || echo "⚠️  GeoLite2 download failed - continuing..."
> alembic upgrade head        || echo "⚠️  Database migration failed - continuing..."
> ```
> Both swallow failure. Consequences to know before you deploy:
> * A GeoLite2 failure (bad credentials, MaxMind outage) produces a **successful deploy
>   with no GeoIP database**. GeoIP is then unavailable for the **entire IP population**,
>   and `/cron-status` reports `geoip_database_missing` — admin-gated, so you must look.
> * A migration failure produces a **successful deploy against an unmigrated database**.
>   Per §2 you run migrations from a developer machine anyway, so this line is redundant;
>   consider removing it rather than leaving a swallowed failure in the deploy path.

### 3.5.5 Deliberately unset — setting these is the mistake

| Variable | Why unset | If you set it |
|---|---|---|
| `REDIS_URL` | The blueprint provisions no Redis. `utils/rate_limiter` falls back to **process-local** counters, which is correct **only** at one worker. | Pointing it at an unreachable Redis makes the limiter fail at request time. It is the correct fix *if* the worker count ever rises — but then five other single-process assumptions need revisiting together (see CLAUDE.md). |
| `DATABASE_ASYNC_URL` | Derived from `DATABASE_URL`. | Only set it deliberately, per §3.5.1 — a value inconsistent with `DATABASE_URL` means sync and async paths hit **different databases**, which will not announce itself. |
| `ALLOW_MULTIPLE_WORKERS` | Not in `config.py`; read directly by `main.py::_assert_single_worker`. | Setting it `true` disables the startup refusal and lets the six single-process subsystems degrade silently. |

### 3.5.6 Not declared in `render.yaml`, and fine as defaults

`JWT_ALGORITHM`, `JWT_EXPIRE_MINUTES` (720 = 12 h), `OTP_TTL_MINUTES` (5),
`OTP_RESET_TTL_MINUTES` (10), `OTP_MAX_ATTEMPTS` (5), `AUTH_RATE_LIMIT_MAX` (10),
`AUTH_RATE_LIMIT_WINDOW` (300 s), `DEFAULT_PAGE_SIZE` (50), `MAX_PAGE_SIZE` (500),
`CACHE_TTL_WHOIS/DNS/GEOIP/REPUTATION/DASHBOARD`, `FEED_SYNC_INTERVAL`.

`JWT_EXPIRE_MINUTES` is worth knowing rather than changing: at 12 h every tester logs in
at least twice a day, which is what makes Resend's 100/day free cap reachable.

### 3.5.7 Two audits you asked for

**Secrets handling — clean.** Every sensitive variable carries `sync: false` or
`generateValue: true`. The 13 literal values committed are all non-sensitive
(`PYTHON_VERSION`, `PORT`, `ENVIRONMENT`, `LOG_LEVEL`, `FEED_SYNC_INTERVAL`,
`GEOIP_DB_PATH`, `CORS_ORIGINS`, `ENABLE_API_DOCS`, `ENABLE_ERROR_EMAILS`, `EMAIL_FROM`,
`NODE_VERSION`, `NODE_ENV`). No credential is committed.

**MaxMind declaration — fixed.** Both variables are declared with `sync: false`, so the
build step has them. The `|| echo` fail-open remains, as above.

### 3.5.8 Three blockers in `render.yaml` before you create the service

1. ~~`region: oregon`~~ **FIXED 2026-08-17** — both blocks now `frankfurt`. Asserted by
   `test_every_service_is_in_frankfurt`, because region is immutable after creation and
   recreating the service is the only remedy.
2. ~~dead `fromService`~~ **FIXED 2026-08-17** — removed, with the reason recorded in
   place. `test_no_dead_fromservice_reference` now fails on any `fromService` naming a
   service the blueprint does not declare. The `sentinel-frontend` block is left as
   vestigial-but-harmless since the frontend deploys to Vercel.
3. **`plan: starter`, not `free`** — **still open, awaiting your decision.** Not changed.
   Worth confirming: the single-worker reasoning and the 512 MB / 0.1 CPU limits in
   `docker-compose.yml` were sized for a free instance.

4. ~~Blueprint rejected~~ **FIXED 2026-08-17.** Three things made it invalid or harmful
   on a free instance, all now removed with the reasons recorded in `render.yaml`:

   * **`disk:` block** — persistent disks are not available on free, which is what the
     Blueprint was rejected for. It was also actively wrong: it mounted at
     `/opt/render/project/src/backend/data`, byte-identical to the directory
     `GEOIP_DB_PATH` points into and where `download_geolite2.py` writes **at build
     time**. The disk would have mounted over the freshly-built `.mmdb` and hidden it, so
     GeoIP would have been missing despite a correct, correctly-credentialled download.
     A test now asserts no disk mount can contain the GeoIP path.
   * **`healthCheckInterval: 50` / `healthCheckTimeout: 10`** — commented "keep service
     alive", which is exactly the keep-alive this deployment must not have. A 50-second
     check means the instance never sleeps and burns ~744 of the 750 monthly hours; the
     four-window sync cadence is designed around it sleeping between windows. Render's
     defaults now apply. `healthCheckPath: /health` is kept — the endpoint is still wanted.
   * **The whole `sentinel-frontend` service** — the frontend deploys to Vercel, so it was
     vestigial, and leaving it meant Render creating a second free web service drawing
     from the same 750-hour pool.

5. **CREATE THE SERVICE FROM THE BLUEPRINT, NOT THE DASHBOARD FORM.** `backend/Dockerfile`
   exists, and Render's creation form auto-detects it — the owner reports the form
   defaulting to Docker. `render.yaml` declares `runtime: python`, so a blueprint-created
   service runs `buildCommand`. A Docker-created one does not, and both consequences are
   silent:

   * `download_geolite2.py` never executes, so there is no GeoIP for the **entire IP
     population**. The Dockerfile creates `/app/data` but downloads nothing into it.
   * `GEOIP_DB_PATH` (`/opt/render/project/src/backend/data/...`) does not exist inside
     the image at all — the Dockerfile's `WORKDIR` is `/app`.

   If you must create it by hand, choose the **Python** runtime explicitly and paste the
   `buildCommand`. `test_the_backend_declares_the_python_runtime` guards the blueprint
   side; nothing can guard the dashboard side, which is why it is written here.

---

## 4. Deploy the service

> ### 4.0 CUTOVER — DONE 2026-08-17, and one constraint that outlives it
>
> All three references to the old origin (`wiestellthreatintelligencebackend.vercel.app`)
> were repointed to **`https://wiestell-backend.onrender.com`**. Verified: zero
> occurrences of the old host remain in tracked files.
>
> | File | What it is now |
> |---|---|
> | `frontend/vercel.json` | destination repointed — **still a committed literal, see below** |
> | `frontend/next.config.js` | fallback repointed; `NEXT_PUBLIC_API_URL` still wins |
> | `scripts/verify-security-headers.sh` | default repointed; `BACKEND_URL` / `$2` still win |
>
> #### `vercel.json` CANNOT reference an environment variable, and that is why it was the one that got missed
>
> Vercel does not interpolate environment variables into `rewrites` destinations — they
> are static strings. There is no `$VAR` or `${VAR}` form that works there. **So this
> origin is committed to the repository and every future cutover is a CODE CHANGE**:
> edit, commit, push, redeploy. It cannot be done from the Vercel dashboard, and nothing
> about the dashboard hints that it can't.
>
> That asymmetry is the whole trap. The other two references read an environment variable
> first, so an operator who sets `NEXT_PUBLIC_API_URL` sees two of the three obey and
> reasonably concludes the cutover is done — while `vercel.json`'s rewrite, applied at
> **Vercel's edge before the Next.js function**, keeps sending traffic to the old origin.
> Every signal says success; the traffic disagrees.
>
> - [ ] **At any future backend move, grep for the origin — do not trust the env var.**
>       `git grep -n "onrender.com"` is the check.
> - [ ] Set `NEXT_PUBLIC_API_URL` in the **Vercel** dashboard as well. It governs
>       `next.config.js` and is read at BUILD time, so changing it needs a redeploy, not
>       just a save.
>
> **Why the duplication is kept rather than removed.** Deleting the `vercel.json` rewrite
> and relying solely on `next.config.js` would make the origin fully env-driven — but the
> two are not equivalent: a `vercel.json` rewrite is handled at the edge and never invokes
> the Next.js function, while a `next.config.js` rewrite routes through it. That is a real
> latency and invocation-count difference, so removing it is a decision about routing, not
> a cleanup. Left as-is, documented.

## 5. Wire the cron

- [ ] Set the `API_BASE_URL` repository **variable** and `CRON_SECRET` repository **secret**
      for `.github/workflows/feed-sync.yml`. `CRON_SECRET` must match Render's exactly —
      `require_admin_or_cron` compares with `hmac.compare_digest` and an empty server-side
      secret never matches.
- [ ] Trigger `workflow_dispatch` once and read the response body. It carries per-feed
      status; a 200 with every feed failing is the shape to look for.
- [ ] Confirm the cron interval still matches `_GOVERNING_SYNC_INTERVAL_SECONDS`.
      `tests/test_deploy_config.py` asserts this, so it should already hold — the manual
      check is for the case where the schedule was changed in the dashboard rather than
      the file.

## 6. Scoring: the two-part deployment

**This is the part most easily got wrong, because the code deploy looks like the whole job.**

Deploying the code changes *how a score is computed*. It changes **nothing already stored**:
ingestion skips rows whose evidence has not changed, and the enrichment cron selects only
never-enriched IOCs. `SCORING_MODEL_VERSION` is **9**; stored values were written under
version 1 or whichever intermediate version was live when a row was last touched.

So until the rescore runs, **the dashboard ranks rows scored under at least four different
models against each other** — "top threats", the critical tile, the ≥76 filter and every
sort by `threat_score`. That is not stale data; it is an unsound triage surface, and it
cannot be demonstrated to a UAT audience as-is. (§8 item 16)

- [ ] Deploy the code (§4 above).
- [ ] **Set the environment first — the script raises immediately without it.** It imports
      `app.config`, which has no default for `DATABASE_URL`, so this is a hard stop rather
      than a degraded run.

      ```powershell
      # PowerShell (the owner's shell). `VAR=value cmd` is a parse error here.
      cd backend
      $env:DATABASE_URL = "mysql+pymysql://user:pass@host/db"
      $env:SECRET_KEY = python -c "import secrets; print(secrets.token_urlsafe(48))"
      ```
      ```bash
      # bash / zsh
      cd backend
      export DATABASE_URL="mysql+pymysql://user:pass@host/db"
      export SECRET_KEY="$(python -c 'import secrets;print(secrets.token_urlsafe(48))')"
      ```
- [ ] `python ../scripts/rescore_corpus.py --dry-run` — gives the score distribution **and** a
      timing sample. **Multiply that sample by at least 1.33× before trusting it**: the dry
      run skips the UPDATE, so it is 3 statements per chunk against the write pass's 4, and
      writes cost more than reads on a shared host. Treat it as a lower bound.
- [ ] Review the distribution before writing. A large shift in the wrong direction is
      easier to investigate now than to unpick afterwards.
- [ ] Run the write pass. Budget from the §5.4.1 table — at 200,000 rows this is **1–2¼
      hours** from a developer machine against Hostinger — **not on Render**, which on the free plan has no shell to run it from and would spin down mid-run anyway. Resumable via `--start-after` and idempotent,
      so an interruption recovers rather than restarts.
- [ ] **Only now** populate any `manual_score_override` values. Set earlier and those rows
      are skipped by the rescore permanently.
- [ ] **Schedule the second rescore** as part of Phase 4, in the same change set as the
      `WHERE Enrichment.id IS NULL` fix. A rescore recomputes from *stored* enrichment
      payloads, and legacy rows carry no `assessed`, so they route through
      `_legacy_assessed` — deliberately conservative, assessing nothing where it cannot
      tell. Those scores change again once the rows refresh. This is a known planned cost,
      not a defect. (§5.4.2)

## 6.5 What Phase 4 changed, and what G asks of you

Sections A–E shipped between 2026-08-17 and this deploy. What behaves differently:

| | before | after |
|---|---|---|
| next-due computed from | `last_sync_at` (at completion) | `last_attempt_at` (at **start**) |
| a failing feed | retried every window forever | backs off 2× per failure, capped at 3 days |
| `last_sync_at` on failure | advanced, so a dead feed looked healthy | frozen at last success |
| an unchanged file | re-downloaded and re-parsed | `304` → status `no_change`, nothing ingested |
| OTX | re-fetched a fixed 7-day window | resumes from `sync_cursor` |
| enrichment refresh | never-enriched only | + expired rows, minus error payloads |
| Shodan | registered without its library | gated out; 5,947 rows now orphaned |

**`no_change` is a new `last_sync_status` value.** Feed health must not render it as
broken — a feed reporting `no_change` for three days is working correctly. If the
dashboard only knows `success` / `failed` / `no_data`, that is a UI gap to close before
UAT, not a feed problem.

### Section G — seeding the three feeds, and the wall-clock it costs

`cisa-kev`, `ecrimelabs-metasploit` and `misp-cert-fr` have never been seeded, so
production has never ingested either CVE source. Seeding them is §3 above. **The cost is
elapsed time, not effort**, and it gates the rescore:

| feed | seeded cadence | first sync after seeding |
|---|---|---|
| `misp-cert-fr` | 21,600 s (**6 h**) | within 6 h |
| `cisa-kev` | 86,400 s (**24 h**) | within 24 h |
| `ecrimelabs-metasploit` | 86,400 s (**24 h**) | within 24 h |

**Up to 24 hours**, not 72 — the three-day figure is the back-off *cap*, which applies
only to a feed that is failing. A newly seeded row has `last_attempt_at = NULL`, so it is
immediately overdue and syncs on the **first** cron run after seeding. The 24 h is the
worst case if that run is missed.

**Or force it:** `POST /api/v1/feeds/sync-all?force=true` ignores cadence entirely and
syncs every enabled feed now. That is the pragmatic route — it turns "wait up to a day"
into one request — at the cost of syncing all 11 feeds at once rather than spreading them.

- [ ] Seed the three feeds (§3).
- [ ] Let each complete **one full sync** — check `last_sync_status = 'success'` and
      `ioc_count > 0` for all three, not just that time has passed.
- [ ] **Only then** run the rescore (§6). Seeding changes `source_count` for any indicator
      the new feeds also report, which moves the diversity term. Rescoring first means
      rescoring twice.

## 7. After the first sync

- [ ] Check `feed_sources.last_sync_status` per feed. `BaseFeed.run()` lets exceptions
      propagate so a real failure records `failed` rather than a misleading `no_data` —
      trust the distinction.
- [ ] Check `last_ingest_gap`. A non-zero value means records may have aged out of a rolling
      window between syncs, which is the signal the cron interval is too slow for that feed.
- [ ] Re-run §5.4's corpus counts. The tagged-IOC count is what makes the `/attack/*` sizing
      in §8 item 17 real rather than provisional — if the tagged population is already past
      ~100,000, the `ioc_techniques` join table (§6.1) stops being an improvement and
      becomes the fix.
- [ ] Spot-check the `enrichments` table for `geoip` rows carrying `error_city`. Existing
      ones do **not** clear themselves even after MaxMind is provisioned — the freeze trap
      means they are never re-enriched. Clearing them is a separate production write needing
      its own sign-off.

## 8. Known-open, so nobody reports them as new

- `/login` has no per-account attempt counter; correct `X-Forwarded-For` handling cannot
  substitute for one. (SECURITY_REVIEW item 8 — needs a migration, so blocked behind §2)
- OTX reputation is mis-scaled: one pulse reads 10, below the 30.0 no-evidence neutral, and
  an AbuseIPDB confidence of 5 reads 5. Positive verdicts can still score safer than
  silence. (§8 item 15)
- Provider corroboration is measured nowhere in the composite. Deliberate and explicit
  rather than fixed. (§8 item 15)
- Two background mechanisms exist; only the HTTP cron runs. Do not assume a change to the
  asyncio scheduler affects production. (Celery was the third and was deleted 2026-08-17.)
- Feed cadence drifts by one cron period when `sync_frequency` is a multiple of the cron
  interval. (§8 item 12 — Phase 4)
