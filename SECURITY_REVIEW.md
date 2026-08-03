# Security Review — Wiestell Threat Intelligence Platform

**Repository:** `Wiestell_threatIntel_platform` (branch `Master`)
**Review date:** 2026-07-28
**Scope:** full codebase — FastAPI backend, Next.js frontend, Docker/nginx/Render/Vercel configuration, Alembic migrations, operational scripts.
**Method:** manual code review of every source file, dependency CVE review, and scripted verification of the fixes (route-guard audit, security logic suite, HTTP access-control suite via `TestClient`, `tsc --noEmit`, `next build`).

Companion document: [PROJECT_SUMMARY.md](PROJECT_SUMMARY.md).

---

## Executive summary

The platform was **effectively unauthenticated and unauthorized**. Authentication existed on paper — password + email OTP + JWT — but it was enforced only by React route guards in the browser. Every one of the 53 non-public API endpoints could be called with `curl` and no credentials, including `POST /api/v1/users`, which minted an **admin** account for anyone who asked. In parallel, live production database credentials and an SMTP password were committed in plaintext to a repository with a public GitHub origin.

**23 findings** were identified: **6 critical, 8 high, 7 medium, 2 low**. **All 23 are fixed** in this change set. Nothing was deferred.

| Severity | Count | Fixed |
|---|---|---|
| Critical | 6 | 6 |
| High | 8 | 8 |
| Medium | 7 | 7 |
| Low | 2 | 2 |

Two findings require action that cannot be performed from the codebase and are the operator's responsibility:

> ### ⚠️ Credential rotation is mandatory
> The MySQL password `C9b>;xrFy` for user `u433859718_wiest_tell` on `193.203.184.197`, and the SMTP password for `noreply@wiestell.com`, were committed in plaintext. They are removed from the working tree but **remain in git history and in any clone, fork or CI cache**. Removing them from the current files does not make them secret again.
>
> 1. Rotate the MySQL password now, and restrict the database user to the application's source IPs.
> 2. Rotate the `noreply@wiestell.com` mailbox password now.
> 3. Rotate any feed/enrichment API keys that were ever placed in a committed file.
> 4. Purge history (`git filter-repo` or BFG) and force-push, or treat the repository as permanently compromised for these values.
> 5. Review MySQL and mail logs for unauthorized access during the exposure window.

---

## Findings

Severity uses CVSS-style reasoning: impact × exploitability, assuming an internet-reachable deployment.

### CRITICAL

---

#### C-01 — Live production database credentials committed to the repository
**Files:** `backend/app/config.py:12-13`, `docker-compose.yml:20,54,78`, `render.yaml:37,39`

The MySQL DSN — host, database, username and password — was a **default value in code**, not just in deployment config:

```python
DATABASE_URL: str = "mysql+pymysql://u433859718_wiest_tell:C9b%3E%3BxrFy@193.203.184.197/..."
```

**Failure scenario.** Anyone with read access to the repository (public GitHub origin, any fork, any CI log) connects directly to the MySQL host and reads or destroys the entire IOC corpus, the user table with its bcrypt hashes, and every contact submission. The default also meant a deployment that forgot to set `DATABASE_URL` would silently connect to production.

**Fix.** `DATABASE_URL` is now a required field with no default — a missing value raises at import. Credentials removed from `docker-compose.yml` (now `${DATABASE_URL:?required}`) and `render.yaml` (now `sync: false`, set in the dashboard).

---

#### C-02 — SMTP password committed in code and in `.env.example`
**Files:** `backend/app/config.py:56`, `.env.example:18`

`EMAIL_PASSWORD: str = "q9#pcv5aC~"` shipped in the settings class, and the same value was pasted into the example env file that exists precisely so real secrets stay out of the repo.

**Failure scenario.** An attacker authenticates to `smtp.hostinger.com` as `noreply@wiestell.com` and sends mail that passes the domain's SPF/DKIM — including password-reset emails that look genuine to Wiestell's own users.

**Fix.** All SMTP settings default to empty and come from the environment. `.env.example` was rewritten with placeholders only. `send_*_email()` now returns `False` early when SMTP is unconfigured instead of attempting a login with empty credentials.

---

#### C-03 — Entire API unauthenticated; anyone could create an admin account
**Files:** `backend/app/api/__init__.py`, and every router

No endpoint carried an authentication dependency. Only `/users/me*` parsed a token, and it did so with hand-rolled header parsing repeated in three places. Authorization did not exist server-side at all: the `role` column was written, never read.

Directly reachable with no credentials:

```
POST   /api/v1/users              → create a user with "role": "admin"   ← privilege escalation
GET    /api/v1/users              → every user record
PUT    /api/v1/users/{id}         → change any user's email
GET    /api/v1/contact/messages   → every contact submission (names, emails, messages)
DELETE /api/v1/feeds/{id}         → destroy feed configuration
POST   /api/v1/feeds/sync-all     → drive unbounded feed + enrichment workload
POST   /api/v1/enrichment/backfill/start → same, up to 50,000 IOCs
POST   /api/v1/ai/chat            → unlimited spend on the Groq API key
GET    /api/v1/iocs, /dashboard/*, /reports/*, /attack/*  → all intelligence data
```

**Failure scenario.** One unauthenticated `POST /api/v1/users` with `{"role": "admin"}` yields a working admin login (the account is created active, no OTP needed). Full takeover requires a single request. The React guards are irrelevant — they run in the attacker's browser, which the attacker controls.

**Fix.** New `backend/app/api/deps.py` provides `get_current_user` (validates the bearer token, loads the user, rejects disabled accounts), `require_roles(...)`, `require_admin`, `require_analyst` and `require_admin_or_cron`. Authentication is applied **at router registration** so a newly added endpoint inherits a safe default rather than being public by omission, with role dependencies on individual privileged routes:

| Surface | Requirement |
|---|---|
| `/users/register`, `/login`, `/verify-otp`, `/forgot-password`, `/reset-password`, `POST /contact/submit`, `/health`, `/` | public (rate limited) |
| IOC/dashboard/report/ATT&CK/AI reads, `GET /feeds`, feed logs, enrichment reads | authenticated |
| IOC create, tag edit, enrichment trigger, report generate, AI report | analyst or admin |
| Feed create/update/delete/sync, user administration, contact inbox, `/cron-status` | admin |
| `POST /feeds/sync-all`, `POST /enrichment/backfill/start` | admin **or** `X-Cron-Secret` |

Self-service registration is also pinned to `viewer` regardless of the submitted `role`, so the escalation path is closed even if the endpoint were reachable.

**Verified:** a scripted audit walks the live route table and asserts every route is guarded unless explicitly allowlisted — *62 routes = 53 guarded + 9 public, 0 unexpectedly public*. An HTTP suite confirms 23 representative endpoints return 401/403 anonymously, and that a viewer is refused admin and analyst-only routes while an admin succeeds.

---

#### C-04 — OTP returned in the HTTP response body
**File:** `backend/app/api/users.py` (login, register, forgot-password)

When email delivery failed, the endpoint returned the code to the caller:

```python
if not email_sent:
    return OTPResponse(message=f"OTP generated but email failed. For demo: {otp_code}")
```

**Failure scenario.** The attacker calls `POST /forgot-password` for a known admin address. If SMTP is down, misconfigured, rate-limited by the provider, or simply not configured in that environment, the reset code comes back in the JSON — and `POST /reset-password` then sets a new password. The second factor is bypassed entirely, and the failure mode is attacker-influenceable (flood the mailbox to induce a provider rejection). Codes were also `print()`ed to stdout on **every** success, so any log reader could authenticate as anyone.

**Fix.** The code is never returned and never logged. Delivery failure produces `503` for login/registration and is silently swallowed for password reset (so the endpoint stays a non-oracle). The email helper logs `otp_email_sent` with no address and no code.

---

#### C-05 — OTP purpose confusion: a password-reset code granted a session
**File:** `backend/app/api/users.py`

`verify_otp` selected *any* pending OTP for an email address, and `reset_password` did the same. OTPs carried no purpose. The rows were also never bound to a single use case, and `verify_otp` unconditionally set `user.is_active = True`.

**Failure scenarios.**
1. A password-reset code (10-minute TTL, obtainable by anyone who can trigger `/forgot-password`) could be posted to `/verify-otp` and exchanged for a **24-hour JWT** — a reset flow becomes a login flow.
2. Conversely a login code could be posted to `/reset-password`.
3. Any successful OTP verification **re-enabled a deliberately disabled account**, defeating offboarding: disable a departing analyst, they log in, the account reactivates.

**Fix.** The `otps` table gained a `purpose` column (`login` / `signup` / `password_reset`) and lookups are purpose-scoped. `/verify-otp` accepts only `login` and `signup`; `/reset-password` accepts only `password_reset`. Reset additionally asserts the OTP's `user_id` matches the resolved user. Codes are single-use (marked `verified`). `verify_otp` no longer reactivates accounts — a disabled user gets `403`. Migration: `d4e5f6a70001_harden_otp_table`.

---

#### C-06 — Predictable default JWT signing key
**Files:** `backend/app/config.py:32`, `docker-compose.yml`

`SECRET_KEY: str = "change-me-in-production"` was the default, and `docker-compose.yml` supplied the same string as its fallback. Tokens are HS256, so the signing key is also the verification key.

**Failure scenario.** An attacker who assumes the default (it is in this repository, and in every fork) forges `{"sub": "<any-user-id>", "exp": <future>}` offline and is authenticated as anyone, including an admin. No network interaction with the auth flow is needed.

**Fix.** No default. In production, a missing/placeholder/short (<32 char) key **raises at startup** with instructions to generate one. In development an ephemeral random key is generated per process, so tokens never survive a restart and no shared secret exists in source. `docker-compose.yml` uses `${SECRET_KEY:?required}`; `render.yaml` uses `generateValue: true`.

**Verified:** `Settings(..., ENVIRONMENT="production", SECRET_KEY=x)` raises for `""`, `"change-me-in-production"` and `"short"`.

---

### HIGH

---

#### H-01 — No brute-force protection on credential or OTP endpoints
**Files:** `backend/app/api/users.py`, `nginx/nginx.conf`

A 6-digit OTP is 1,000,000 possibilities with a 5-minute window and **unlimited attempts**. There was no per-IP limit, no per-account attempt counter and no nginx limit. Password login was equally unlimited. (`utils/rate_limiter.py` existed but was only used for outbound third-party API pacing.)

**Failure scenario.** After triggering an OTP for a target account, an attacker submits codes as fast as the server responds. At a few hundred requests per second the whole keyspace is covered well inside the TTL, so the second factor is defeated by brute force alone.

**Fix.** Three layers: (1) per-IP dependency limits on `login`, `register`, `verify-otp`, `forgot-password`, `reset-password` and `contact/submit` (Redis-backed sliding window, in-process fallback); (2) a per-OTP `attempts` counter that locks the code after `OTP_MAX_ATTEMPTS` (default 5); (3) an nginx `limit_req` zone at 1 r/s with burst 5 on the auth paths specifically, plus 30 r/s generally.

**Residual risk — what actually protects production (restated 2026-07-29).** Only layer (2) is unconditionally effective. Layers (1) and (3) are both weaker than the description above implies:

- **nginx is not in the Render request path.** `nginx/nginx.conf` applies to the `docker-compose` topology only. Production runs the API on Render, which routes to the container directly, so the `limit_req` zones are not enforced at all in the deployment that matters. Layer (3) is a development-and-self-host control, not a production one.
- **The in-memory limiter does not coordinate.** Without `REDIS_URL` set, `rate_limit()` falls back to a per-process dictionary. Render can run multiple instances, and each serverless-style process keeps its own counters, so the effective limit is `AUTH_RATE_LIMIT_MAX × number of live processes` — and a process recycle resets it to zero. The limit is therefore a nuisance barrier rather than a bound.

The per-OTP `attempts` counter is the control that actually defeats the brute-force scenario, because it lives in the database and is shared by every process. Sizing the OTP keyspace or the TTL on the assumption that layers (1) and (3) hold would be a mistake. Provisioning Redis and putting a rate limiter in front of Render (or moving to a platform-level WAF rule) is the outstanding work.

> **How much of that is actually live in production.** Only layer (2) unconditionally.
>
> * Layer (3) requires nginx to be in the request path. Production runs on Render/Vercel, where it is not — `nginx/nginx.conf` covers the Docker Compose deployment only.
> * Layer (1) is only global when `REDIS_URL` is configured. Without it the limiter falls back to an in-process token bucket, which does not coordinate across serverless instances or worker processes; on Vercel each invocation may start with a fresh bucket.
>
> So in the current production topology, **OTP brute force is bounded by the per-code attempt counter (the strongest of the three), but password login has no effective rate limit.** Configuring `REDIS_URL` closes it. This is the same issue as residual risk #5 and is restated here because the finding should not read as fully mitigated.

---

#### H-02 — Exception details and request headers leaked to clients and email
**Files:** `backend/app/main.py:106-113`, `backend/app/api/contact.py:50`, `backend/app/api/feeds.py`

The 500 handler returned `error_type` to the client always, and the exception message whenever `ENVIRONMENT == "development"`. The contact endpoint returned `f"...: {str(e)}"` unconditionally. The alert email embedded `dict(request.headers)` **verbatim** and the full traceback.

**Failure scenarios.**
1. `str(exc)` on a SQLAlchemy `OperationalError` contains the connection URI including the password — an attacker who can trigger a DB error harvests the DSN.
2. Every alert email carried the victim's `Authorization: Bearer <jwt>` and cookies through SMTP to an external mailbox — a session token exfiltration channel that fires on any unhandled error.
3. Exception type and traceback fingerprint the ORM, driver and file layout for a follow-up attack.

**Fix.** New `backend/app/utils/sanitize.py`. The handler returns only `{"detail": "Internal server error", "error_id": "<12 hex>"}`; the id correlates to a full server-side log entry. `redact_headers()` masks `Authorization`, `Cookie`, `X-Api-Key`, `X-Cron-Secret` and similar; `redact_secrets()` rewrites `scheme://user:password@host` to `scheme://user:***REDACTED***@host` and masks every configured secret by value. Redaction is applied to logs, alert emails, the persisted `feed_sources.last_sync_error` column (both on write and on serialization) and `/cron-status`. Alert emails are now opt-in (`ENABLE_ERROR_EMAILS=false` by default) and HTML-escaped.

**Verified:** `redact_secrets("...mysql+aiomysql://dbuser:S3cr3tPw@10.0.0.5/tip")` drops the password and keeps the username; a header dump containing a real JWT and cookie comes back masked while `User-Agent` survives.

---

#### H-03 — Arbitrary environment variable read → secret exfiltration via feed config
**Files:** `backend/app/services/feed_scheduler.py:87`, `backend/app/schemas/feed.py`

A feed row's `api_key_env` was dereferenced with no validation:

```python
api_key = os.environ.get(feed.api_key_env) or getattr(settings, feed.api_key_env, None)
```

and `POST /api/v1/feeds` (unauthenticated, per C-03) accepted any string for it. The resolved value is then sent to the feed's third-party endpoint as an API key — for example as the `Auth-Key` header to `mb-api.abuse.ch`.

**Failure scenario.** Create a feed with `slug: "malwarebazaar"` and `api_key_env: "SECRET_KEY"` (or `DATABASE_URL`, or `EMAIL_PASSWORD`), trigger a sync, and the platform transmits its own JWT signing key or database DSN to an external host. With the signing key the attacker forges admin tokens; the value also lands in the third party's logs, outside Wiestell's control.

**Fix.** `ALLOWED_FEED_API_KEY_ENVS` in `config.py` enumerates the legitimate feed-key variables. A Pydantic validator rejects anything else on create **and** update, and `feed_scheduler` re-checks at read time so pre-existing malicious rows cannot fire. The feed slug is also constrained to `^[a-z0-9-]+$`.

**Narrowed 2026-07-29: 11 names → 5, a 55% reduction in this surface.** The allowlist had grown to hold every third-party key in `Settings`, most of which no feed row could ever reach. Audited against what each surviving connector class actually declares:

| Removed | Why it was unreachable |
|---|---|
| `VT_API_KEY`, `PHISHTANK_API_KEY` | connector modules deleted with the feeds |
| `SHODAN_API_KEY`, `NVD_API_KEY`, `YARAIFY_API_KEY`, `CVEDETAILS_ACCESS_TOKEN` | **enricher-only.** Read from `settings` directly in `enrichers/__init__.py::build_registry` and the enricher constructors. No `BaseFeed` subclass declares them, so no `feed_sources` row could cause them to be dereferenced or forwarded. |

What remains is exactly the five names a live connector reads: `OTX_API_KEY` and `ABUSEIPDB_API_KEY` (required), plus the optional abuse.ch keys `THREATFOX_API_KEY`, `MALWAREBAZAAR_API_KEY` and `URLHAUS_API_KEY`. The four enricher keys stay in `Settings` and in the redaction list — only their reachability from a feed row is withdrawn.

`tests/test_feeds.py::TestApiKeyEnvAllowlist::test_allowlist_matches_the_surviving_connectors` asserts the set equals the connector-declared set in both directions, so re-widening it without a connector that reads the key fails the suite.

**Verified:** `FeedCreate(api_key_env=...)` raises for `"SECRET_KEY"`, `"DATABASE_URL"`, `"EMAIL_PASSWORD"`, `"PATH"` and `"HOME"`, and — since the 2026-07-29 narrowing — also for the six withdrawn names (`"VT_API_KEY"`, `"PHISHTANK_API_KEY"`, `"SHODAN_API_KEY"`, `"NVD_API_KEY"`, `"YARAIFY_API_KEY"`, `"CVEDETAILS_ACCESS_TOKEN"`). `"OTX_API_KEY"` and the other four connector-declared names are accepted.

---

#### H-04 — CORS wildcard combined with credentialed requests
**File:** `backend/app/main.py:48-58`

`allow_origins=["*"] if settings.CORS_ORIGINS == "*"` together with `allow_credentials=True`. Starlette resolves that combination by **reflecting the requesting origin**, which is strictly worse than a literal `*`: it makes credentialed cross-origin reads succeed from any site. `allow_methods=["*"]` and `allow_headers=["*"]` were also unnecessarily broad.

**Failure scenario.** With `CORS_ORIGINS=*` set (the documented escape hatch), any page a logged-in analyst visits can script authenticated requests against the API and read the responses — full intelligence exfiltration and state change from a drive-by page.

**Fix.** `settings.cors_origin_list` filters `*` out entirely, so a wildcard cannot be configured. Methods and headers are enumerated explicitly. A warning is logged if no origins are configured.

---

#### H-05 — Interactive API docs and OpenAPI schema public in production
**Files:** `backend/app/main.py:42-44`, `nginx/nginx.conf`

`/docs`, `/redoc` and `/openapi.json` were served unconditionally, publishing every route, parameter and schema — and, given C-03, a working "Try it out" console against an unauthenticated API.

**Fix.** Gated behind `settings.docs_enabled` (`ENABLE_API_DOCS`, default `false`, auto-enabled in development). When disabled, FastAPI is constructed with `docs_url=None, redoc_url=None, openapi_url=None`. nginx additionally returns 404 for all three paths. `render.yaml` sets `ENABLE_API_DOCS=false`.

---

#### H-06 — Unauthenticated resource-exhaustion and third-party cost abuse
**Files:** `backend/app/api/feeds.py`, `enrichment.py`, `ai.py`, `ioc.py`

`POST /feeds/sync-all` (fetches every feed, then enriches up to 500 IOCs), `POST /enrichment/backfill/start` (up to 50,000 IOCs, each fanning out to WHOIS/DNS/VirusTotal/Shodan) and the Groq-backed AI endpoints were all anonymous. `GET /iocs/lookup` created and enriched an IOC on every cache miss.

**Failure scenario.** Repeated anonymous calls saturate the connection pool and the shared MySQL host, burn the platform's VirusTotal/Shodan/AbuseIPDB quotas (denying enrichment to legitimate analysts and risking key bans), and run up an unbounded Groq bill. `POST /iocs/lookup?value=<attacker-chosen>` also makes the platform issue outbound requests to arbitrary attacker-named hosts.

**Fix.** Maintenance endpoints require admin or the cron secret. AI endpoints are authenticated and rate limited (chat 30/5 min, analyze 20/5 min, report 5/10 min and analyst-only). `GET /iocs/lookup` is authenticated and capped at 60/min per caller.

---

#### H-07 — Content-Security-Policy was report-only
**File:** `frontend/next.config.js:15-17`

The header was `Content-Security-Policy-Report-Only`, which enforces nothing. `object-src 'none'`, `frame-ancestors 'none'`, `base-uri` and `form-action` were advisory.

**Failure scenario.** Because the session token lives in `localStorage`, any successful script or object injection reads it directly — and the policy that was meant to contain the injection was switched off.

**Fix.** Switched to the enforcing `Content-Security-Policy` header. `'unsafe-inline'` is retained for `script-src` because the Next.js App Router emits inline hydration and JSON-LD without a nonce — documented in the config as the remaining gap. The deprecated `X-XSS-Protection` header (which can itself introduce issues) was removed, and `poweredByHeader: false` was set.

---

#### H-08 — Health and cron-status endpoints disclosed internal state
**Files:** `backend/app/main.py`

`/api/v1/health` returned the `ENVIRONMENT` name and database reachability. `/api/v1/cron-status` was fully public and returned **`feed.last_sync_error` verbatim** for every feed, alongside the full schedule and platform details.

**Failure scenario.** `last_sync_error` is populated from raw driver exceptions, so a public endpoint could serve `(pymysql.err.OperationalError) ... mysql+aiomysql://user:password@host/db` — the database credentials, with no authentication and no error needed at request time.

**Fix.** `/cron-status` requires admin, and its error strings pass through `redact_secrets()` (as does the `FeedResponse.last_sync_error` serializer, covering `GET /feeds`). `/health` keeps the database up/down signal for orchestrators but no longer names the environment or returns error text.

---

### MEDIUM

---

#### M-01 — OTPs generated with a non-cryptographic RNG and stored in plaintext
**File:** `backend/app/api/users.py:35`

`random.choices(string.digits, k=6)` uses the Mersenne Twister, which is fully reconstructible from observed output; codes were then stored plaintext in `otps.otp` and compared with `!=` (non-constant-time).

**Fix.** `secrets.choice` for generation; storage is a `SECRET_KEY`-keyed, email-bound SHA-256 HMAC (so a database read yields nothing replayable, and a code cannot be moved between accounts); comparison uses `hmac.compare_digest`. The `otp` column was widened to 255 in migration `d4e5f6a70001`, which also deletes pre-existing plaintext rows.

**Verified:** 200/200 generated codes unique; the stored digest differs from the code, is stable, and changes with the email address.

---

#### M-02 — Weak password policy; bcrypt truncation accepted silently
**File:** `backend/app/schemas/user.py`

Minimum length 6, no complexity requirement, maximum 128. bcrypt ignores everything past 72 bytes, so a 128-character passphrase was silently truncated while the UI implied it was honoured.

**Fix.** Minimum 12 characters, at least three of {lowercase, uppercase, digit, symbol}, and a hard 72-**byte** ceiling so nothing is silently dropped. Applied to registration, admin creation, password change and reset. `email` fields upgraded from a loose regex to `EmailStr`; `username` constrained to `^[A-Za-z0-9._-]+$`; OTP fields constrained to `^\d{6}$`.

---

#### M-03 — Account-status oracle on login
**File:** `backend/app/api/users.py:107`

A disabled account returned `403 "Account is disabled"` while a wrong password returned `401`, and a nonexistent email skipped bcrypt entirely — a timing side channel on top of the status difference.

**Fix.** Unknown email, wrong password and disabled account all return the same `401 "Invalid email or password"`. `pwd_context.dummy_verify()` burns equivalent hashing time when no account exists, and the distinguishing detail goes to the structured log instead.

---

#### M-04 — CSV export vulnerable to spreadsheet formula injection
**File:** `backend/app/api/ioc.py` (`export_iocs`)

IOC values come from untrusted third-party feeds and were written unescaped into CSV.

**Failure scenario.** A feed (or an analyst-submitted IOC) contains `=cmd|'/c calc'!A1`. An analyst exports and opens the file in Excel/LibreOffice and the payload executes on their workstation — the SOC's own tooling becomes the delivery mechanism.

**Fix.** `_csv_safe()` prefixes any cell starting with `= + - @`, tab or CR with a single quote. Applied to every exported field.

**Verified:** four representative payloads are neutralised; `1.2.3.4` is untouched.

---

#### M-05 — Prompt injection surface in the AI endpoints
**File:** `backend/app/api/ai.py`

`ChatMessage.role` was an unvalidated `str` passed to Groq, `content` and `context` were unbounded, and the message list had no length cap.

**Failure scenario.** A caller sends `{"role": "system", "content": "..."}` and overrides the assistant's instructions; unbounded content and list length additionally make each request arbitrarily expensive.

**Fix.** `role` is constrained to `^(user|assistant)$`, `content` to 8,000 chars, `context` to 4,000, and the list to 1–40 messages. (`groq_service.chat` already coerced unknown roles to `assistant`; the schema now rejects them outright.)

**Verified:** `ChatRequest` with a `system` role raises.

---

#### M-06 — Outdated dependencies with known CVEs
**File:** `backend/requirements.txt`

| Package | Was | Now | Issue |
|---|---|---|---|
| `python-jose` | 3.3.0 | **removed** → `pyjwt==2.10.1` | Unmaintained; CVE-2024-33663 (algorithm confusion), CVE-2024-33664 (JWE decompression bomb) |
| `fastapi`/starlette | 0.109.2 | 0.115.6 | CVE-2024-47874 — multipart DoS |
| `python-multipart` | 0.0.9 | 0.0.18 | CVE-2024-53981 — DoS on malformed multipart |
| `aiohttp` | 3.9.3 | 3.11.11 | Request smuggling / DoS fixes |
| `pymysql` | 1.1.0 | 1.1.1 | CVE-2024-36039 — SQL injection via crafted dates |
| `jinja2` | 3.1.3 | 3.1.5 | Sandbox breakout fixes |
| `bcrypt` | 3.2.2 | 4.2.1 | Passlib-compatibility and maintenance |
| `aioredis` | 2.0.1 | **removed** | Unmaintained since 2022; merged into `redis-py` |
| `cryptography`, `sqlalchemy`, `alembic`, `celery`, `pydantic`, `httpx`, `dnspython`, `structlog`, `tenacity`, `croniter`, `weasyprint`, `pandas`, `groq` | — | current | Routine maintenance |

The JWT migration is a code change, not just a version bump: `deps.py` uses `pyjwt` with an explicit `algorithms=[...]` allowlist and `options={"require": ["exp", "sub"]}`.

---

#### M-07 — Unbounded pagination and unvalidated filters on the contact inbox
**File:** `backend/app/api/contact.py`

`page` and `page_size` were plain `int` defaults with no bounds, and `status` was unvalidated. `page=0` produced a negative `OFFSET` (a driver error), `page_size=10000000` attempted to serialise the whole table, and `notes` on the resolve endpoint was a query parameter (landing in access logs).

**Fix.** `page ≥ 1`, `1 ≤ page_size ≤ 200`, `status` restricted to `pending|in-progress|resolved` with a 400 otherwise, and `notes` moved to a length-capped request body.

---

### LOW

---

#### L-01 — Analyst activity history persisted per-browser, not per-session
**File:** `frontend/src/lib/userActivity.ts`

Up to 500 activity records per user — searched values, viewed IOCs, threat scores — were kept in one shared `localStorage` key and were **not** cleared on logout, so the next person to use a shared SOC workstation could read the previous analyst's investigation history.

**Fix.** `logout()` now clears the current user's activity records. (Server-side storage would be the better long-term design — noted in `PROJECT_SUMMARY.md`.)

---

#### L-02 — Debug logging of API responses and OTPs; Redis exposed on all interfaces
**Files:** `frontend/src/lib/api.ts`, `hooks/useIOCSearch.ts`, `app/(analytics)/ioc-search/page.tsx`, `backend/app/utils/email_service.py`, `docker-compose.yml`

`api.ts` logged every request, every response header set and every full response body to the browser console — including token-bearing flows and indicator data. The email service `print()`ed OTP codes and recipient addresses to stdout. `docker-compose.yml` published Redis on `0.0.0.0:6379` with no password, reachable from the LAN.

**Fix.** All response/parameter logging removed from the frontend; `print()` replaced with structlog events that omit addresses and codes; Redis bound to `127.0.0.1:6379`. Committed junk strings in `README.md` and `render.yaml` were also removed.

---

## Hardening added beyond the findings

- **Security headers on every API response** (`main.py` middleware): `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store`, a restrictive CSP (`default-src 'none'` when docs are disabled), and HSTS in production.
- **Stronger tokens:** JWTs now carry `iat`, `jti`, `role` and `type: "access"`, are validated with an explicit algorithm allowlist and a required-claims check, and expire in 12 hours instead of 24. A non-access token type is rejected.
- **Email HTML escaping** for the username in OTP mail and for all diagnostics in alert mail.
- **SMTP STARTTLS with certificate verification** (`starttls(context=ssl.create_default_context())`), previously a bare `starttls()`.
- **nginx:** `server_tokens off`, `client_max_body_size 1m`, response headers, and the two `limit_req` zones described in H-01.
- **Frontend:** a rejected token is dropped on the first `401` instead of being replayed; FastAPI validation errors are surfaced readably so the new password policy is explained to the user; the admin contact inbox and the public contact form now go through the shared authenticated API client instead of raw `fetch()`.
- **Fixed two crash-on-call endpoints** discovered while auditing (`/attack/*` and the correlation engine used PostgreSQL `ARRAY` operators against MySQL JSON columns).

---

## Verification evidence

| Check | Result |
|---|---|
| `python -m compileall` — `app`, `scripts`, `alembic` | pass |
| `from app.main import app` | pass — 62 API routes (`len(app.routes)` is 66 including Starlette internals) |
| Route-guard audit against an explicit public allowlist | **62 routes = 53 guarded + 9 public, 0 unexpectedly public** |
| HTTP suite: 23 protected endpoints called anonymously | all 401/403 |
| HTTP suite: garbage bearer token | 401 |
| HTTP suite: viewer → admin endpoints / analyst-only mutations | 403 |
| HTTP suite: analyst → IOC write allowed, user admin denied | pass |
| HTTP suite: admin → admin endpoint | 200 |
| HTTP suite: disabled account with a validly signed token | 403 |
| HTTP suite: wrong `X-Cron-Secret` | 401 |
| HTTP suite: hardening headers present | pass |
| Logic suite: token forgery / wrong type / missing `exp` | all rejected |
| Logic suite: OTP entropy, keyed hashing, email binding | pass |
| Logic suite: weak and over-72-byte passwords | rejected |
| Logic suite: self-registration role | forced to `viewer` |
| Logic suite: production start with placeholder `SECRET_KEY` | raises |
| Logic suite: wildcard CORS origin | stripped; docs disabled |
| Logic suite: secret redaction (DSN password, `Authorization`, `Cookie`) | pass |
| Logic suite: `api_key_env` allowlist | `SECRET_KEY`/`DATABASE_URL`/`EMAIL_PASSWORD`/`PATH` rejected |
| Logic suite: CSV formula escaping | pass |
| Logic suite: AI `system` role injection | rejected |
| `tsc --noEmit` | pass |
| `next build` | pass — 26 routes |

---

## Residual risk

Accepted or out-of-scope items, in rough priority order:

1. **Credential rotation (see the banner above)** — the single most important remaining action. Not fixable in code.
2. **Token storage in `localStorage`.** Reachable by any successful XSS. Moving to an `HttpOnly; Secure; SameSite=Strict` cookie plus CSRF tokens is the correct fix but changes the auth contract on both tiers.
3. **No token revocation.** Logout is client-side only; a stolen JWT stays valid until `exp` (now 12 h). Add a `token_version` column on `users` (bumped on logout/password change) and check it in `get_current_user`.
4. **CSP still allows `'unsafe-inline'` for scripts** — required by the Next.js App Router without nonce support. Revisit when nonce-based CSP is available.
5. **Rate limiting is per-process when Redis is absent.** The in-memory fallback does not coordinate across workers or serverless instances; the nginx zone covers the containerised deployment, but a Vercel/Render deployment should have `REDIS_URL` configured for the limits to be global.

   **Addendum 2026-07-31 — provisioning Redis does NOT close this, contrary to what the sentence above says.** `deps.py::_client_ip` derives the bucket key from `X-Forwarded-For` and trusts the first entry with no trusted-proxy allowlist and no hop count:

   ```python
   forwarded = request.headers.get("X-Forwarded-For", "")
   if forwarded:
       return forwarded.split(",")[0].strip()
   ```

   The header is entirely client-supplied, so an attacker rotating it gets a fresh bucket per request and the per-IP budget never binds — with or without Redis. Two independent causes, one outcome; only the first was recorded.

   **Scope.** Every `rate_limit()` call site: `register`, `login`, `verify-otp`, `forgot-password`, `reset-password`, `contact-submit`, `ioc-lookup`, and the three `ai-*` endpoints.

   **What this is not.** It is *not* an authentication or privilege bypass. `get_current_user` loads the user from the database and `require_roles` reads `user.role` from that row, so the JWT's `role` claim is never consulted for authorization and cannot be forged into privilege. The `X-Cron-Secret` path uses `hmac.compare_digest` and is gated on a non-empty configured secret. A background review characterised this as a "spoofable-field auth bypass"; that framing is wrong, and the narrower reading is the correct one.

   **What it actually costs**, in severity order:
   - **Password guessing at `/login` is unthrottled.** This is the sharpest residual, because there is no per-account failure counter to fall back on — the finding on line 177 already notes password login has no effective limit, and this is a second reason it does not.
   - **AI endpoint spend is unbounded** (`ai-chat` 30/5 min, `ai-analyze` 20/5 min, `ai-report` 5/10 min), which is a direct cost-of-service exposure rather than a data one.
   - **`contact-submit` spam protection is nominal.**
   - **OTP brute force remains bounded**, by the per-code `attempts` counter in the database (`users.py:136`, capped at `OTP_MAX_ATTEMPTS`). That control is neither IP-based nor per-process, so it holds. Defence in depth works here — which is exactly why line 170 identifies it as the control that actually defeats the scenario.

   **Fix, not yet applied — blocked on a topology fact.** Honour `X-Forwarded-For` only when the immediate peer is a trusted proxy, otherwise use `request.client.host`. Getting that right requires knowing what terminates TLS in production and how many hops sit in front of the app: under `nginx/nginx.conf` the trusted peer is nginx and the client is the last-but-one entry, whereas on Render the edge appends the real client and a fixed hop count is the usual approach. Choosing wrong fails in one of two bad directions — trusting too much leaves this open, trusting too little buckets every caller together and turns the limiter into a global cap that a single noisy client can exhaust for everyone. **Owner input needed: which topology is live, nginx or Render's edge?**
6. **Registration still enumerates emails** via `409 Username or email already registered`. This is a deliberate usability trade-off; rate limiting is the mitigation.
7. **No audit log.** Privileged actions (feed deletion, user creation, role changes) are logged with structlog but not persisted to a tamper-evident store.
8. **`postcss` and `sharp` high-severity advisories remain.** Both are transitive dependencies pinned inside Next.js itself, so the only fix npm offers is downgrading Next to v9 — rejected. They clear when Next ships updated transitives. Exposure is limited: postcss runs at build time, and `sharp`/libvips only handles images passing through `next/image`, which this app uses for a local logo and favicon.

### Addressed after the initial review

* **Automated test suite added** — `backend/tests/` (271 tests, no database required) converts the review's ad-hoc verification into committed regression coverage: route-guard audit, role boundaries, token forgery/`alg:none`/expiry/type, OTP hashing and purpose-binding, password policy, production `SECRET_KEY` refusal, wildcard-CORS stripping, secret redaction, the `api_key_env` allowlist at both schema and scheduler level, CSV formula escaping and AI prompt-role validation.
* **`npm ci` fixed** — the lockfile was out of sync with `package.json`; regenerated and verified from a clean tree.
* **Next.js patched 16.1.6 → 16.2.12** (non-major), as part of the July 2026 Next.js security release. 16.1.6 carried numerous high-severity advisories: Middleware/Proxy bypasses (App Router segment-prefetch, Pages Router i18n, dynamic route parameter injection), several DoS vectors in Server Components and Server Actions, cache poisoning and confusion, and a CSP-nonce XSS.

  **Correction to an earlier claim in this document:** the rewrite SSRF (CVE-2026-64645) was assessed and **does not apply**. It requires a `rewrites()` or `redirects()` rule whose destination *hostname* is derived from request-controlled input. The actual rule builds its host from a build-time environment variable (`NEXT_PUBLIC_API_URL`) and interpolates only `:path*`, a path segment; the `www` redirect uses `has: [{type: 'host'}]` as a match condition with a literal destination host. The bump remains correct on the strength of the other advisories.

  Next.js now runs a **monthly security release programme**, so this needs a recurring dependency check rather than a one-time bump.

---

## Changed files

**Backend — new**
- `backend/app/api/deps.py` — authentication, RBAC, cron secret, rate limiting
- `backend/app/utils/sanitize.py` — secret and header redaction
- `backend/alembic/versions/d4e5f6a70001_harden_otp_table.py` — hashed OTPs, `purpose`, `attempts`

**Backend — modified**
- `app/config.py` (secrets removed, startup validation, `api_key_env` allowlist, auth tunables)
- `app/main.py` (CORS, docs gating, security headers, opaque errors, admin-only cron-status)
- `app/api/__init__.py`, `users.py`, `ioc.py`, `feeds.py`, `enrichment.py`, `reports.py`, `attack.py`, `ai.py`, `contact.py`
- `app/schemas/user.py`, `app/schemas/feed.py`
- `app/models/otp.py`
- `app/services/feed_scheduler.py`, `app/services/correlation_engine.py`
- `app/utils/email_service.py`
- `requirements.txt`

**Frontend — modified**
- `next.config.js` (enforced CSP, no `X-XSS-Protection`, `poweredByHeader: false`)
- `src/lib/api.ts` (no response logging, 401 token drop, readable validation errors, contact endpoints)
- `src/lib/auth.tsx` (clear activity on logout), `src/lib/types.ts`
- `src/app/(protected)/contacts/page.tsx`, `src/app/contact/page.tsx` (authenticated API client)
- `src/hooks/useIOCSearch.ts`, `src/app/(analytics)/ioc-search/page.tsx` (logging removed)

**Infrastructure — modified**
- `docker-compose.yml` (required secrets, Redis on loopback, CORS/cron/docs vars)
- `render.yaml` (DB credentials to dashboard, generated cron secret, docs off)
- `nginx/nginx.conf` (rate-limit zones, headers, body cap, docs 404, `server_tokens off`)
- `.env.example` (placeholders only, documented requirements)
