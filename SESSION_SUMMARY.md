# Session Summary — Wiestell Threat Intelligence Platform

**Date:** 2026-07-28
**Repository:** `Wiestell_threatIntel_platform`, branch `Master`
**Starting state:** clean working tree at commit `5432b57`
**Ending state:** 17 new files, 46 modified, **nothing committed** — the full change set is staged in the working tree for review.

Companion documents produced this session:
[PROJECT_SUMMARY.md](PROJECT_SUMMARY.md) · [SECURITY_REVIEW.md](SECURITY_REVIEW.md) · [CLAUDE.md](CLAUDE.md)

---

## 1. What was asked, and what happened

| # | Request | Outcome |
|---|---------|---------|
| 1 | Review and analyse the entire codebase; write a project summary; run a security review and fix all findings; write a report | 182 files reviewed. 23 findings (6 critical / 8 high / 7 medium / 2 low) — **all fixed**. `PROJECT_SUMMARY.md` + `SECURITY_REVIEW.md` written. |
| 2 | Create a `CLAUDE.md` | Written, focused on non-obvious architecture and the traps that cost time during the review. |
| 3 | Integrate newly added enrichers and feeds "in the entire project" | 3 feeds + 3 enrichers wired end-to-end. Both sets had contract mismatches that would have prevented them working at all. |
| 4 | Follow-ups: test suite, lockfile fix, UI panels, enricher consolidation | All four delivered, sequenced so the risky refactor ran last, behind the new tests. |

---

## 2. The headline security problem

The platform was **effectively unauthenticated and unauthorized**. Authentication existed on paper — password → email OTP → JWT — but was enforced only by React route guards running in the visitor's own browser. All 53 non-public API endpoints answered anonymous `curl`.

The shortest full-compromise path was a single request:

```
POST /api/v1/users  {"username":"x","email":"x@y.z","password":"...","role":"admin"}
```

which created an **active admin account** with no OTP step. Alongside that: a `"change-me-in-production"` default JWT signing key (offline token forgery), OTP codes returned in the response body whenever SMTP failed (second-factor bypass on password reset), and password-reset codes redeemable at `/verify-otp` for a 24-hour session token.

Separately, **live production credentials were committed in plaintext** — the Hostinger MySQL DSN (in `config.py` as a *default value*, plus `docker-compose.yml` and `render.yaml`) and the `noreply@wiestell.com` SMTP password (in `config.py` and, ironically, in `.env.example`).

---

## 3. Findings that were not obvious

Beyond the expected auth/secrets issues, these came out of reading the code closely:

**Secret exfiltration via feed configuration.** `feed.api_key_env` was dereferenced with no validation, and the resolved value is forwarded to a third-party feed API as a key. Creating a feed with `api_key_env: "SECRET_KEY"` would have transmitted the JWT signing key to `abuse.ch`. Now allowlisted at both the schema and the scheduler read site, so pre-existing rows can't fire either.

**Session tokens leaving via email.** The 500 handler embedded `dict(request.headers)` verbatim into an alert email — so any unhandled error mailed the victim's `Authorization: Bearer` token out through SMTP. Alert emails are now opt-in, HTML-escaped, and pass through a redaction layer.

**CORS wildcard + credentials.** `allow_origins=["*"]` with `allow_credentials=True` makes Starlette *reflect* the requesting origin, which is worse than a literal `*`: any site could read authenticated responses. A wildcard can no longer be configured.

**Public endpoint serving database credentials.** `/api/v1/cron-status` was unauthenticated and returned `feed.last_sync_error` verbatim, populated from raw driver exceptions — which embed the full connection URI.

**CSV formula injection.** IOC values come from untrusted feeds and were exported unescaped. `=cmd|'/c calc'!A1` in a feed would execute on an analyst's workstation when they opened the export — the SOC's own tooling as the delivery mechanism.

**Outdated Next.js with many high-severity advisories** (found in phase 4, via a clean `npm install`) — Middleware/Proxy bypasses, DoS in Server Components and Server Actions, cache poisoning, CSP-nonce XSS. Patched 16.1.6 → 16.2.12.

> **Correction (2026-07-29):** this was originally written up as "SSRF via an attacker-controlled rewrite destination hostname, and this app proxies `/api/*` through exactly that mechanism". That was a **false positive**. CVE-2026-64645 needs the destination *hostname* to come from request-controlled input; here it comes from a build-time env var and only the path segment is interpolated. The version bump stands on the other advisories. See `SECURITY_REVIEW.md` for the full assessment.

---

## 4. Functional bugs found while reviewing

None of these were in scope, all were fixed:

1. **Three ATT&CK endpoints crashed on every call.** `attack.py` filtered a MySQL `JSON` column with the PostgreSQL-only `ARRAY.any()` operator. `correlation_engine.py` had the same defect with `.overlap()`. Both now use `json_contains`.
2. **A dead feed registry entry.** `FEED_CONNECTORS["mitre-attack"]` pointed at a `MitreAttackFeed` class that does not exist — `mitre_attack.py` only exposes a `load_attack_data()` function for `seed_mitre.py`. Any sync of that slug raised `AttributeError`.
3. **Enrichment risk was computed and discarded.** Nothing recomputed `threat_score` after enrichment, so the model's 10% enrichment-risk weight always evaluated against an empty list. Closed by `_rescore_from_enrichment`.
4. **The new feed connectors could not have worked.** They annotated `parse()` as returning `list[IOCCreate]` while returning `_make_ioc()` dicts (ingestion does `raw.get("type")`), and set `source_url` instead of the `slug`/`feed_type`/`url` attributes the registry, scheduler and seed script actually read.
5. **The new enrichers were dead code.** They relied on `supports()`/`cache_ttl` members `BaseEnricher` never declared, and the engine didn't use the `app/enrichers/` package at all — it had six hardcoded inline functions with a string `if/elif` dispatch. Nothing could have called them.
6. **Two pre-existing enricher modules were actively harmful.** `reputation_enricher` was an empty stub returning no data, and `whois_enricher` called the blocking `whois` library **directly on the event loop**. Both were superseded rather than adopted during consolidation.
7. **`npm ci` failed** with `EUSAGE` — the lockfile was out of sync with `package.json`, breaking any reproducible CI/Vercel build.

---

## 5. What changed, by area

### Authentication and authorization (new `backend/app/api/deps.py`)
`get_current_user`, `require_roles(...)`, `require_admin`, `require_analyst`, `require_admin_or_cron`, `rate_limit(...)`, `create_access_token`. Applied **at router registration** so new endpoints inherit a safe default. Roles: reads → authenticated; IOC/report mutations → analyst; feed CRUD, user admin, contact inbox, `/cron-status` → admin; `sync-all` and `backfill/start` → admin or `X-Cron-Secret`. Self-registration is pinned to `viewer`.

JWTs moved from the unmaintained `python-jose` to `PyJWT`, now carry `iat`/`jti`/`role`/`type`, validate with an explicit algorithm allowlist and required-claims check, and expire in 12h instead of 24h.

### OTP flow
Purpose-bound (`login`/`signup`/`password_reset`) so a reset code cannot buy a session token; codes stored as a `SECRET_KEY`-keyed, email-bound SHA-256 HMAC; `secrets` instead of `random`; per-code attempt counter; constant-time comparison; never logged, never returned. Verification no longer re-enables a disabled account. Migration `d4e5f6a70001`.

### Secrets and configuration
`DATABASE_URL` is required with no fallback; production refuses to start on a weak `SECRET_KEY`; development generates an ephemeral one. Credentials removed from `config.py`, `docker-compose.yml`, `render.yaml` and `.env.example`. New `app/utils/sanitize.py` redacts connection-string credentials, known secret values and credential-bearing headers — applied to logs, alert emails, the persisted `last_sync_error` column and its serializer.

### Hardening
Rate limits on all credential endpoints (application + nginx zones); `/docs`, `/redoc`, `/openapi.json` closed in production; enforced CSP (was report-only); security headers on every API response; opaque 500s with a correlation `error_id`; Redis bound to loopback; `server_tokens off`; dependency updates for CVEs in `starlette`, `python-multipart`, `aiohttp`, `pymysql`, `jinja2`; Next.js 16.1.6 → 16.2.12.

### Feeds and enrichers
3 new feeds registered (CISA KEV, eCrimeLabs Metasploit, MISP CERT-FR) — connector attributes, `FEED_CONNECTORS` entries with alias slugs, `seed_feeds.py` rows, docs. 11 feeds total (PhishTank and VirusTotal were removed on 2026-07-29).

All 9 enrichers consolidated into `BaseEnricher` subclasses in `app/enrichers/`, registered in one place. The engine dropped from **616 to 234 lines** and now holds zero per-source knowledge. Scoring gained branches for CVSS bands, CISA KEV membership, public-exploit availability and YARA/ClamAV hits, plus `cisa-kev`/`exploitable`/`metasploit` as high-risk context tags.

### Frontend
Response/parameter logging removed (it printed tokens and indicator data to the browser console); a rejected token is dropped on the first 401; admin inbox and public contact form moved onto the authenticated API client; analyst activity history cleared on logout; new `VulnerabilityEnrichment.tsx` panels with CVSS severity bands, a CISA KEV badge and exploit warnings.

---

## 6. Verification

| Check | Result |
|---|---|
| `python -m pytest` (`backend/tests`) | **271 passed**, ~5s, no database required |
| Route-guard audit (every live route vs. an explicit allowlist) | **62 routes = 53 guarded + 9 public, 0 unexpectedly public** |
| `python -m compileall` (app, tests, migrations, scripts) | clean |
| `npm ci` from a clean tree | pass (previously `EUSAGE`) |
| `tsc --noEmit` | clean |
| `next build` | pass, 26 routes |
| `npm audit --omit=dev` | 3 high, all pinned inside Next.js's own tree |

The test suite pins: route guarding, role boundaries, token forgery/`alg:none`/expiry/type, OTP hashing and purpose-binding, password policy, production `SECRET_KEY` refusal, wildcard-CORS stripping, secret redaction, the `api_key_env` allowlist at schema *and* scheduler level, feed parsing and registry resolution, the per-type enrichment source table, WHOIS staying off the event loop, CSV formula escaping, and AI prompt-role validation.

Two tests failed on first run and both were worth having: one was a harness bug, the other revealed that a worst-case CVE scored 44 (below "high") because `_base_reputation_score` returns a flat 30 for any IOC without feed reputation data — a constant carrying 30% of the composite. Documented rather than silently changed.

Three tests were deliberately rewritten after the enricher consolidation because they described the old two-tier architecture. The engine-level behaviour tests passed unchanged throughout, which is what made the refactor safe.

---

## 7. Outstanding — owner actions

> ### ⚠️ 1. Rotate the exposed credentials (cannot be done from the codebase)
> The MySQL password for `u433859718_wiest_tell@193.203.184.197` and the `noreply@wiestell.com` SMTP password were committed in plaintext. They are gone from the working tree but **remain in git history and in every clone, fork and CI cache**.
>
> 1. Rotate the MySQL password; restrict the DB user to the application's source IPs.
> 2. Rotate the mailbox password.
> 3. Rotate any feed/enrichment API key that was ever committed.
> 4. Purge history (`git filter-repo` / BFG) and force-push, or treat these values as permanently burned.
> 5. Review MySQL and mail logs for access during the exposure window.

**2. Before deploying**
```bash
cd backend
alembic upgrade head       # d4e5f6a70001_harden_otp_table
python scripts/seed_feeds.py             # 3 new feed rows
```
Set `SECRET_KEY` (≥32 random chars) — production now refuses to start without one. Optionally set `CRON_SECRET`, `NVD_API_KEY`, `CVEDETAILS_ACCESS_TOKEN`.

Strongly recommended: one abuse.ch Auth-Key from <https://auth.abuse.ch/>, placed in **all four** of `URLHAUS_API_KEY`, `THREATFOX_API_KEY`, `MALWAREBAZAAR_API_KEY` and `YARAIFY_API_KEY` (the code reads separate names; `YARAIFY_API_KEY` alone falls back to `MALWAREBAZAAR_API_KEY`). Verified 2026-07-30: abuse.ch CSV exports remain open but its JSON query APIs return 401, so without a key URLhaus and ThreatFox ingest fewer IOC types and MalwareBazaar enrichment is unavailable entirely.

**3. Known-remaining, documented**
- `postcss` / `sharp` high-severity advisories are pinned inside Next.js's dependency tree; npm's only offered fix is downgrading Next to v9. They clear on an upstream Next release.
- Token storage in `localStorage` (XSS-reachable) and no token revocation on logout — both are architectural changes affecting both tiers.
- CSP still permits `'unsafe-inline'` for scripts, required by the Next App Router without nonce support.
- Rate limiting is per-process without Redis; set `REDIS_URL` for it to be global on serverless.
- Two schedulers exist (asyncio loop, HTTP cron); only the HTTP cron runs. Celery beat was the third and was deleted 2026-08-17.
- `_base_reputation_score`'s flat 30 compresses the achievable score range for CVE-only indicators — a product decision.

---

## 8. File inventory

**New (17)**

```
CLAUDE.md, PROJECT_SUMMARY.md, SECURITY_REVIEW.md, SESSION_SUMMARY.md
backend/pytest.ini
backend/requirements-dev.txt
backend/alembic/versions/d4e5f6a70001_harden_otp_table.py
backend/app/api/deps.py                       auth, RBAC, cron secret, rate limiting
backend/app/utils/sanitize.py                 secret + header redaction
backend/app/feeds/cisa_kev.py                 (authored by the user, corrected here)
backend/app/feeds/ecrimelabs.py               (authored by the user, corrected here)
backend/app/feeds/misp_cert_fr.py             (authored by the user, corrected here)
backend/app/enrichers/nvd_enricher.py         (authored by the user, wired in here)
backend/app/enrichers/cvedetails_enricher.py  (authored by the user, wired in here)
backend/app/enrichers/yaraify_enricher.py     (authored by the user, wired in here)
backend/app/enrichers/malwarebazaar_enricher.py
backend/tests/                                conftest + 5 test modules, 271 tests
frontend/src/components/ioc/VulnerabilityEnrichment.tsx
```

**Modified (46)** — all 9 API routers and `api/__init__.py`; `config.py`, `main.py`, `database`-adjacent models and schemas; `enrichment_engine`, `feed_scheduler`, `correlation_engine`, `scoring_engine`; `email_service`; `requirements.txt`; the five pre-existing enricher modules; `docker-compose.yml`, `render.yaml`, `nginx/nginx.conf`, `.env.example`, `README.md`, `scripts/seed_feeds.py`; and 11 frontend files.
