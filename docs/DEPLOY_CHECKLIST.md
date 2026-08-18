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

- [ ] **Rotate the credentials still in git history.** `9107d1c` carries a literal
      `EMAIL_PASSWORD`, and SECURITY_REVIEW.md's rotation notice lists a MySQL password and
      SMTP password. Removing them from the working tree did not make them secret. Rotate,
      then decide whether to purge history.
- [ ] **Run the owner queries in one sitting** — four blocking, two not:
      §5 of [the migration-chain design](superpowers/specs/2026-07-30-migration-chain-repair-design.md)
      (`SELECT VERSION()`, `SHOW CREATE TABLE iocs`, `SHOW CREATE TABLE feed_sources`,
      `SELECT * FROM alembic_version`), plus §5.4 (four corpus counts) and §5.5 (the GeoIP
      `error_city` check). Record the output **verbatim in that document** before anything
      changes it.
- [ ] **Confirm `alembic upgrade head` cannot run yet.** It fails at error 1170 on
      `iocs.value`. Nothing below that depends on migrations can proceed until §2 is done.

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

## 4. Deploy the service

- [ ] Set every `sync: false` variable in the Render dashboard. `tests/test_deploy_config.py`
      asserts none of them carry literal values in `render.yaml`.
- [ ] Deploy, and confirm the build log shows the GeoLite2 download **succeeding** — it is
      `|| echo "...continuing"`, so a failure is not a build failure.
- [ ] **Verify the actual running start command, not the one in `render.yaml`.** The
      dashboard can override it, and that override lives in no file any test can read. Four
      subsystems assume one process; `main.py::_assert_single_worker` refuses to boot at
      `--workers > 1`, so a refused start is the symptom to recognise. (CLAUDE.md invariant)
- [ ] **Measure the hop count — do this EARLY, not last.** Log the raw `X-Forwarded-For`
      from the deployed instance and count the entries, then set `TRUSTED_PROXY_HOPS`. This
      closes a bypass *and* fixes an availability problem: until it is set, every caller
      buckets under Render's edge address, so the per-IP limits are global limits and one
      noisy client locks out login and the AI endpoints for everyone (R-06).
      **Also establish whether the origin is reachable off-edge** (R-03). If `*.onrender.com`
      answers directly, a request straight to the origin satisfies a count measured through
      a CDN while supplying its own entry — and 0 may be the only honest value, which makes
      the per-account counter the sole credential control rather than a complement.
      Err **low** if you must err: too high indexes into the client-supplied portion.
- [ ] `GET /api/v1/health` — expect 200. Deliberately **minimal**: it must stay
      unauthenticated for Render's health checker, so anything on it is world-readable.
      (Render reads only the status *code*, not the body.)
- [ ] **`GET /api/v1/cron-status` with an admin token, and read the `degradations` array.**
      Empty on a correct deployment. It reports the two states where the app runs but is not
      doing what the design assumes — both settable in Render's dashboard, invisible in the
      repository, and otherwise evidenced only by a boot log line that scrolls away:

      | `id` | Means |
      |---|---|
      | `geoip_database_missing` | the `.mmdb` is absent, so **every** IP indicator is enriched with no country or ASN data |
      | `multiple_workers_allowed` | `ALLOW_MULTIPLE_WORKERS` is set, so rate limits, the DB pool, enrichment concurrency and any cache are all per worker |

      **Admin-gated on purpose.** This was briefly on the public `/health` payload, which
      was a poor trade: `multiple_workers_allowed` tells an unauthenticated reader that the
      login rate limit is N times weaker than it appears — precisely the fact worth having
      before starting a credential-stuffing run. Publishing one's own mitigation gap for
      post-deploy convenience is not worth it, so it moved here, where operational state
      already lives behind admin auth.

      Note `/health`'s `status` stays `"healthy"` even when a degradation is present. That
      is deliberate: `"degraded"` drives orchestrator restarts and neither of these is fixed
      by restarting, so flipping it would train uptime monitoring to ignore the field.

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
      hours** from a laptop against Hostinger. Resumable via `--start-after` and idempotent,
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
