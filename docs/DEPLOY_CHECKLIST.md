# Deploy checklist

**Status:** Phase 6 draft, 2026-07-31. Written before the first deploy of this change set,
which is the point — several steps exist because getting the *order* wrong is unrecoverable
or expensive, and that is not discoverable while deploying.

Ordering constraints, stated once so the steps below make sense:

| Because | This must precede this |
|---|---|
| the rescore script skips rows holding an override | first rescore → any `manual_score_override` |
| `Base.metadata.create_all()` runs in the seed script and fails on the current schema | migration repair → seeding |
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

- [ ] Apply the migration-chain repair per §4 of its design. **Reconcile `alembic_version`
      with reality first** — stamping matters more than upgrading here, because replaying
      revisions that were effectively applied by hand fails partway and leaves a mixed state.
- [ ] Run the two diagnostic queries (§2.1 prefix-collision count, §3.2 exact-duplicate
      count) and record the numbers. If duplicates exist, the dedupe **merges** rather than
      deletes — deleting a loser lowers the survivor's `source_count` and silently changes
      its score.
- [ ] **Delete the test-only prefix-length scaffold** in `tests/conftest_mysql.py` once the
      real schema is fixed, or the `-m mysql` tier keeps testing a schema production does
      not have.
- [ ] Add `iocs.scoring_model_version` (what lets the rescore target stale rows) and
      `iocs.manual_score_override` (inert until it exists).
- [ ] Confirm `alembic upgrade head` now succeeds from an **empty** database. Disaster
      recovery is currently untested and impossible; this is the step that changes that.

## 3. Seed

- [ ] `python scripts/seed_feeds.py` — slugs must match `FEED_CONNECTORS` exactly or the
      feed cannot sync. Note this script calls `create_all()`, so it cannot run before §2.
- [ ] `python scripts/seed_mitre.py` — the ATT&CK catalogue. `/attack/*` returns empty
      without it.
- [ ] Verify `virustotal` and `phishtank` are `is_enabled = 0`. Revision `e5f6a7b80002`
      soft-disables them; their connectors are **deleted**, so if the revision has not
      reached production they sit permanently overdue logging `scheduler_no_connector`.

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
- [ ] `python scripts/rescore_corpus.py --dry-run` — gives the score distribution **and** a
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
- Three background mechanisms exist; only the HTTP cron runs. Do not assume a change to the
  asyncio scheduler or Celery affects production.
- Feed cadence drifts by one cron period when `sync_frequency` is a multiple of the cron
  interval. (§8 item 12 — Phase 4)
