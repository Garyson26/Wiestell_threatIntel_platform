# Design — Reputation Evidence Model, Feed Removal, Corpus Rescore

**Date:** 2026-07-29
**Source spec:** Handoff Spec 3 (supersedes Spec 2 Phase 1)
**Repository:** `Wiestell_threatIntel_platform`, branch `Master`
**Convention:** one change set, staged for review, **not committed**

---

## 1. Corrections to the source spec

Four claims in the spec do not survive contact with the code. Each is measured, not
argued.

### 1.1 The CVE fixture deflation is not caused by the reputation rule

The spec predicts that requiring positive evidence for a 0.0 reputation will lift the
low-severity CVE fixtures from 32 → 38 and 26 → 29.

It cannot. For an IOC of type `cve`, `_base_reputation_score` resolves through the
**CVSS** branch (`_reputation_from_cvss`), and the fixtures in
`TestCVEProfileFixtures` carry no `reputation` enrichment entry at all. Measured term
breakdown, before any change:

| Fixture | Score | reputation | diversity | recency | frequency | enrichment | context |
|---|---|---|---|---|---|---|---|
| F1 exploited critical KEV CVE (9.8, KEV, exploit, day 0) | **83** critical | 98.0×0.30 | 30.0×0.05 | 100.0×0.10 | 10.0×0.00 | 100.0×0.30 | 50.0×0.25 |
| F2 moderate unexploited CVE (7.5, 30d) | **32** medium | 75.0×0.30 | 30.0×0.05 | 20.0×0.10 | 10.0×0.00 | 20.0×0.30 | 0.0×0.25 |
| F3 low-severity CVE (4.0, day 0) | **26** medium | 40.0×0.30 | 30.0×0.05 | 100.0×0.10 | 10.0×0.00 | 10.0×0.30 | 0.0×0.25 |
| F4 fresh exploited critical, 3 feeds, 5 sightings | **86** critical | 100.0×0.30 | 80.0×0.05 | 100.0×0.10 | 40.0×0.00 | 100.0×0.30 | 50.0×0.25 |

The reputation term is 75.0 and 40.0 — CVSS 7.5 and 4.0 scaled — not the neutral
constant and not an aggregate score. The reputation-evidence rule changes nothing here.

The 38/29 predictions are reconstructible from two different readings:

- `_enrichment_risk_score` adds `total_signals += 4` for the cvedetails payload even
  when it reports *no* exploit, giving F2 an enrichment term of 20.0 rather than the
  33.3 that NVD alone would produce.
- `_recency_score` places a 30-day-old indicator in the `< 90 days` bucket at 20.0. The
  `< 30 days` bucket at 40.0 requires age strictly under 30 days.

F2 with both readings changed: 22.5 + 1.5 + 4.0 + 0 + 10.0 + 0 = **38.0**. F3 with the
first alone: 12.0 + 1.5 + 10.0 + 0 + 5.0 + 0 = **28.5 → 29**. Exact matches, which is
what identifies them as the source of the prediction.

**Consequence for the spec's gate.** Section 1 instructs stopping before Section 3 if
the fixtures do not move. They do not and cannot. Per the owner's decision the rescore
script is still written, but **it is not run** — separately unavoidable, since no DSN is
available in this environment.

**The gate is replaced, not dropped.** A CVE-fixture gate cannot test a rule that the CVE
path never reaches. The equivalent non-CVE gate, which does:

> A fresh feed-sourced URL whose reputation providers were all silent must score
> **unknown**, not clean — i.e. its reputation term must be `NEUTRAL_REPUTATION`, and its
> composite must match the same indicator with no providers configured at all.

Pinned as a test, not just measured, so it cannot regress silently.

### 1.2 The rule is still correct, and it bites on non-CVE indicators

Measured on a fresh URLhaus-style malware URL, day 0, one feed, `malware` tag:

| Reputation payload | Score |
|---|---|
| aggregate 0, `sources_checked` 3 (silent providers) | **26** medium |
| aggregate 0, `sources_checked` 0 (no keys configured) | **34** medium |
| aggregate 80, `sources_checked` 1 (flagged) | **60** high |

Provider silence costs 8 points against the same indicator with no providers configured
at all. That is the defect Section 1 describes, and it is real — it is simply not what
moved the CVE fixtures.

### 1.3 `feed_sources.is_enabled` already exists

Section 2.2 asks for a new `enabled BOOLEAN NOT NULL DEFAULT TRUE` column. `is_enabled`
is already on the model ([backend/app/models/feed.py:22](../../../backend/app/models/feed.py#L22))
and is already the filter in every consumer: the scheduler tick, `feeds/sync-all`,
`dashboard/feed-health`, `main.py`'s cron status and `report_generator`. Adding a second
column would split the meaning of "enabled" across two fields.

The initial migration declares it `nullable=True`, so the spec's *intent* — a
`NOT NULL DEFAULT TRUE` flag — is not yet fully satisfied. This design tightens the
existing column instead of adding a new one.

**Spec 2 Phase 4 must drop `enabled` from its column list.** `is_enabled` is the column.

### 1.4 `scripts/seed_feeds.py` is already at 11 feeds

Both rows are already commented out; `FEEDS` holds 11 entries. The work here is deleting
the commented blocks, not removing live rows.

---

## 2. Scope of this change set

| Section | Action |
|---|---|
| 1 | Reputation evidence model — enricher payload + scoring rule + tests |
| 1a | Enrichment-risk dilution fix (owner-approved addition) |
| 2 | Remove PhishTank and VirusTotal; soft-disable both DB rows |
| 3 | Write `scripts/rescore_corpus.py`; **do not run it** |
| 4 | Verify six confirmations; fix any that have not landed |
| 5 | Scope GTM to a new `(marketing)` route group |
| 5a | Move `?email=` out of the URL (owner-approved addition) |

**Build order** (owner-specified): risk dilution → reputation evidence → feed removal →
frontend → rescore script last, so the script is written against final scoring inputs.

Out of scope: score bucket thresholds, `feed_ingestion.py`'s ingestion shape,
`build_registry` order, the `aiomysql.ensure_closed` patch, `manual_score_override`'s
migration (Spec 2 Phase 4).

---

## 3. Section 1 — reputation must require positive evidence

### 3.1 The enricher payload does need to change

Today `ReputationEnricher.enrich` returns `aggregate_score`, `sources_checked`,
`sources_flagged` and a free-form `details` map. That is not sufficient to evaluate the
rule:

- Nothing records **which providers support the IOC type**. `sources_checked` counts
  providers that answered, so "AbuseIPDB was never applicable" and "AbuseIPDB was
  applicable and silent" are indistinguishable.
- `details` is populated only on HTTP 200 and its shape is per-provider, so
  corroboration has to be dug out of a different key per provider (`reports`,
  `total_engines`, `pulse_count`).
- OTX's `pulse_count: 0` means "not indexed" — silence — but reads identically to a
  positive harmless verdict in the aggregate.

**New field: `providers`**, a list of records, one per provider the enricher knows
about, regardless of outcome:

```python
{
  "name": "abuseipdb" | "otx",
  "supports_type": bool,   # does this provider cover this IOC type at all
  "configured": bool,      # was a credential present
  "responded": bool,       # did it return a parseable answer
  "verdict": "malicious" | "harmless" | "silent" | "unavailable",
  "corroboration": int,    # report / sample / analysis count backing the verdict
}
```

`aggregate_score`, `sources_checked`, `sources_flagged`, `details` and `note` are all
retained unchanged — the dashboard and `_enrichment_risk_score` read them.

`verdict` semantics, which are the whole point:

- `malicious` — a positive detection (`abuseConfidenceScore > 0`, `pulse_count > 0`).
- `harmless` — the provider answered, reported no detection, **and** `corroboration > 0`.
  AbuseIPDB with `totalReports > 0` and no confidence score qualifies. OTX cannot
  produce this: `pulse_count: 0` carries no corroboration, so OTX silence is `silent`.
- `silent` — answered, no detection, no corroboration. Not exculpatory.
- `unavailable` — not configured, HTTP error, or unparseable.

### 3.2 The scoring rule

`_reputation_from_enrichment` gains an evidence gate. 0.0 is returned only when **all**
of the following hold:

1. At least one provider with `supports_type: true` has `responded: true`.
2. That provider's verdict is `harmless` with `corroboration > 0`.
3. No provider returned `malicious`.
4. The IOC has no `ioc_sources` row from an enabled feed.

Anything else — including a non-zero aggregate with an otherwise clean picture — falls
through to the existing behaviour: use `aggregate_score` when a supporting provider
responded, else `NEUTRAL_REPUTATION`.

**Old-shape payloads.** A cached row without a `providers` key routes to *unknown*, never
to clean. No backfill.

> **Correction, 2026-07-30.** This section originally said the 6-hour
> `CACHE_TTL_REPUTATION` would refresh such rows naturally. **That is wrong.**
> `expires_at` is only consulted once enrichment runs for an IOC, and the cron
> selects `WHERE Enrichment.id IS NULL` — IOCs with *no* enrichment row. An IOC
> enriched once is never selected again, so its payload never refreshes however
> stale it becomes. Old-shape payloads are **permanent** until Spec 2 Phase 4 fixes
> the selection, and the unknown-routing fallback is load-bearing indefinitely
> rather than for six hours. Same applies to the `error*` prefix match in
> `_reached_a_verdict` and, when it lands, the `assessed` legacy fallback.

### 3.2a The 0.0 branch becomes unreachable, deliberately

Once VirusTotal is gone, **no remaining provider can produce a corroborated harmless
verdict**:

- **OTX** has no corroboration channel at all. `pulse_count: 0` means "no pulse mentions
  this indicator", which is absence of evidence. It can only ever yield `malicious`
  (count > 0) or `silent`.
- **AbuseIPDB**'s `abuseConfidenceScore` is *derived from* abuse reports, so a zero score
  with `totalReports: 0` is silence. A non-zero `totalReports` with a zero confidence
  score is the one shape that would qualify — reports exist but were assessed as not
  abusive — and it is rare enough that it cannot be relied on. (`isWhitelisted: true` is
  a genuine clean assertion, but it is a property of AbuseIPDB's allowlist rather than a
  verdict on the indicator, and it is IP-only.)

So after this change **reputation ranges 30–100 in practice**, never 0. The branch is
kept rather than deleted for two reasons: it documents what evidence *would* justify a
0.0, and it stays correct the moment a provider with a real clean-assertion channel is
added.

To make that transition visible rather than silent, a test asserts the branch is
**currently unreachable**: no combination of OTX and AbuseIPDB payloads produces 0.0.
When someone adds a provider that can assert cleanliness, that test fails and tells them
the branch has gone live and needs a deliberate decision.

**Section 1's live effect is therefore entirely "stop scoring silence as clean."** It
raises scores for indicators whose providers were silent; it lowers nothing.

### 3.3 Point 4 needs a new input, and it must not be `source_count`

`source_count` is the distinct `ioc_sources.feed_id` count and drives the diversity term.
Filtering it on `feed_sources.is_enabled` would lower diversity for every IOC that
PhishTank or VirusTotal ever contributed to — precisely the uncontrolled score change
Section 2.2 forbids.

It also stays a **parameter**, rather than a synthetic entry in `enrichment_data`. That
list holds `enrichments` rows and `_enrichment_risk_score` switches on `source`, so a
synthetic member would need special-casing in the risk scorer too — two coupled changes
to avoid one argument. `source_count` already sets the precedent for "scoring input that
is not an enrichment row".

The floor therefore takes a separate parameter:

```python
def calculate_threat_score(
    ioc_data, source_count=1, enrichment_data=None,
    has_enabled_feed_source: Optional[bool] = None,
) -> int
```

`None` means "the caller does not know" and is treated as **True** — the floor applies
and 0.0 is unreachable. Unknown must never resolve to clean, so the permissive direction
is the one that blocks the 0.0.

Callers:

| Caller | Value |
|---|---|
| `feed_ingestion` | `True` — the row is being written because a feed reported it |
| `enrichment_engine._rescore_from_enrichment` | queried alongside the existing distinct-feed count |
| `scripts/rescore_corpus.py` | from the same per-chunk grouped query — see below |
| anything else / tests | omitted → `None` → floor applies |

In the rescore script both values come from **one** statement — `COUNT(DISTINCT feed_id)`
alongside `MAX(is_enabled)` over the `ioc_sources → feed_sources` join, grouped by
`ioc_id`. Two separate queries would both break the four-statements-per-chunk budget and
allow the values to drift between fetches if a feed were toggled mid-run.

The mild coupling with the diversity factor is acknowledged: source presence already
feeds diversity. It is acceptable because point 4 is a gate on one boundary value, not an
additive term.

### 3.4 Tests

New cases in `TestReputationFromEnrichment`:

- silent provider (`verdict: silent`) → `NEUTRAL_REPUTATION`
- harmless with corroboration, no feed source → `0.0`
- harmless with corroboration, **with** a feed source → `NEUTRAL_REPUTATION`
- a provider with `supports_type: false` does not satisfy point 1
- a `malicious` verdict alongside a `harmless` one → not 0.0
- old-shape payload (`providers` absent) → `NEUTRAL_REPUTATION`
- `has_enabled_feed_source` omitted → floor applies

`test_confirmed_clean_scores_low` currently asserts `aggregate 0, sources_checked 3 → 0.0`.
That assertion encodes the defect and is rewritten, not deleted — the docstring records
why.

---

## 4. Section 1a — enrichment-risk dilution (owner-approved addition)

`_enrichment_risk_score` adds a source's `total_signals` unconditionally. A payload that
carries no verdict therefore lowers the ratio: a reputation row with
`sources_checked: 0` contributes 0 risk against a denominator of 3, so an IOC with no
provider keys scores *worse* on enrichment risk than one with no reputation row at all.
Same class of error as Section 1 — an absence read as evidence.

**Fix, scoped to "no verdict reached":** a source contributes to `total_signals` only when
it produced a usable verdict. Skipped:

- a non-Mapping `data`, or a payload carrying an `error` key — the source failed
- a reputation payload where no provider supporting this IOC type responded
  (`sources_checked: 0`, or no `providers` entry with `supports_type` and `responded`)
- `{"found": False}` — the source's database has no record of this indicator
- GeoIP with no `country_code`; WHOIS/DNS that did not resolve
- NVD with neither a CVSS score nor a KEV flag

**Explicitly still counted: a negative verdict.** The CVE Details enricher emits three
distinguishable shapes, and only the third is a verdict:

| Payload shape | Meaning | Contributes? |
|---|---|---|
| `{"source": "cvedetails", "error": "..."}` | HTTP or parse failure | no |
| `{"source": "cvedetails", "found": False}` | CVE absent from their database | no |
| full dict incl. `cvedetails_exploit_available` | record returned, field read | **yes** |

F2's `_NO_EXPLOIT` fixture is the third shape with an explicit `False` — a genuine
"checked, no public exploit exists". That is real evidence of lower risk, and dropping it
would score an unchecked CVE identically to one confirmed to have no exploit.

**So F2 stays at 32 and F3 stays at 26, and 38/29 are not targets.** Those predictions
treated a negative verdict as an absence — the same mistake as scoring silence as clean,
in the opposite direction. The recency half of the 38 prediction was also wrong:
`age < timedelta(days=30)` is false at exactly 30 days, so a 30-day fixture lands in the
`<90d` bucket at 20.0, not 40.0.

**Two consequences found while implementing, both intended:**

*Reverse DNS stops diluting every IP.* The DNS risk branch measures exactly one thing —
fast flux, an A-record set large enough to look like rotating infrastructure. Only a
*forward* lookup can answer that. The enricher's reverse shape,
`{"type": "reverse", "ptr": [...], "hostname": ...}`, carries neither `records` nor
`fast_flux`, so before this change every IP with a PTR row contributed
`total_signals += 2` against 0 risk. It is now correctly classified as no verdict for this
dimension. This raises the enrichment term for IPs, which is the largest single population
affected by the fix.

*Silence is treated identically in both scorers.* An early version of this change had OTX's
zero pulse count rejected as clean evidence by `_base_reputation_score` but counted as a
low-risk signal by `_enrichment_risk_score` — the same absence meaning two different
things, raising one term while lowering another. `_reputation_reached_verdict` is
deliberately narrower than `_reputation_provider_responded`: the former asks "did
reputation produce evidence" (needed by the risk ratio), the latter "is `aggregate_score`
meaningful" (needed by the reputation term). A caught test failure, not a design intent.

**Recorded, not fixed here:** [cvedetails_enricher.py:118](../../../backend/app/enrichers/cvedetails_enricher.py#L118)
does `entry.get("exploitAvailable", False)`, which converts a *missing* API field into a
negative verdict. That is the same silence-as-evidence pattern one layer lower — inside
the payload rather than the scorer — and it means the scorer cannot always distinguish
shape 3's "no" from "the field wasn't there". Logged in `PROJECT_SUMMARY.md` §8; fixing it
needs a live CVE Details subscription to confirm the API's actual behaviour, which this
deployment does not have.

Net effect on the corpus: IOCs whose enrichers errored or returned nothing score higher
on the enrichment term. Chiefly the reputation-with-no-keys population, which is
currently the entire corpus if `OTX_API_KEY` and `ABUSEIPDB_API_KEY` are unset.

---

## 5. Section 2 — remove PhishTank and VirusTotal

Final state: **11 feeds** — URLhaus, ThreatFox, MalwareBazaar, Feodo Tracker,
Blocklist.de, Emerging Threats, CISA KEV, eCrimeLabs Metasploit, MISP CERT-FR (keyless),
plus OTX and AbuseIPDB (keyed).

### 5.0 `ALLOWED_FEED_API_KEY_ENVS`: 11 → 5, audited

The allowlist gates `feed.api_key_env`, so "reachable" means *a `feed_sources` row can
cause this variable to be dereferenced and forwarded to a third party*
([feed_scheduler.py:99-108](../../../backend/app/services/feed_scheduler.py#L99-L108)).
Audited rather than assumed:

| Env var | Declared by a surviving connector | Set on a seeded row | Verdict |
|---|---|---|---|
| `OTX_API_KEY` | `otx_alienvault.py`, `requires_api_key=True` | yes | reachable |
| `ABUSEIPDB_API_KEY` | `abuseipdb.py`, `requires_api_key=True` | yes | reachable |
| `THREATFOX_API_KEY` | `threatfox.py`, optional `Auth-Key` | yes | reachable |
| `MALWAREBAZAAR_API_KEY` | `malwarebazaar.py`, `Auth-Key` + export URL path | no | reachable if set |
| `URLHAUS_API_KEY` | `urlhaus.py`, export URL path | no | reachable if set |
| `SHODAN_API_KEY` | — | no | **unreachable** — enricher-only |
| `NVD_API_KEY` | — | no | **unreachable** — enricher-only |
| `YARAIFY_API_KEY` | — | no | **unreachable** — enricher-only |
| `CVEDETAILS_ACCESS_TOKEN` | — | no | **unreachable** — enricher-only |
| `VT_API_KEY` | connector deleted | no | gone |
| `PHISHTANK_API_KEY` | connector deleted | no | gone |

The spec's premise that only OTX and AbuseIPDB are keyed misses the three abuse.ch keys.
ThreatFox, MalwareBazaar and URLhaus are all live and `is_enabled: True`, all three
connectors read a key when one is present, and ThreatFox's row already sets one.

The four enricher-only keys are read from `settings` directly in `build_registry` and the
enricher constructors; no connector class declares them, so no feed row can reach them.
They are removed from the allowlist while remaining `Settings` fields.

**Owner decision: trim to the five connector-declared names.** Result: 11 → 5, a **55%**
reduction in the H-03 exfiltration surface — not the 25% the spec estimated, nor the 18%
that removing only VT and PhishTank would have given. The commit message states 55%.

`SHODAN_API_KEY`, `NVD_API_KEY`, `YARAIFY_API_KEY` and `CVEDETAILS_ACCESS_TOKEN` stay in
`Settings` and in `.env.example` — the enrichers still need them. Only their
*feed-row reachability* is withdrawn.

### 5.1 Code removal

| Target | Action |
|---|---|
| `app/feeds/virustotal.py`, `app/feeds/phishtank.py` | delete |
| `services/feed_scheduler.py::FEED_CONNECTORS` | remove both slugs |
| `app/tasks/feed_tasks.py` (its own duplicate registry) | remove both slugs |
| `scripts/seed_feeds.py` | delete the two commented blocks |
| `app/config.py` | remove `VT_API_KEY` / `PHISHTANK_API_KEY` settings; trim the allowlist to five per §5.0 |
| `app/utils/sanitize.py` | remove both from the redaction key list |
| `app/enrichers/reputation_enricher.py` | remove the VirusTotal provider branch |
| `.env.example`, `docker-compose.yml`, `render.yaml` | drop both keys |
| `frontend` | see 5.3 |

`build_registry` does not change: VirusTotal was a provider *inside* the reputation
enricher, not a registered enricher. Nine enrichers, unchanged order.

### 5.2 Data — soft-disable

One hand-written revision off `d4e5f6a70001`:

1. Backfill `UPDATE feed_sources SET is_enabled = 1 WHERE is_enabled IS NULL`.
2. `ALTER` `is_enabled` to `BOOLEAN NOT NULL DEFAULT TRUE`.
3. `UPDATE feed_sources SET is_enabled = 0 WHERE slug IN ('virustotal', 'phishtank')` —
   idempotent, a no-op if the rows were never seeded.

No rows are deleted. `ioc_sources` and therefore `source_count` are untouched.

**Downgrade is a deliberate no-op.** `is_enabled` already existed before this revision, so
there is no schema addition to reverse, and re-enabling two feeds whose connector modules
have been deleted would be actively harmful — the scheduler would pick them up and fail
every sync with `ModuleNotFoundError`. The revision's `downgrade()` therefore does
nothing but carry a comment saying so: the `NOT NULL` tightening is left in place because
loosening it serves no purpose, and re-enabling the two rows is a manual decision that
belongs with whoever restores the connectors.

### 5.3 Frontend

Remove every claim that VirusTotal or PhishTank is a data source: `PoweredBy.tsx`,
`app/about/page.tsx`, `(protected)/settings/page.tsx` (the API-key list),
`(protected)/ai-assistant/page.tsx` (the system prompt's feed inventory), and any
`lib/types.ts` union member.

**Owner decision: the outbound `virustotal.com/gui` pivot links stay.** Three call sites
— `(analytics)/ioc-detail/[id]`, `(protected)/ioc/[id]`, `(analytics)/analytics` — build
a click-through to the VirusTotal web UI. No API key, no ingestion, and one-click pivot
is standard analyst workflow. The verification grep therefore has three documented
exceptions rather than coming back empty; they are listed in the handback.

### 5.4 Test and documentation counts

`tests/test_feeds.py:146` asserts `FeedCreate(api_key_env="VT_API_KEY")` is accepted —
the positive case moves to `OTX_API_KEY`. Every negative case (`SECRET_KEY`,
`DATABASE_URL`, `EMAIL_PASSWORD`, `PATH`) is kept.

13 → 11 in `README.md` (intro, feed table, enrichment table, env table),
`PROJECT_SUMMARY.md` §1 and §4, `SESSION_SUMMARY.md` §5. `CLAUDE.md`'s "10+ feeds" and
the "nine free feeds" line both stay correct.

---

## 6. Section 3 — `scripts/rescore_corpus.py`

Written and staged; **not executed**. No `backend/.env` and no DSN exist in this
environment, so the dry-run distribution table is an owner action.

- Runs from a developer machine against the Hostinger DSN. Never on Render.
- Owns its session and **commits per chunk** — the API's `flush()`-only convention does
  not apply to a standalone script.
- Keyset pagination: `WHERE id > :last_id ORDER BY id LIMIT 30`. `CHAR(36)` UUIDs order
  lexicographically but stably. `--start-after` resumes an interrupted run.
- Retry on 1205 / 1213 via `utils/db_retry.retry_on_lock_timeout`.
- Idempotent; safe to re-run from the beginning.

**Four statements per chunk**, not thirty-one:

1. `SELECT` the 30 IOC rows.
2. One `SELECT ... GROUP BY ioc_id` over `ioc_sources` → distinct `feed_id` count, plus
   the enabled-feed count for `has_enabled_feed_source` in the same query.
3. One `SELECT` over `enrichments` for those 30 ids, grouped in Python.
4. One `executemany UPDATE`.

`source_count` is **distinct `ioc_sources.feed_id`**, never `sighting_count`.

`iocs` carries no derived category or colour column — only `threat_score` and
`confidence` — so nothing else needs updating in statement 4. Verified against
[backend/app/models/ioc.py](../../../backend/app/models/ioc.py).

`--dry-run` computes without writing and prints band counts before and after using the
76/51/26 thresholds from `get_score_category`. Statement count is logged per chunk so the
"4, not 31" claim is measurable by log inspection.

**Run-order guard.** `WHERE manual_score_override IS NULL`, applied only when the column
exists (probed once via `information_schema`), so the script is correct both before and
after the Spec 2 Phase 4 migration.

---

## 7. Section 4 — confirmations

| Item | Status found |
|---|---|
| Type guards on `reputation_scores` | **landed** — `_mean_reputation_scores`, ten parametrised cases |
| Dead `ratio` / `total_feeds` removed | **landed** — `test_total_feeds_parameter_is_gone` pins it |
| Flat-30 characterised as "a field nothing writes" | **landed** — docstring and test class both say so |
| Next.js rewrite SSRF claim removed | to verify |
| README PostgreSQL badge / stack table / diagram / quick start / repo URL | to verify |
| H-01 restated (nginx not in Render path, limiter does not coordinate) | to verify |
| `PROJECT_SUMMARY.md:177` "Starlette internals" → the four docs routes | to fix |
| Spec 2 Phase 4's column list must drop `enabled` | to record |

### 7.1 The two open numbers, settled

**66.** `len(app.routes)` is **62** with `ENVIRONMENT=production ENABLE_API_DOCS=false`
and **66** with docs on. The four extra are FastAPI's docs routes: `/openapi.json`,
`/docs`, `/redoc` and — the one the spec's arithmetic missed — `/docs/oauth2-redirect`.
62 + 4 = 66. The hypothesis was right; it was one short because FastAPI mounts an OAuth2
redirect helper alongside Swagger UI. `PROJECT_SUMMARY.md:177` attributes the four to
"Starlette internals", which is wrong and is corrected.

**58.** Not reproducible as a ceiling. A sweep of 4,032 CVE configurations finds **665**
that score exactly 58; it is not distinctive and appears in no document or fixture. The
reproducible figures are:

| Measurement | Score |
|---|---|
| CVE ceiling, `cve` profile, 1 feed / 5 feeds | 96 / 100 |
| CVE ceiling, old default profile, 1 feed / 5 feeds | 86 / 100 |
| Realistic day-0 KEV CVE, old default profile, 1 feed | 67 |
| Same indicator's old-default trajectory, days 0→365 | 67, 62, 62, 67, 64, 64, 66, 66 |

That trajectory reproduces both the documented urgency inversion and the origin of the
"measured ceiling 66" claim — 66 is where the curve settles at day 180+, not a maximum.

---

## 8. Section 5 — GTM scoping (confirmed, and triggered)

The condition holds. Indicator values reach the URL from three call sites:

- [frontend/src/app/page.tsx:62](../../../frontend/src/app/page.tsx#L62) — `/ioc-search?q=<indicator>`
- [frontend/src/components/layout/Header.tsx:27](../../../frontend/src/components/layout/Header.tsx#L27) — the global header search, present on every signed-in page
- [frontend/src/app/page.tsx:55](../../../frontend/src/app/page.tsx#L55) — `/ioc?search=<url>`

And a fourth leak the spec did not anticipate:
[(bare)/forgot-password/page.tsx:34](../../../frontend/src/app/(bare)/forgot-password/page.tsx#L34)
pushes `/reset-password?email=<address>`, so a user's email address is also in
`page_location`.

GTM and gtag are both in the **root** layout
([frontend/src/app/layout.tsx:99-141](../../../frontend/src/app/layout.tsx#L99-L141)),
so they load on every route group.

**Owner decision: move the public pages into a `(marketing)` route group.**

```
app/
  layout.tsx              no GTM
  (marketing)/
    layout.tsx            GTM + gtag + noscript iframe
    page.tsx  about/  contact/
  (bare)/ (protected)/ (analytics)/    no GTM
```

Route groups do not change URLs, so `/`, `/about` and `/contact` are unaffected. The
property this buys over a pathname allowlist: a new protected route cannot inherit GTM by
forgetting anything. `(bare)` is deliberately excluded — that is where `?email=` lands.

CSP: `script-src` keeps `googletagmanager.com` only on the marketing paths, scoped via
`next.config.js`'s `headers()` source patterns, with `frame-src` for the noscript iframe
scoped the same way. `frontend/public/_headers` is kept aligned per the existing sync
warning.

### 8.1 `?email=` needs its own fix

Excluding `(bare)` stops GTM from seeing the address, but GTM was never the only reader.
`/reset-password?email=<address>` also puts it in:

- **browser history** — persists after logout, visible to anyone with the device
- **the `Referer` header** sent to every external origin loaded by that page — which is
  how the address reaches third parties even with GTM gone
- **access logs** — nginx and any proxy in front of the app, retained indefinitely

`Referrer-Policy` mitigates only the second, and only for origins that honour it.

**Fix:** carry the address in session state instead of the URL. `forgot-password` already
knows it, so it writes it to `sessionStorage` under a short-lived key and
`reset-password` reads it there, falling back to an on-page input if the value is absent
(direct navigation, new tab, or a resumed flow). `sessionStorage` rather than
`localStorage` because the value should not outlive the tab, and not a POST body because
the target is a client-rendered page reached by client navigation, not a form submission.

The OTP itself is unaffected — it is already entered on the page and posted in the body,
never in a URL.

---

## 9. Verification

```bash
cd backend && python -m pytest && python -m compileall -q app alembic tests ../scripts
cd ../frontend && npx tsc --noEmit && npm run build
```

Plus: the four fixtures re-run with numbers; the CVE trajectory (monotone non-increasing,
peak at day 0); a grep for `virustotal`/`phishtank` with the three pivot-link exceptions
named; and the rescore script's per-chunk statement count by log inspection.

Not deliverable here: the `--dry-run` band distribution (no DSN) and the browser console
pass (owner action).

### Environment note

`pymysql`, `aiomysql`, `passlib[bcrypt]`, `bcrypt`, `pyjwt`, `structlog` and
`email-validator` were absent, so `python -m pytest` could not import `app` at all. They
were installed at the versions pinned in `requirements.txt`. The suite passes at **271
tests** before any change in this set.

---

## 10. Open items for the owner

1. Sign-off on the `--dry-run` distribution before the rescore writes (Section 3.4) —
   requires running it against the Hostinger DSN.
2. Spec 2 Phase 4 must drop `enabled` from its column list; `is_enabled` is the column.
3. Still outstanding from Spec 2: email provider, PDF reports in UAT scope, the four UTC
   cron times, Render region, free instance versus $7 Starter.
4. Browser console pass over login, dashboard, IOC search, IOC detail and ATT&CK.
