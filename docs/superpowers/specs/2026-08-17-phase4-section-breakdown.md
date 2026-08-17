# Phase 4 — section breakdown

**Status: proposal. No code written.** Requested 2026-08-17 after the owner confirmed
`HANDOFF_SPEC_2_PLATFORM.md §Phase 4` is substantially obsolete — it predates the taxonomy
collapse, the `Enrichment.id IS NULL` finding landing here, the read-chunk work, the
ORM-expiry refactor, the `INCREMENTAL` kind, `manual_score_override`, and the column-list
corrections. The current source of truth is
[2026-07-30-phase4-scheduling-design-notes.md](2026-07-30-phase4-scheduling-design-notes.md);
this document turns those notes into an ordered, gated plan.

## The organising principle

The notes contain two very different kinds of work, and the failure mode is doing them in
one pass:

* **Mechanical and fully specified** — five columns, a cadence arithmetic fix, read-chunk
  sizing. The design decisions are already made and recorded; these are transcription
  plus tests.
* **Genuinely new engineering** — the OTX `modified_since` cursor and the `INCREMENTAL`
  shape. This changes what a connector fetches and how continuity is guaranteed, and it
  is the only part where the design could still turn out wrong.

They are separated below with gates between them, so the mechanical work can land and be
verified without the cursor rewrite in flight.

---

## Gate 0 — two owner measurements, one of which is decision-driving

**§2.8 is marked BLOCKER and it still is.** Render's free-instance spin-down keys on
absence of *inbound HTTP*, not on whether the process is busy — so a long sync spins the
instance down while it is working. URLhaus alone is 3,626 round-trips at the current
30-row chunk:

| per round-trip | URLhaus sync wall-clock |
|---|---|
| 50 ms | 3.0 min |
| 150 ms | 9.1 min |
| 300 ms | **18.1 min — exceeds the 15-minute window on one feed** |

**Q0.1 — Render→Hostinger round-trip latency.** This decides whether Phase 4 needs
resumability *within* a feed (a `sync_cursor` surviving a mid-feed spin-down) or only
*between* feeds. That is an architectural fork, not a tuning parameter, so Section D
should not start before it is answered. Section B below probably resolves it — reads drop
~94% — but "probably" is not a basis for the design.

**Q0.2 — the enrichment quota counts (§2.6.1).** Three queries, already written in the
notes: rows and expiry distribution per source, IOCs with no enrichment at all, and corpus
size by type. These size Section E; picking `enrich_limit` first and discovering a free-tier
ceiling in production is the failure mode being avoided.

Everything from Section A to Section C can proceed while these are outstanding.

---

## Section A — the five columns and the cadence fix *(mechanical)*

One migration, one behaviour change. §2.2 reconciled the proposed column list down to five
genuinely new ones; `enabled`, `last_ingest_watermark`, `last_ingest_gap`,
`sync_interval_minutes` and `next_due_at` are all dropped or already exist.

| Column | Purpose |
|---|---|
| `last_attempt_at` | scheduling input, stamped at attempt **start**, on every attempt including failures |
| `sync_cursor` | OTX `modified_since`; its own column, **not** `config` (§2.4 — `FeedUpdate` replaces `config` wholesale) |
| `http_etag` | conditional requests |
| `http_last_modified` | conditional requests |
| `consecutive_failures` | back-off state |

**A1.** Migration adding the five, with `last_attempt_at` backfilled from `last_sync_at` so
no feed is judged instantly overdue on the first tick after deploy.

**A2.** The cadence fix (§1.3): compute next-due from the attempt's **start**, captured
before `connector.run()`, not from its completion. This is what makes
`sync_frequency == cron_interval` behave, and it removes the MalwareBazaar floor workaround
(`_GOVERNING_SYNC_INTERVAL_SECONDS`) rather than generalising it.

**A3.** The `last_attempt_at` / `last_sync_at` split (§1.3.1). Beyond fixing scheduling this
buys a real signal: `last_attempt_at` advancing while `last_sync_at` stands still is exactly
"this feed is broken, not idle", which today is invisible.

**A4.** Classify the five new columns in `scripts/seed_feeds.py`. Not optional —
`tests/test_seed_feeds.py::test_every_feedsource_column_is_classified` fails until each is
placed in `_CODE_DERIVED`, `_REPORTED_ONLY` or `_OPERATIONAL`. All five are operational;
the guard exists so that is a decision rather than an omission.

**A5.** Retire `_GOVERNING_SYNC_INTERVAL_SECONDS` and update
`tests/test_deploy_config.py`, which currently asserts the cron interval against it.

> **GATE 1 — cadence is correct and deploy-safe.** Simulation reproduces the §1.3 table
> (exact intervals at 6h/12h/24h/72h); the mysql tier is green; nothing about OTX has moved.
> This is a shippable increment on its own.

---

## Section B — decouple read chunk size from write chunk size *(mechanical, largest single win)*

Independent of everything else, and worth doing early because it is what most likely
declasses the Gate 0 blocker.

Plain `SELECT`s take no row locks under REPEATABLE READ, so the read phase has no reason
to share the 30-row write chunk. Nested loop: read 500, write and commit in sub-batches of
30. **Writes stay at 30** — a 500-row read chunk committing once would hold locks across
~17 write statements, strictly worse than today.

| read chunk | URLhaus read statements | vs 30-row |
|---|---|---|
| 30 | ~2,072 | — |
| 500 | ~124 | **−94%** |

≈37 s of read round-trips instead of 10 min at 300 ms. §2.9.2 notes the re-read gate does
not reduce this: the gate removes *writes*, and you cannot decide to skip a row without
reading it, so ~51,000 records per sync must be read regardless.

> **GATE 2 — SPLIT, 2026-08-17.** Section B's merits do not depend on the latency
> number: reading 500 rows instead of 30 removes the same round-trips whatever each one
> costs. So the chunk split landed on its own merits, and the §2.8 re-derivation moved
> out of this gate.
>
> **The §2.8 re-derivation is now a PHASE 6 (post-deploy) verification step**, because
> Render→Hostinger latency cannot be measured before the service exists. Q0.1 as
> originally framed is not answerable pre-deploy at all — timing from a Mumbai
> workstation traverses a different path than Render's edge, so a pre-deploy figure is a
> data point, not the answer. A timing loop against the production DSN from the owner's
> machine would give a **lower bound** if one is wanted; it is an owner action, since no
> DSN exists in the working environment and connecting to production is out of scope here.
>
> What Phase 6 must re-derive, once real latency is known: whether one feed's sync fits
> inside the 15-minute idle window, and therefore whether Section D needs resumability
> *within* a feed or only *between* feeds.

**MEASURED RESULT (2026-08-17, MariaDB 11.8, statement counts on the wire).** The design
note's ~94% figure is READ statements only; total statements include writes, so the
end-to-end saving is smaller and the two should not be conflated:

| scenario | 450 rows, reads at 30 | reads at 500 | total saving |
|---|---|---|---|
| first sync (all rows new) | 77 | 63 | 18% |
| **steady state (all rows exist)** | **106** | **64** | **40%** |

The steady-state saving of 42 statements is *exactly* the predicted read saving —
15 chunks × 3 reads = 45, down to 1 × 3 = 3 — so **reads did drop 93%**, as designed.
Total statements fall 40% because the write path is untouched, which is deliberate.

The first-sync row matters for a different reason: with every row new, `existing_map` is
empty and two of the three reads short-circuit without querying, so only one read runs per
chunk. **A test measuring a first sync would pass with the feature reverted** — which the
first version of `test_read_chunk_sizing.py` did. It now populates first and measures the
second pass.

---

## Section C — taxonomy collapse and the timestamp defects *(mechanical, but score-affecting)*

**C1.** Collapse `rolling_window` + `full_list_kind` into one `source_shape` enum with four
values — `SLIDING_WINDOW`, `CURRENT_STATE_LIST`, `CUMULATIVE_CATALOGUE`, `INCREMENTAL` —
keeping timestamp-ness as a separate per-record fact via `_source_timestamped`. Declare it
on all 11 connectors per the §2.10.2 table. Three connectors that currently declare nothing
become declarable, which is the point.

**C2.** CISA KEV `dateAdded` → `_make_ioc` (§2.10.3). Today it is parsed into metadata and
never passed on, so `last_seen` records *our ingest date* rather than CISA's — potentially
years apart. **Score-affecting: recency moves.**

**C3.** MISP CERT-FR event-date join via `manifest.json`. Also score-affecting, and it
changes what the connector fetches, so it is the one item here that carries real risk.
**Candidate for deferral** — it is the least valuable of the three and the only one needing
a second HTTP call and a UUID→date map.

**C4.** `SCORING_MODEL_VERSION` bump. Per the freeze-trap design §6.5 this is an acceptance
criterion for C2/C3, not a judgement call.

> **GATE 3 — PASSED 2026-08-17. Measured against the live catalogues, and the headline
> is that Section C moves NOTHING in the existing corpus.**
>
> **CISA KEV** (fetched from CISA directly, 1,665 entries, every one with a parseable
> `dateAdded`):
>
> | | days since dateAdded |
> |---|---|
> | min / p25 / median | 6 / 580 / 1,417 |
> | p75 / p90 / max | 1,628 / 1,748 / 1,748 |
>
> 69.1% of the catalogue is 2–5 years old and only 1.1% is under 30 days. Before the fix
> every entry scored recency **100.0** (ingest date); after, the mean is 5.9 —
> **−94.1 recency points**, or **−9.41 composite** at the `cve` profile's 10% recency
> weight.
>
> **MISP CERT-FR** (18 events, stated exactly rather than sampled): span 2020-01-10 to
> 2024-06-04, ages 804–2,411 days. **Every single event is older than 90 days, so all 18
> land on the recency floor of 5.0** — a uniform **−95.0** recency delta, **−14.25
> composite** at the default profile's 15% weight. No distribution to sample; it is one
> value.
>
> **BUT NEITHER POPULATION EXISTS YET.** `cisa-kev` and `misp-cert-fr` are two of the
> three feeds never seeded to production, so there are no rows to move — and no
> `dateAdded` values in the database to have queried in the first place. The CVE rows that
> do exist arrived incidentally via OTX pulses and carry no KEV dates.
>
> **C1 moves nothing either**, and that is by construction rather than luck: AbuseIPDB and
> Feodo Tracker are the only C1-affected feeds that production actually ingests, and both
> branches are gated on `_source_timestamped` precisely so their behaviour is unchanged.
>
> **So Section C's entire score impact is PROSPECTIVE.** It lands with Section G's first
> sync, not with the rescore in Section H. `SCORING_MODEL_VERSION = 10` is still correct —
> the model did change — but the rescore's expected-movement notes must not promise a
> CVE/hash shift that has nothing to act on.
>
> Incidental finding: `cisa_kev.py` uses the GitHub mirror because "direct CISA URLs
> return 403 from Cloudflare". Measured today, the opposite held — the mirror returned
> **429 Too Many Requests** and CISA's canonical URL returned 200. Not changed here (it is
> one observation, not a pattern), but recorded: the stated reason for the mirror no longer
> reproduces, and the mirror is the one that rate-limits.

---

## Section D — the OTX cursor rewrite *(the genuinely new engineering)*

Everything above is transcription. This is not.

**D1.** `sync_cursor` plumbing — read before fetch, write after successful ingest, in the
same statement that stamps `last_attempt_at` where possible so the two cannot drift.

**D2.** OTX `modified_since`. The connector currently re-fetches subscribed pulses wholesale;
with a cursor it returns only what changed. This is what `INCREMENTAL` exists to describe:
gap monitoring is unnecessary because the cursor guarantees continuity, and a reappearing
record genuinely *was* modified, so incrementing `sighting_count` is correct. Today OTX gets
that behaviour by declaring nothing — by accident rather than by declaration.

**D3.** Conditional requests (`http_etag`, `http_last_modified`) for the static exports.
Separable from D2 and lower risk; can slip without blocking anything.

**D4.** `consecutive_failures` and back-off.

**Deliberately out of scope:** `otx_alienvault` has no direct test coverage and that was
left deliberately, because this section rewrites it. Tests are written here, against the
new shape, rather than twice.

> **GATE 4 — verified against the live OTX API**, not a mock. The cursor's correctness is
> a property of the provider's behaviour; a fixture cannot establish that nothing falls
> between two fetches.

---

## Section E — the enrichment selection fix *(score-affecting; gated on Q0.2)*

`enrichment/step` currently selects `WHERE Enrichment.id IS NULL` — never-enriched only. Three
consequences, all live today: an IOC enriched once is never re-enriched; `expires_at` never
causes a refresh on the cron path; and the freeze trap already exists in a form Spec 5 framed
as hypothetical.

Correct condition: no enrichment row **or** `expires_at` passed. But that turns a one-shot
population into an unbounded one, so **Q0.2 must land first** — the deliverable is a table of
rows-per-source, expiry distribution, and resulting calls/day at candidate
`(enrich_limit, cadence)` pairs. OTX, AbuseIPDB and NVD free tiers are the binding constraints,
and one IOC refresh is several provider calls, not one.

**E1.** Only after this lands and a full refresh cycle demonstrably completes may the three
§2.7 fallbacks be removed. They are load-bearing indefinitely until then, and deleting them as
cleanup is the specific mistake that section exists to prevent.

---

## Section F — `ioc_techniques` join table *(promoted: improvement → fix)*

At 217,485 rows, item 17's "comfortable at today's scale" is falsified for any tagged fraction
at or above ~25%. `/attack/matrix` and `/attack/heatmap` fetch every tagged IOC's
`mitre_techniques` and count in Python — 2 statements but linear in corpus size, uncached, per
request.

A normalised `ioc_techniques(ioc_id, technique_id)` turns this into an indexed `GROUP BY`
returning hundreds of rows instead of tens of thousands. Schema work, so it belongs with the
migration in Section A rather than at the end — but it is independent of cadence and can land
on its own.

**Not score-affecting**, so it does not constrain the rescore's position.

---

## Section G — deploy: seed the three missing feeds

`cisa-kev`, `ecrimelabs-metasploit` and `misp-cert-fr` have never been seeded, so production
has never ingested either CVE source. `scripts/seed_feeds.py` is now the only safe path: it
matches by alias group (three production rows use alias slugs), preserves operational state,
and reports rather than writes `url`. Verified idempotent against a replica of production's
exact eight rows.

**Ordering note that affects Section H.** Seeding these feeds changes `source_count` for any
indicator they also report, which moves the source-diversity term. So the three feeds should
be seeded **and allowed to complete one sync** before the rescore — otherwise the rescore
runs against a corpus that is about to change, and a second rescore is needed.

---

## Section H — the rescore, cleanly last

~29,000 statements over 7,250 chunks; **~1 h 13 m at 150 ms, ~2 h 25 m at 300 ms**. A
scheduled maintenance window, not an errand.

It must come after every score-affecting change above — C2, C3, E and G — or it will need
repeating. It must not overlap a live UAT window: the write pass contends with ingestion for
locks on the same table, and 7,250 commits is not a corner case. Note the `--start-after`
resume point before starting.

Analyst-submitted IOCs will **not** move (no evidence → the 20.0 zero-evidence neutral,
recomputed to 20.0). A flat band there is expected, not a skipped-rows bug.

---

## Proposed order

```
Gate 0  (owner: Q0.1 latency, Q0.2 enrichment counts)   ── blocks D and E only
  │
  A  columns + cadence ─────────► GATE 1  shippable increment
  │
  B  read/write chunk split ────► DONE    §2.8 re-derivation deferred to Phase 6
  │
  C  taxonomy + KEV/MISP dates ─► GATE 3  score movement characterised
  │
  D  OTX cursor + INCREMENTAL ──► GATE 4  verified against the live API
  │
  E  enrichment selection            (needs Q0.2)
  F  ioc_techniques                  (independent; can land any time after A)
  G  seed 3 feeds + one sync
  H  rescore                         LAST
```

A, B and F are independent of the outstanding owner queries and of each other. C is
independent but score-affecting. D is the only section carrying design risk, and it sits
behind two gates that exist to shrink it.

## Open questions for the owner

1. **Q0.1 / Q0.2** above — Q0.1 gates Section D's architecture.
2. **Is C3 (MISP CERT-FR manifest join) in or out?** It is score-affecting, needs a second
   fetch and a UUID→date map, and is the least valuable of the three timestamp fixes. My
   recommendation is **out** for Phase 4, recorded as a follow-up — but it is score-affecting,
   so deferring it means it lands after the rescore and would eventually need a second one for
   those hashes.
3. **Does Section F ship with Phase 4 or separately?** It is the largest schema change and is
   unrelated to scheduling. Bundling it means one migration and one deploy; splitting it means
   Phase 4 stays thematically coherent.
