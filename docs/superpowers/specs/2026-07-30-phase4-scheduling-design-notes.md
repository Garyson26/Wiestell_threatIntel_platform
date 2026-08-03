# Design Notes for Spec 2 Phase 4 — Feed Scheduling Columns

**Date:** 2026-07-30
**Status:** notes only. Nothing here is implemented except where marked *shipped*.
**Purpose:** correct three defects in the Phase 4 design before it is written
(§1 scheduling drift, §2.3 a redundant column, §2.5 the traffic claim), and reconcile
its proposed column list against the schema that actually exists.
**Blocked on:** `SHOW CREATE TABLE feed_sources;` from production — §2 reconciles
against the *model*, which may have drifted from the live table.

---

## 1. The skip-alignment defect, and why `sync_frequency < cron_interval` does not generalise

### 1.1 Measured behaviour

`sync-all` in its default smart mode evaluates
`overdue = last is None or (now - last).total_seconds() >= freq`, and
`last_sync_at` is stamped when ingestion **finishes**
([feed_ingestion.py:121](../../../backend/app/services/feed_ingestion.py#L121)).

Simulated against a 6-hour cron with a 10-minute sync duration:

| `sync_frequency` | intended interval | actual | run times (hours) |
|---|---|---|---|
| 1h | 6h | **6h** ✓ | 0, 6, 12, 18, 24, 30 |
| 3h | 6h | **6h** ✓ | 0, 6, 12, 18, 24, 30 |
| 6h (= cron) | 6h | **12h** | 0, 12, 24, 36, 48 |
| 12h (2×) | 12h | **18h** | 0, 18, 36, 54, 72 |
| 24h (4×) | 24h | **30h** | 0, 30, 60, 90, 120 |
| 72h (12×) | 72h | **78h** | 0, 78, 156, 234 |

### 1.2 Two refinements to the diagnosis

**The penalty is exactly one cron period, and it does not accumulate.** Each run
stamps a fixed offset past a tick, so the schedule settles into a stable rhythm at
`(k + 1) × cron_interval` for `sync_frequency = k × cron_interval`. The 12-hour feed
runs at 0, 18, 36, 54 — a constant 18-hour gap, not a widening one. Bounded and
predictable, but permanently wrong.

**`sync_frequency < cron_interval` is not a general rule.** It works for
MalwareBazaar only because that feed is *meant* to sync on every firing. It cannot
express "every 72 hours" at all — any value that coarse necessarily lands on a
multiple and inherits the penalty. CISA KEV at 72h is the case that breaks it.

### 1.3 The fix

Compute the next-due time from the attempt's **start**, captured before the fetch,
not from its completion.

```python
attempt_started_at = _naive_utc()          # BEFORE connector.run()
iocs = await connector.run()
... ingest ...
feed.last_attempt_at = attempt_started_at  # see 1.3.1 — NOT last_sync_at
```

With a zero effective offset the simulation gives exact intervals for every value,
including `sync_frequency == cron_interval`:

| `sync_frequency` | actual | run times |
|---|---|---|
| 6h | **6h** ✓ | 0, 6, 12, 18, 24 |
| 12h | **12h** ✓ | 0, 12, 24, 36, 48 |
| 24h | **24h** ✓ | 0, 24, 48, 72, 96 |
| 72h | **72h** ✓ | 0, 72, 144, 216, 288 |

**Spec 2 §4.3 has the identical defect.** It specifies
`next_due_at = now() + interval` *after each attempt*, which is completion time and
reproduces the table in §1.1 exactly. Compute it from the attempt's start timestamp.

### 1.3.1 Split the field rather than choosing between its two meanings

`last_sync_at` currently carries two jobs — scheduling input and "last successful
ingest" for `dashboard/feed-health` — and the fix above would force a choice between
them. A second column resolves both at once:

| Column | Meaning | Stamped |
|---|---|---|
| `last_attempt_at` *(new)* | scheduling input | at attempt **start**, on **every** attempt including failures |
| `last_sync_at` *(existing)* | last **successful** ingest | unchanged — on success only |

That gives three properties simultaneously:

- scheduling gets exact intervals, because the value it reads is stamped before the
  work rather than after it;
- "last successful sync was three days ago" stays visible to feed-health and the
  dashboard, with no change to either;
- **a permanently failing feed can no longer look healthy.** Today a feed that
  fails fast still updates nothing useful; with the split, `last_attempt_at`
  advancing while `last_sync_at` stands still is exactly the signal that a feed is
  broken rather than idle, and it pairs naturally with `consecutive_failures`.

It also removes the coupled decision entirely: stamping the start on failed attempts
becomes unambiguous, because it goes to `last_attempt_at` and cannot be mistaken for
a successful ingest.

**So `last_attempt_at` is a fifth genuinely-new Phase 4 column.** The smart-mode
check becomes:

```python
overdue = feed.last_attempt_at is None or (
    (now - feed.last_attempt_at).total_seconds() >= freq
)
```

Migration note: backfill `last_attempt_at = last_sync_at` so existing feeds are not
all judged immediately overdue on the first tick after deploy.

### 1.4 Interim state (shipped)

`MalwareBazaarFeed.default_sync_frequency` stays at 3600 — a *floor* below the cron
interval so every firing syncs — with `_GOVERNING_SYNC_INTERVAL_SECONDS = 6 * 3600`
as the figure tests assert against. That is a workaround for one feed, not a
solution. Phase 4's start-timestamp fix is what generalises it.

---

## 2. Column reconciliation

### 2.1 What `feed_sources` actually has

Generated from the model on 2026-07-30 (see the caveat below):

```sql
CREATE TABLE feed_sources (
    id                    VARCHAR(36) NOT NULL,
    name                  VARCHAR(100) NOT NULL,
    slug                  VARCHAR(100) NOT NULL,
    description           TEXT,
    feed_type             VARCHAR(20) NOT NULL,
    url                   TEXT,
    api_key_env           VARCHAR(100),
    is_enabled            BOOL NOT NULL DEFAULT true,
    sync_frequency        INTEGER,
    last_sync_at          DATETIME,
    last_sync_status      VARCHAR(20),
    last_sync_error       TEXT,
    last_ingest_watermark DATETIME,
    last_ingest_gap       TEXT,
    ioc_count             INTEGER,
    config                JSON,
    created_at            DATETIME,
    PRIMARY KEY (id),
    UNIQUE (slug)
)
```

**Caveat:** this is the **model's** DDL, not production's. `iocs` has already been
shown to have drifted from its model, so `feed_sources` may have too.
`SHOW CREATE TABLE feed_sources;` should be captured alongside the `iocs` one.

### 2.2 Phase 4's proposed columns, reconciled

| Proposed | Verdict |
|---|---|
| `enabled` | **exists** as `is_enabled`, filtered on by four call sites. Revision `e5f6a7b80002` tightened it to `NOT NULL DEFAULT TRUE`. |
| `last_ingest_watermark` | **exists** — added by `f6a7b8c90003`. |
| `last_ingest_gap` | **exists** — added by `f6a7b8c90003`. |
| `sync_interval_minutes` | **redundant.** `sync_frequency` already exists, in seconds, and is already honoured by smart mode, the asyncio scheduler tick and the Celery task. Two cadence fields with nothing keeping them in step is the bug this table is meant to prevent. Keep `sync_frequency`; if minutes are wanted for readability, make it a computed property, not a column. |
| `next_due_at` | **CUT** — see §2.3. |
| `http_etag` | **genuinely new.** Nothing equivalent exists; no code references ETags. |
| `http_last_modified` | **genuinely new.** No `If-Modified-Since` handling anywhere. |
| `sync_cursor` | **genuinely new.** The only `cursor` in the codebase is the DBAPI cursor in `database.py`. |
| `consecutive_failures` | **genuinely new.** No failure counter or back-off state exists; `last_sync_status` records only the most recent outcome. |

So the genuinely new set is the four predicted from the docs —
**`http_etag`, `http_last_modified`, `sync_cursor`, `consecutive_failures`** — plus
**`last_attempt_at`** from §1.3.1, which the reconciliation itself surfaced. Five in
total; `enabled`, `last_ingest_watermark`, `last_ingest_gap`,
`sync_interval_minutes` and `next_due_at` are all dropped.

### 2.3 `next_due_at` — cut

**Decision: do not add it.** The performance case does not clear the bar.

`last_attempt_at + sync_frequency` is what smart mode computes, and with **11 feeds**
`ORDER BY last_attempt_at + INTERVAL sync_frequency SECOND` costs nothing
measurable. Against that, materialising it introduces derived state that can
disagree with its inputs: a `sync_frequency` change leaves stale `next_due_at`
values, so a new cadence silently does not take effect until each feed next runs —
a real bug class, and one that is hard to spot because everything keeps working,
just on the old schedule.

Revisit only if the feed count reaches a scale where the expression is measurably
hot, and if it is ever added, derive it in the same statement that stamps
`last_attempt_at` so the two cannot drift.

### 2.4 A note on `config`

`feed_sources.config` is a JSON column that is **written on create and never read
anywhere**. It is dead today. It is tempting as a home for `sync_cursor`, but
`FeedUpdate` replaces `config` wholesale, so an operator editing config through the
API would silently wipe machine-managed state — which is why the watermark got a
dedicated column instead. Either give `sync_cursor` its own column too, or
namespace `config` and stop `FeedUpdate` replacing it wholesale. Do not do neither.

---

## 2.5 Correction to Spec 2 §4.4 — the traffic claim

Spec 2 §4.4 states that conditional requests (`If-None-Match` / `ETag`) would cut
feed bandwidth by **80–90%**. That figure assumes largely static files. It does not
hold for the feeds this platform actually polls.

URLhaus's `csv_recent` and ThreatFox's exports **regenerate continuously** — the
measured MalwareBazaar export carries a `Last updated` header stamped minutes before
the fetch, and abuse.ch documents its exports as regenerating every 5 minutes. A
six-hourly poll will therefore essentially always see a changed file, and a `304`
will rarely fire.

**Where the saving actually comes from: cadence.** Polling four times a day instead
of hourly is what reduces transfer, by a factor of six, and that is independent of
ETags. Conditional requests contribute close to nothing at this interval.

Keep `http_etag` and `http_last_modified` — they are cheap, correct, and they *do*
pay off for the feeds that genuinely are static-ish (CISA KEV's JSON catalogue,
eCrimeLabs' CVE list, MISP CERT-FR's hash file, all polled daily or less). But:

- **the traffic budget must not be built on them**; size it from cadence and
  measured file sizes (URLhaus `csv_recent` alone is 3.0 MB per fetch);
- state the expected 304 hit rate per feed rather than one blended figure, because
  it differs by an order of magnitude between the continuously-regenerated exports
  and the daily catalogues;
- measure it after implementing rather than projecting it — the ETag response can be
  logged per sync at no cost.

---

## 2.6 The enrichment selection, and sizing its quota before building it

`enrichment/step`'s selection is Phase 4 work, not Spec 5 work — it is already
specified there as "no enrichment row **or** `expires_at` passed", which is the
correct condition. Fixing it in Spec 5 would mean writing it twice.

What Spec 5 established is that the **current** condition is a one-way gate, and
that this is a live defect rather than a design gap:

```python
select(IOC).outerjoin(Enrichment, IOC.id == Enrichment.ioc_id)
           .where(Enrichment.id.is_(None))      # never-enriched only
           .limit(enrich_limit)                  # default 100
```

Three consequences, all currently in effect:

1. **An IOC enriched once is never re-enriched.** `_rescore_from_enrichment` therefore
   never fires for it again.
2. **`expires_at` never causes a refresh on the cron path.** The TTL is honoured inside
   `_get_cached_enrichment`, but only once enrichment has been *triggered* for that
   IOC — which this selection prevents. So `CACHE_TTL_REPUTATION` does not roll the
   cache over, and every "transitional" fallback that depended on it is permanent
   (see §2.7).
3. **The freeze trap already exists.** Spec 5 §4 frames it as arising from a future
   `threat_score >= 51` selection; it is already here in a different form.

### 2.6.1 Size the quota before writing the code

Once the selection includes expired rows, the population becomes "every IOC whose
enrichment has aged out", which is unbounded rather than one-shot. `enrich_limit`
and the cron cadence together set the steady-state API call rate, and that rate has
to fit inside free-tier limits. Measure, do not estimate:

```sql
-- How many enrichment rows exist, and how stale are they?
SELECT source, COUNT(*) AS rows,
       SUM(expires_at IS NULL)              AS no_ttl,
       SUM(expires_at <= NOW())             AS already_expired,
       MIN(expires_at), MAX(expires_at)
FROM enrichments GROUP BY source ORDER BY rows DESC;

-- How many IOCs have no enrichment at all (the current selection's population)?
SELECT COUNT(*) FROM iocs i
LEFT JOIN enrichments e ON e.ioc_id = i.id WHERE e.id IS NULL;

-- Corpus size by type, which bounds the steady-state refresh rate.
SELECT type, COUNT(*) FROM iocs GROUP BY type;
```

Then compute the steady-state cost per refresh cycle, per provider. The binding
constraints are the free tiers: **OTX** and **AbuseIPDB** (AbuseIPDB's free plan is
notably tight on daily checks), plus NVD's 5 requests/30s unauthenticated or 50/30s
with a key. Note that one IOC refresh is **several** provider calls — the reputation
enricher alone queries every configured provider that supports the type — so the call
count is not the row count.

Deliverable for Phase 4: a table of rows-per-source, expiry distribution, and the
resulting calls-per-day at candidate `(enrich_limit, cadence)` pairs. That table sets
the values; picking them first and discovering the ceiling in production is the
failure mode to avoid.

## 2.7 Three fallbacks are permanent, not transitional

Because §2.6 point 2 means cached enrichment never refreshes, every mechanism written
as "temporary until TTLs roll over" is load-bearing indefinitely — until Phase 4 lands:

| Fallback | Where | Originally described as |
|---|---|---|
| Old-shape reputation payloads route to *unknown* | `_reputation_providers`, `_reputation_provider_responded` | "expires naturally via CACHE_TTL_REPUTATION" |
| `error*` prefix match for failure detection | `_reached_a_verdict` | to be retired once `assessed` lands |
| `assessed`-absent legacy inference | Spec 5 §1, not yet built | "removable once TTLs have rolled the cache over" |

All three docstrings and the Spec 3 design document have been corrected. The
practical consequence: **do not delete any of them as cleanup** before Phase 4's
selection fix has landed and a full refresh cycle has demonstrably completed.

---

## 2.8 BLOCKER — a single feed's sync can exceed Render's idle window

Not an observation. This decides whether Phase 4's `sync-due?max=1` design is viable
at all.

Measured statements per full sync, at 30 rows per chunk:

| Feed | rows | chunks | statements |
|---|---|---|---|
| URLhaus `csv_recent` | 15,524 | 518 | **3,626** |
| ThreatFox exports | 2,486 | 83 | 581 |
| MalwareBazaar public | 2,643 | 89 | 623 |

At Render→Hostinger latency, for URLhaus alone:

| per round-trip | URLhaus sync wall-clock |
|---|---|
| 50 ms | 3.0 min |
| 150 ms | 9.1 min |
| 300 ms | **18.1 min** |

**Render's free-instance spin-down is driven by absence of inbound HTTP traffic, not
by whether the process is busy.** A 15-minute idle window therefore expires *during*
a long sync: the instance is working hard and receiving nothing, which is exactly the
condition that spins it down. At 300 ms per round-trip a single URLhaus sync exceeds
the window on its own.

Consequences for Phase 4:

- **`sync-due?max=1` is not automatically safe.** One feed is not a small unit of
  work; URLhaus is 3,626 round-trips.
- **The outstanding owner latency measurement is decision-driving, not
  informational.** It determines whether Phase 4 needs resumability *within* a feed
  (a `sync_cursor` that survives a spin-down mid-feed) or only *between* feeds.
- Section 3's re-read gate and §2.9's read-chunk sizing both cut this substantially,
  and probably resolve it — but "probably" is not a basis for the design. Measure
  latency, then re-derive these numbers.

### 2.8.1 Correction — the write volume is a fifth of what I first reported

I reported 30,826 records per sync × 4 syncs = ~123,300 writes/day for the full-list
feeds. **That assumed every feed syncs in every window, which Phase 4's cadence does
not do.** Re-derived against the real cadence, and after §2.9's cumulative-catalogue
fix:

| Feed | rows | cadence | kind | writes/day |
|---|---|---|---|---|
| URLhaus `csv_recent` | 15,524 | 6h | timestamped | ~0 (gated) |
| ThreatFox exports | 2,486 | 6h | timestamped | ~0 (gated) |
| MalwareBazaar public | 2,643 | 6h | timestamped | ~0 (gated) |
| blocklist.de `all.txt` | 23,112 | 24h | current-state | **23,112** |
| Emerging Threats | 586 | 24h | current-state | 586 |
| CISA KEV | 1,656 | 72h | cumulative | **0** |
| eCrimeLabs Metasploit | 3,195 | 72h | cumulative | **0** |
| MISP CERT-FR | 2,277 | 72h | cumulative | **0** |
| **total** | | | | **23,698/day** |

**23,698 writes per day — 19% of the figure I quoted**, and concentrated in a single
daily blocklist.de sync rather than spread over four. The cumulative catalogues
contribute nothing at all now that they are correctly frozen.

**So this decision should not be driven by the spin-down blocker.** The write volume
is not the problem; the *read* volume is — 108,686 rows read per day, all of which
must be read whatever the gate then decides. That is §2.9's territory, and it is the
largest remaining performance item.

Record the measured latency in this document before Phase 4 is written.

## 2.9 Decouple read chunk size from write chunk size

The 30-row chunk exists for one reason: holding InnoDB row locks for the duration of a
single `executemany` UPDATE rather than across a Python loop. **Plain `SELECT`s take
no row locks** under `REPEATABLE READ` — they are consistent reads served from the
MVCC snapshot — so the read phase has no reason to share that size.

Per chunk the reads are: the `iocs` lookup, the grouped distinct-feed count, the
already-linked set, and (post-gate) enrichment. Four statements amortised over 30 rows
today; over 200–500 rows they would be amortised 7–17× better.

| read chunk | URLhaus read chunks | read statements | vs 30-row |
|---|---|---|---|
| 30 | 518 | ~2,072 | — |
| 200 | 78 | ~312 | −85% |
| 500 | 31 | ~124 | **−94%** |

At 300 ms that is roughly 37 s of read round-trips instead of 10 min.

**Writes stay at 30, and the commit stays per write batch.** A 500-row read chunk
committing once at the end would hold locks across ~17 write statements — strictly
worse than today. The shape is a nested loop: read 500, then write and commit in
sub-batches of 30.

### 2.9.1 Correcting my own reason for deferring this

I first deferred this on the grounds that it would mean "rewriting the locking
strategy", which CLAUDE.md forbids. **That was wrong.** Reading 500 rows while still
writing in 30-row committed batches preserves every element of the documented
invariant — one lock-free `SELECT`, `INSERT ... IGNORE` for new rows, one
`executemany` UPDATE per batch, commit per batch, retry on 1205/1213. It is a nested
loop, not a change of strategy.

Where the coupling actually lives: `ingest_iocs` slices `valid` at `batch_size` and
hands each slice to `_process_async_chunk_with_retry`, which performs reads, writes
and commit for that one slice. Read and write chunk are the same unit *because the
outer loop makes them so* — and loosening that is the change, not rewriting locking.

**The real obstacle is smaller and different: ORM object expiry across a retry.**
`_ingest_chunk` holds `existing_map` as live ORM `IOC` instances and reads
`existing.tags`, `.sighting_count`, `.last_seen`, `.metadata_`, `.mitre_techniques`
during scoring. `session.rollback()` on a 1205 expires every one of them, so a write
sub-batch that retries cannot reuse the snapshot the read phase built — accessing an
expired attribute raises, which is exactly why
`_process_async_chunk_with_retry` re-fetches the feed row on every attempt.

Two ways through:

1. **Snapshot the reads into plain data** — extract the handful of fields scoring
   needs into dicts or a small frozen dataclass before the write phase. A rollback
   then cannot invalidate them, one retry does not re-issue the reads, and the loop
   stops depending on ORM identity at all. Mechanical, and it *removes* an existing
   fragility rather than adding one.
2. **Re-read on retry** — keep ORM instances and accept that a retry re-issues the
   grouped reads for that read chunk. Simpler, and retries are rare, but it makes the
   worst case worse than today.

(1) is the right shape. It is a real refactor of `_ingest_chunk` rather than a
parameter change, which is the honest reason it is not in Spec 5 — not the locking
strategy.

**Tune by measurement, not by picking a number.** 500 IOC rows plus their enrichment
JSON held in Python at once is the binding constraint on a 512 MB instance, and the
`deploy.resources.limits` ceiling in `docker-compose.yml` makes that measurable
locally. Measure resident memory at 200, 350 and 500 before settling.

### 2.9.2 What the saving is worth after Section 3

Section 3 changed the arithmetic, so re-derive rather than reusing the table above:

| Population | records/sync | gate outcome | reads still needed |
|---|---|---|---|
| URLhaus, ThreatFox, MalwareBazaar | 20,653 | mostly skipped | yes — the reads are how you know |
| full-list exports (blocklist.de et al.) | 30,826 | always re-scored | yes |

The gate removes *writes*, not *reads*: you cannot decide to skip a row without first
reading it. So the read-side cost is unchanged by Section 3 and this remains the
largest single remaining win — roughly 51,000 records per sync, all of which must be
read whatever the gate then decides.

---

## 2.10 Source-shape taxonomy — designed, to be built in Phase 4

Two `BaseFeed` attributes currently describe how a source's record set changes between
fetches, and they answer two different questions:

| Attribute | Question | Drives |
|---|---|---|
| `rolling_window` | does the record set slide, so records can fall through a sync gap? | watermark gap detection (`_check_window_continuity`) |
| `full_list_kind` | does the source republish everything without timestamps, and does its list expire or accumulate? | `sighting_count` and `last_seen` semantics |

A mutual-exclusion guard holds the incoherent state out
(`tests/test_feeds.py::TestDeclarationTaxonomy`), so this is a clarity problem rather
than a correctness one. **Collapse belongs in Phase 4**, which already owns gap
detection, cursors, cadence and the `feed_sources` columns — all three of which the
taxonomy informs. It was briefly slated for Spec 5 §1 on the grounds that `assessed`
touches the same declaration surface; it does not — `assessed` is on `BaseEnricher`,
these are on `BaseFeed`, different hierarchies with no overlap.

### 2.10.1 The shape

**One declaration of source shape, with "does it carry timestamps" as a separate
fact.** Both gap detection and counter semantics derive from the pair. Collapsing to a
single enum that also encodes timestamp-ness would conflate a monitoring question with
a scoring question and have to be re-split.

```python
SLIDING_WINDOW       # holds "the last N hours"; records age out
CURRENT_STATE_LIST   # holds everything currently true; entries expire
CUMULATIVE_CATALOGUE # only grows; entries never leave
INCREMENTAL          # a delta stream; returns only what changed since a cursor
```

Timestamp-ness stays discoverable per record via `_source_timestamped`, which
`_make_ioc` already records.

| Shape | Gap monitoring | `last_seen` | counter |
|---|---|---|---|
| `SLIDING_WINDOW` | **yes** — records can age out between syncs | from source | on source advance |
| `CURRENT_STATE_LIST` | no — nothing is lost, the list is complete | advances (presence re-asserts liveness) | frozen |
| `CUMULATIVE_CATALOGUE` | no — nothing ever leaves | from source if available, else frozen | frozen |
| `INCREMENTAL` | no — the cursor guarantees continuity | from source | **on reappearance** |

### 2.10.2 `INCREMENTAL` — the fourth value OTX needs

The three-value enum does not cover OTX. Its `modified_since` cursor means it never
republishes: it returns only what changed. So it is neither sliding, current-state nor
cumulative.

The distinctive property is that **a record reappearing genuinely was modified**, so
incrementing is correct — which is exactly what "declaring neither" gives it today, by
accident rather than by declaration. Gap monitoring is unnecessary because the cursor
guarantees continuity: nothing can fall between two fetches, since the second fetch
starts where the first ended. That is a stronger guarantee than the watermark check
provides, and declaring it makes the reason explicit rather than incidental.

Candidates for each shape, from the 2026-07-31 audit:

| Shape | Connectors |
|---|---|
| `SLIDING_WINDOW` | URLhaus, ThreatFox, MalwareBazaar |
| `CURRENT_STATE_LIST` | blocklist.de, Emerging Threats, **AbuseIPDB**, **Feodo Tracker** |
| `CUMULATIVE_CATALOGUE` | CISA KEV, eCrimeLabs, MISP CERT-FR |
| `INCREMENTAL` | **OTX** |

The three currently declaring nothing all become declarable, which is the point:
AbuseIPDB's blacklist ("most reported in the last N days") and Feodo Tracker's
recommended list (currently-active C2s) *are* current-state lists — they simply also
carry timestamps, which today's two-attribute scheme cannot express.

### 2.10.3 CISA KEV is being treated as timestamp-free when it is not

**Found 2026-07-31.** `cisa_kev.py:87` reads `dateAdded` into
`metadata["date_added"]` — and then never passes it to `_make_ioc`. So `_make_ioc`
defaults `first_seen`/`last_seen` to `now()`, `_source_timestamped` is False, and
**`last_seen` records the date we ingested the entry rather than the date CISA added
it — potentially years apart.**

Passing it through puts KEV on the timestamp path, and the behaviour improves without
the frozen-counter property changing: `dateAdded` never moves for an existing entry,
so the gate still never fires. What changes is that recency becomes accurate — a newly
added KEV CVE reads fresh, a 2021 entry decays correctly. That is the difference
between *frozen because we have no information* and *frozen because the source says
nothing changed*.

Checked the other two cumulative feeds for the same defect:

| Feed | Date available? | Action |
|---|---|---|
| **CISA KEV** | **yes** — `dateAdded` per entry, already parsed into metadata | pass it to `_make_ioc` |
| eCrimeLabs Metasploit | **no** — verified: the feed is one bare CVE ID per line, 3,195 lines, no ISO date anywhere in the response | genuinely timestamp-free |
| MISP CERT-FR | **not in `hashes.csv`** (two columns: hash, event UUID) — but the MISP `manifest.json` carries per-event dates, and the CSV's second column is that event UUID, so it is **joinable** | see below |

For MISP CERT-FR the join is available but costs a second fetch and a UUID→date map.
Worth doing — event date is a far better `first_seen` than ingest date for
incident-response hashes — but it changes what the connector fetches, so it belongs
with the taxonomy work rather than being smuggled in.

**All three are score-affecting** (recency moves), so whichever change set lands them
bumps `SCORING_MODEL_VERSION` per §6.5 of the freeze-trap design. Not done in Spec 5
§1, which is `assessed` alone.

---

## 3. Phase 6.3 requirement — the cadence constant must be checked against the workflow

`MalwareBazaarFeed._GOVERNING_SYNC_INTERVAL_SECONDS = 6 * 3600` hardcodes a schedule
that will actually live in `.github/workflows/*.yml` once Phase 6.3 writes it.
Nothing makes the two agree. If the owner picks three windows a day instead of four,
the constant is silently wrong by 2 hours **and the margin test still passes** —
which is the same class of defect as the rest of this document: a number asserted in
one place and enforced in another.

**When 6.3 writes the workflow, add a test that:**

1. globs `.github/workflows/*.yml`;
2. extracts every `schedule: - cron:` expression;
3. computes the minimum interval between consecutive firings (not just the count —
   `0 0,1,2,18 * * *` fires four times a day but has a 1-hour minimum gap and a
   16-hour maximum, and it is the **maximum** gap that matters for window loss);
4. asserts it matches `_GOVERNING_SYNC_INTERVAL_SECONDS`;
5. skips with a clear reason if no workflow file exists yet, so it is harmless until
   6.3 lands.

Note step 3 carefully: the naive implementation counts entries and divides 24 hours
by the count, which is wrong for any non-uniform schedule. Compute the actual
worst-case gap, including the wrap-around from the last firing of one day to the
first of the next.

---

## 3.5 Phase 5 note — ingest write volume is mostly redundant

URLhaus's `csv_recent` holds **15,524 URLs**, and every one of them is re-read on
every sync. The existing-row branch builds an `update_mappings` entry
unconditionally, so the `executemany` UPDATE touches ~15k rows four times a day
against a shared MySQL host — precisely the InnoDB lock-contention scenario that
`feed_ingestion`'s 30-row chunking, per-chunk commits and 1205/1213 retry exist to
survive. Almost all of that write volume rewrites values that did not change.

This is an independent argument for the timestamp gate in
[2026-07-30-sighting-count-and-recency-design.md](2026-07-30-sighting-count-and-recency-design.md):
**if the source timestamp has not advanced, there is nothing to write** — skip the
row from `update_mappings` rather than writing an identical one. Expected effect for
URLhaus: from ~15k rows per sync to the few hundred that are genuinely new or
advanced.

Measure it with the `-m mysql` statement counter after implementing; do not assert
the reduction.

One interaction to carry into Phase 5: `threat_score` is currently recomputed on
every re-read, so skipping unchanged rows also stops re-scoring them. That is
desirable for write volume, but it means a scoring-model change no longer propagates
through ordinary ingestion and `rescore_corpus.py` becomes the only path that
applies a new model to existing rows.

---

## 4. Cross-references

- Migration chain blocker and the `iocs.value` fix: [2026-07-30-migration-chain-repair-design.md](2026-07-30-migration-chain-repair-design.md)
- `NaiveUTCDateTime` TypeDecorator: [2026-07-30-naive-utc-typedecorator-design.md](2026-07-30-naive-utc-typedecorator-design.md)
- Rolling-window continuity, shipped: revision `f6a7b8c90003`,
  `BaseFeed.rolling_window`, `feed_scheduler._check_window_continuity`
- `sighting_count` / `last_seen` counting re-reads: [2026-07-30-sighting-count-and-recency-design.md](2026-07-30-sighting-count-and-recency-design.md)
