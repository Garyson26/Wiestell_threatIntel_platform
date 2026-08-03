# Design — `sighting_count` and `last_seen` Count Re-reads, Not Observations

**Date:** 2026-07-30
**Status:** **design only — queued for Spec 5.** Not implemented.
**Blocking constraint:** must land **before** `scripts/rescore_corpus.py` runs.

---

## 1. Confirmed mechanism

Two unconditional writes in the existing-row branch of the ingest chunk
([feed_ingestion.py:241-276](../../../backend/app/services/feed_ingestion.py#L241),
mirrored in the sync variant at :470-505):

```python
new_sighting = existing.sighting_count + 1        # unconditional
...
update_mappings.append({
    "sighting_count": new_sighting,
    "last_seen": _now(),                          # unconditional — INGEST time
    ...
})
```

Neither consults the source-reported timestamp. So both fields measure *how many
times we have read a file* and *when we last read it*, not what the source observed.

### 1.1 The inconsistency that makes it unambiguous

The **new-row** path honours the source ([:294](../../../backend/app/services/feed_ingestion.py#L294)):

```python
"first_seen": _strip_tz(raw.get("first_seen")) or now,
"last_seen":  _strip_tz(raw.get("last_seen"))  or now,
```

URLhaus's parser already computes `last_seen = _parse_ts(last_online)` — the
source's own "last confirmed online" timestamp. It is used on first ingest and then
**discarded on every subsequent sync**, replaced by ingest time. The same indicator
is dated one way when new and another way when re-read, and the re-read path is the
one that runs ~122 times.

### 1.2 Scale, from the measured windows

| Feed | Window | Syncs an IOC survives (4/day) |
|---|---|---|
| MalwareBazaar | 47.78 h | ~8 |
| URLhaus `csv_recent` | 733.39 h (30.5 d) | **~122** |
| ThreatFox exports | 4237.04 h (176.5 d) | **~706** |

URLhaus's `csv_recent` holds 15,524 URLs. Each is re-read ~122 times.

---

## 2. Two distinct defects, not one

### 2.1 Sighting frequency inverts

`_sighting_frequency_score` saturates at 100 from 100 sightings — reached after
~25 days of a 30.5-day window. Measured composite for a URLhaus URL (1 feed,
`malware` tag, no reputation providers configured):

| Age in window | sightings | frequency term | composite |
|---|---|---|---|
| 0 d | 1 | 10.0 | **36** |
| 1 d | 4 | 25.0 | 39 |
| 7 d | 28 | 70.0 | 46 |
| 25 d | 100 | 100.0 | **50** |
| 30 d | 120 | 100.0 | 50 |

**A three-week-old URL scores 14 points above a brand-new one on identical
evidence.** The only difference is how long it sat in a file. This is the same shape
as the CVE urgency inversion and the same principle as the `source_count` fix: count
the event, not the read.

ThreatFox is worse — 706 re-reads means the term is pinned at 100 for essentially
every IOC older than 25 days, so 15% of the composite carries no information at all.

### 2.2 Recency goes dead

Because `last_seen` is overwritten with `_now()` on every sync, `_recency_score`
returns 100.0 (`age < 1 hour`) for **every re-read row**, regardless of the
indicator's true age. It only discriminates once a feed *stops* republishing.

So the two terms fail differently and both are worth stating:

| Term | Weight | Failure |
|---|---|---|
| sighting frequency | 15% | **inverts** — rises with time-in-window |
| recency | 15% | **dies** — frozen at maximum for every re-read row |

Together, 30% of the default composite is decoupled from the indicator.

Under a timestamp gate the recency term recovers its intended decay:
100 → 65 (1 d) → 40 (7 d) → 20 (30 d).

---

## 3. Proposed fix

Increment `sighting_count`, and advance `last_seen`, **only when the
source-reported timestamp is later than what is stored**.

```python
source_last_seen = _strip_tz(raw.get("last_seen")) or _strip_tz(raw.get("first_seen"))

advanced = source_last_seen is not None and (
    existing.last_seen is None or source_last_seen > existing.last_seen
)

new_sighting = existing.sighting_count + (1 if advanced else 0)
new_last_seen = source_last_seen if advanced else existing.last_seen
```

Per-feed timestamp fields, all already parsed by their connectors:

| Feed | Field | Notes |
|---|---|---|
| URLhaus | `last_online`, falling back to `dateadded` | `last_online` genuinely advances when re-confirmed |
| MalwareBazaar | `first_seen_utc` | never advances — a sample is submitted once |
| ThreatFox | `first_seen_utc` | never advances |
| Feodo Tracker | check before assuming | |
| Blocklist.de, Emerging Threats | **none** | keep current behaviour, documented |

### 3.1 What this means per feed, honestly

For MalwareBazaar and ThreatFox, `first_seen_utc` never advances, so
`sighting_count` becomes effectively **1 for the whole population**. That is
correct — those feeds genuinely provide no re-observation evidence — but it means
the frequency term contributes a flat 10.0 for them rather than becoming
informative. The term only carries signal where a source actually re-confirms
(URLhaus's `last_online`) or where multiple feeds report the same indicator.

That is worth stating rather than glossing: this fix removes false signal, it does
not add true signal. Whether a 15% weight is still justified for a term that is
constant across most of the corpus is a **separate question for the weight
profiles**, and arguably the frequency weight should move to diversity or
enrichment for non-URLhaus types. Do not fold that decision into this fix.

### 3.2 Timestamp-free feeds

Blocklist.de and Emerging Threats carry no timestamps, so `_make_ioc` defaults both
to `now()` — the same trap that made `rolling_window` opt-in. For these, `advanced`
is always true and behaviour is unchanged. Document it; do not try to infer
observation times that do not exist.

---

## 4. Ordering constraint — this must precede the rescore

`scripts/rescore_corpus.py` reads **stored** `sighting_count` and `last_seen`
straight out of the row and passes them to `calculate_threat_score`. It does not and
cannot recompute them.

So if the rescore runs first, it faithfully bakes the inflated counts into
`threat_score` — and because it is idempotent, re-running it later would not undo
that. The inflation would be laundered into the corpus as a "corrected" score.

**Required order:**

1. Land the timestamp gate (stops further inflation).
2. Repair or recompute existing `sighting_count` / `last_seen` values — see §4.1.
3. Then run `rescore_corpus.py --dry-run`, and only then the write pass.

### 4.1 Repairing existing values is not mechanical

The true observation count for a historical IOC is **not recoverable** from the
database: nothing records which syncs saw it. Options, none free:

- **Reset to 1** for every IOC whose only source is a rolling-window feed. Loses
  genuine multi-feed corroboration where it exists, but that signal lives in
  `ioc_sources` / `source_count` anyway, which is the term that is *supposed* to
  carry it.
- **Clamp** to a plausible ceiling (say 5). Arbitrary, and still fiction.
- **Recompute from `ioc_sources`** — `COUNT(*)` of source links rather than a sync
  counter. Defensible: it counts distinct feed-reports, which is closer to
  "sightings" than either alternative, and it is derivable.
- **Leave and document.** Rejected: the whole point of the rescore is that stored
  scores are stale, and this would keep 30% of the composite stale afterwards.

`last_seen` is partly recoverable for URLhaus, since `last_online` can be re-read
from the current export for any URL still in the window — but not for URLs that have
aged out.

Recommendation: reset-to-1 for rolling-window-only IOCs, combined with a full
re-sync of URLhaus so `last_online` repopulates for everything still live. Both
numbers then mean what they claim. Needs owner sign-off because it discards data.

---

## 5. Secondary benefit — InnoDB write volume

15,524 URLhaus rows × 4 syncs/day currently means the `executemany` UPDATE touches
~15k existing rows per sync against a shared MySQL host. That is precisely the
lock-contention scenario `feed_ingestion`'s chunking, retry and per-chunk commits
exist to survive — and almost all of it is writing values that did not change.

With the timestamp gate, an IOC whose source timestamp has not advanced needs **no
UPDATE at all**: skip it from `update_mappings` entirely rather than writing an
identical row. For URLhaus that should reduce the per-sync write set from ~15k rows
to the genuinely-new-or-advanced few hundred.

That is an independent argument for the fix, and it should be measured with the
`-m mysql` statement counter once implemented, not asserted.

Note one interaction: `threat_score` is currently recomputed on every re-read, so
skipping the UPDATE also stops re-scoring unchanged rows. That is desirable — but it
means a scoring-model change no longer propagates through ordinary ingestion, and
`rescore_corpus.py` becomes the only path that applies a new model to old rows.
Worth stating in the Phase 5 notes.

---

## 6. Cross-references

- Rolling-window measurements: `BaseFeed.rolling_window`, `_MEASURED_WINDOW_HOURS`
  on each connector, revision `f6a7b8c90003`
- Rescore script and its statement budget: `scripts/rescore_corpus.py`,
  `tests/test_rescore_corpus.py`
- Phase 4 scheduling columns: [2026-07-30-phase4-scheduling-design-notes.md](2026-07-30-phase4-scheduling-design-notes.md)
