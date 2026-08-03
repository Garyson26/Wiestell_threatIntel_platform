# Design — Migration Chain Repair (`iocs.value` cannot be indexed)

**Date:** 2026-07-30
**Status:** **design only — blocked on four owner queries.** Nothing implemented.
**Blocking on:** `SELECT VERSION();`, `SHOW CREATE TABLE iocs;`,
`SHOW CREATE TABLE feed_sources;` and `SELECT * FROM alembic_version;` against the
Hostinger instance. See §5. A fifth query (§5.5) is **not** a blocker for this
design — it settles the GeoIP/MaxMind question recorded as PROJECT_SUMMARY §8 item 14
— but it is listed here so all five can be run in one sitting.

---

## 1. The defect

Both documented ways to create the schema fail on MySQL 8:

```
(1170, "BLOB/TEXT column 'value' used in key specification without a key length")
```

| Path | Where it is documented | Result |
|---|---|---|
| `alembic upgrade head` | `CLAUDE.md`, `README.md`, `PROJECT_SUMMARY.md` | fails on `create_table('iocs')` |
| `Base.metadata.create_all()` | called unconditionally by `scripts/seed_feeds.py` | fails on the same DDL |

Cause: `iocs.value` is `sa.Text()` and the table declares
`UniqueConstraint("type", "value")`. MySQL and MariaDB both refuse to build an index
over a `TEXT`/`BLOB` column without a prefix length.

Found 2026-07-30 while standing up the local Docker harness, which had never been
run before — the failure is invisible to a suite that mocks the session.

### 1.1 Blast radius beyond first-run

- **Disaster recovery is untested and currently impossible.** There is no path from
  an empty database to a working one.
- **Spec 2 Phase 6 assumes migrations run from a developer machine.** They cannot.
- **The `-m mysql` test tier** can only run because `tests/conftest_mysql.py` applies
  a labelled test-only prefix-length adaptation. That scaffold must be deleted once
  this is fixed, or the tier will keep testing a schema production does not have.
- **`scripts/rescore_corpus.py` is written but unrun.** It must not run before this
  is settled, since the fix may involve a migration that rewrites the table.

### 1.2 What this implies about production

Production has a schema, so it was **not** built by either documented path. Two
plausible histories, and the fix depends on which:

1. `value` was once `VARCHAR(n)` with a working unique index, and the model later
   drifted to `Text` without a migration. The live column is still `VARCHAR`.
2. The table was created by hand, possibly with a prefix index, possibly with **no
   unique constraint at all**.

History 2 with no unique constraint is the dangerous one: `feed_ingestion` relies on
`INSERT ... IGNORE` against `uq_ioc_type_value` for deduplication. Without the
constraint, `IGNORE` suppresses nothing and every re-sync appends duplicate rows.

**This is why `SHOW CREATE TABLE iocs;` is blocking.** Do not choose a fix first.

---

## 2. Options

### 2.1 Prefix index — `UNIQUE(type, value(255))` — **REJECTED**

Not a workaround; a live data-loss bug.

`feed_ingestion` deduplicates through `INSERT ... IGNORE` against this exact
constraint. With a 255-character prefix, two **distinct** URLs sharing their first
255 characters collide, `IGNORE` swallows the second, and the indicator is silently
dropped — no error, no log line, no row.

For a URLhaus-derived corpus that is routine rather than exotic: same host, same long
path, differing only in a query-string parameter near the end. Tracking and affiliate
URLs look exactly like this.

**If production turns out to have a prefix index, indicators have already been lost.**
Quantify it on access with:

```sql
-- How many (type, 255-char prefix) groups hold more than one distinct value?
SELECT COUNT(*) AS colliding_groups, SUM(n - 1) AS rows_at_risk
FROM (
  SELECT type, LEFT(value, 255) AS p, COUNT(DISTINCT value) AS n
  FROM iocs GROUP BY type, p HAVING n > 1
) AS collisions;
```

That counts what a prefix constraint *would* merge. Rows already dropped by a live
prefix index cannot be recovered from the database — only by re-syncing the feeds.

### 2.2 `VARCHAR(n)` — **REJECTED**

InnoDB caps an index key at 3072 bytes on `DYNAMIC` row format. `utf8mb4` costs 4
bytes per character, and the composite index also carries `type VARCHAR(20)` (80
bytes + length prefix), leaving roughly **740 characters** for `value`.

Malware URLs exceed that. Truncating them at write time corrupts the indicator; not
truncating raises error 1071 at DDL time — the failure I hit at prefix 768 while
building the test scaffold, which is how the 740 figure was arrived at rather than
guessed.

### 2.3 Generated hash column — **ADOPT**

```sql
ALTER TABLE iocs
  ADD COLUMN value_sha256 CHAR(64)
      GENERATED ALWAYS AS (SHA2(value, 256)) STORED;

ALTER TABLE iocs
  DROP INDEX uq_ioc_type_value,
  ADD CONSTRAINT uq_ioc_type_value UNIQUE (type, value_sha256);
```

- `value` stays `Text` — no length ceiling, no truncation.
- Uniqueness is **exact**: SHA-256 over the full value, not a prefix.
- Index key is 64 bytes plus `type`, far inside the 3072-byte cap.
- `INSERT ... IGNORE` is unchanged — it targets the same constraint name, and the
  generated column is computed by the server, so no application code writes it.
- The ORM needs `value_sha256` declared with
  `sa.Computed("SHA2(value, 256)", persisted=True)` so Alembic and
  `create_all()` both emit it.

---

## 3. Two things to verify, not assume

### 3.1 Is `STORED` accepted by the production server?

MySQL 5.7+ accepts `STORED`. MariaDB used `PERSISTENT` historically and added
`STORED` as a synonym in **10.2**; on anything older the `ALTER` fails. The generated
column also cannot be added with `ALGORITHM=INPLACE` on a stored column in some
versions, meaning a full table rebuild and a write lock for its duration.

`SELECT VERSION();` therefore gates both the syntax and the maintenance window.

### 3.2 Do existing rows already violate exact uniqueness?

If production has **no** unique constraint, duplicates may exist, and adding the
constraint will fail partway through the `ALTER`. Check before, not during:

```sql
-- Exact duplicates that a (type, value_sha256) constraint would reject.
SELECT type, SHA2(value, 256) AS h, COUNT(*) AS n
FROM iocs GROUP BY type, h HAVING n > 1 ORDER BY n DESC LIMIT 50;
```

If any exist, the migration needs a dedupe step first, and dedupe is not mechanical —
it has to merge rather than delete, because each duplicate may carry its own
`ioc_sources` links, `enrichments` rows and `sighting_count`. Deleting the loser
would lower `source_count` for the survivor and change its score, which is precisely
the uncontrolled change the VirusTotal/PhishTank soft-disable was designed to avoid.

Sketch of the merge, to be written properly once the counts are known: keep the
oldest `first_seen`, the newest `last_seen`, the **sum** of `sighting_count`, the
union of `tags` / `mitre_techniques`, repoint `ioc_sources` and `enrichments` at the
survivor with `INSERT ... IGNORE`, then delete the losers and rescore the survivor.

---

## 4. Migration plan, once the answers are in

1. Record `SHOW CREATE TABLE iocs;`, `SHOW CREATE TABLE feed_sources;` and
   `SELECT * FROM alembic_version;` verbatim in this document. The starting state
   must be written down before anything changes it.
2. Run both diagnostic queries in §2.1 and §3.2; record the numbers.
3. **Reconcile `alembic_version` with reality before running any migration.** If the
   stamped revision does not describe the live schema, `alembic stamp <rev>` it to
   the one that does, rather than letting `upgrade head` replay revisions that were
   effectively applied by hand. Getting this wrong is worse than doing nothing: a
   replay from an empty `alembic_version` fails at 1170 *after* creating whatever
   tables precede `iocs`, leaving a half-built schema.
4. If duplicates exist, write and review the merge migration **separately** and run
   it first. Do not combine dedupe with a schema change.
5. Repair the **initial** revision `56fe08259401` so a fresh database works from
   empty. It has never succeeded, so editing it rewrites no one's history — but say
   so explicitly in the revision docstring, because editing a shipped migration is
   normally wrong.
6. New Alembic revision off the current head (`f6a7b8c90003`):
   - add `value_sha256` as a stored generated column;
   - drop and re-add `uq_ioc_type_value` against `(type, value_sha256)`;
   - `downgrade()` reverses both, since unlike `e5f6a7b80002` this one genuinely can.
7. Update `app/models/ioc.py` to declare the generated column and the new constraint.
8. Delete the test-only adaptation in `tests/conftest_mysql.py::_test_metadata` and
   confirm `-m mysql` still passes against the real schema.
9. Verify the whole path on the container: `docker compose down -v`, `up -d db`,
   `alembic upgrade head`, `seed_feeds.py`, `-m mysql`.
10. Land the `sighting_count` / `last_seen` timestamp gate and repair the inflated
    stored values — see
    [2026-07-30-sighting-count-and-recency-design.md](2026-07-30-sighting-count-and-recency-design.md).
    The rescore reads those fields directly, so running it first would bake the
    inflation in permanently.
11. Only then run `scripts/rescore_corpus.py --dry-run`, and the write pass after
    sign-off on the distribution.

## 5. Open questions for the owner

1. `SELECT VERSION();` — MySQL 8 or MariaDB, and which minor version?
2. `SHOW CREATE TABLE iocs;` — current column type and what constraint, if any?
2b. `SHOW CREATE TABLE feed_sources;` — the model may have drifted here too; the
   Phase 4 column reconciliation needs the live DDL as well.
2c. **`SELECT * FROM alembic_version;`** — and this one may be the most consequential.
   If the schema was built by neither documented path, the table may be stamped at a
   revision that does not describe reality, or hold no row at all. Either way
   `alembic upgrade head` will not do what Phase 6 assumes:
   - **no row** → Alembic replays from `56fe08259401`, which fails at error 1170 on
     `create_table('iocs')`, having already created whatever tables precede it;
   - **stamped too late** → the revisions in between are skipped silently, so
     `is_enabled NOT NULL`, `last_ingest_watermark` and `last_ingest_gap` never
     appear and the application errors on a missing column at runtime;
   - **stamped too early** → replay hits the same 1170.

   **Consequence to note now: `e5f6a7b80002` is what disables VirusTotal and
   PhishTank.** Until the chain actually runs against production, both feeds are
   still `is_enabled = 1` there — and their connector modules have been deleted, so
   every sync attempt logs `scheduler_no_connector` and the feeds sit permanently
   overdue. The soft-disable is staged, not in effect.
3. If a prefix index is present: is a re-sync to recover silently dropped indicators
   acceptable, and over what period?
4. Maintenance window for a possible full table rebuild on `ALTER`.

### 5.5 Not a blocker for this design — has the GeoIP database ever been present?

```sql
SELECT COUNT(*)                                            AS geoip_rows,
       SUM(JSON_EXTRACT(data, '$.error_city') IS NOT NULL) AS failed_lookups,
       SUM(JSON_EXTRACT(data, '$.country_code') IS NOT NULL
           AND JSON_UNQUOTE(JSON_EXTRACT(data, '$.country_code')) <> '')
                                                           AS resolved
FROM enrichments
WHERE source = 'geoip';
```

`failed_lookups` high and `resolved` at or near zero means the MaxMind `.mmdb` has
never been present in production, and therefore that **the whole IP population has been
scored with no country or ASN evidence** — WHOIS alone. That is the second factor in the
enrichment-risk saturation estimate (Spec 5 §1 item 2), which could not be quantified
without it, and it decides whether item 14 is a latent risk or the live state.

Note the interaction with the freeze trap: enrichment selection is
`WHERE Enrichment.id IS NULL`, so these rows are never refreshed. Even once the database
is provisioned, every IP already carrying an `error_city` row keeps it until that
selection is fixed *and* a full refresh has run. A `DELETE FROM enrichments WHERE
source = 'geoip' AND JSON_EXTRACT(data, '$.error_city') IS NOT NULL` would let them
re-enrich, but it is a write against production and needs its own sign-off.

---

## 6. Schema work that lands behind this repair

Recorded here because it is blocked on the same four owner queries, and because it is the
eventual right answer to a problem Phase 5 could only mitigate in application code.

### 6.1 `ioc_techniques` — a normalised join table

**Problem.** `iocs.mitre_techniques` is a JSON array, and `JSON_CONTAINS` cannot use an
index. Counting IOCs per technique therefore has no efficient SQL form: the join

```sql
SELECT t.id, COUNT(i.id) FROM attack_techniques t
LEFT JOIN iocs i ON JSON_CONTAINS(i.mitre_techniques, JSON_QUOTE(t.id))
GROUP BY t.id
```

is one statement but degenerates to a cross product — hundreds of techniques × tens of
thousands of IOCs, evaluated per pair, on a shared host. Phase 5 avoided that by fetching
every tagged IOC's array in one scan and counting in Python, which fixed the statement
count (41 → 2 on both `/attack/matrix` and `/attack/heatmap`) but moved the cost to
transfer and CPU. Measured, uncached, per request:

| Tagged IOCs | Wire | Parse + count, local | ≈ at 0.1 CPU |
|---|---|---|---|
| 10,000 | 176 KB | 44 ms | ~0.4 s |
| 50,000 | 877 KB | 207 ms | ~2 s |
| 200,000 | 3.5 MB | 1.15 s | ~11 s |

Linear in corpus size, so comfortable now and not at scale.

**Proposal.**

```sql
CREATE TABLE ioc_techniques (
  ioc_id       CHAR(36)    NOT NULL,
  technique_id VARCHAR(20) NOT NULL,
  PRIMARY KEY (ioc_id, technique_id),
  KEY idx_technique (technique_id),
  CONSTRAINT fk_it_ioc FOREIGN KEY (ioc_id) REFERENCES iocs(id) ON DELETE CASCADE
);
```

`SELECT technique_id, COUNT(*) FROM ioc_techniques GROUP BY technique_id` is then an
index-only scan returning a few hundred rows. The `idx_technique` key also makes
`/attack/techniques/{id}` an indexed lookup instead of the `JSON_CONTAINS` filter it uses
today.

**Alternative: an indexed generated column.** Cheaper to adopt but weaker — a
`VARCHAR` generated from `mitre_techniques` can be indexed, but only usefully for a
single-technique-per-IOC assumption, which is false here (1–3 is typical). The join table
is the correct normalisation; the generated column is a shortcut that would need undoing.

**Why it is blocked.** It needs a migration, and `alembic upgrade head` currently fails
at error 1170 on `iocs.value`. It also needs a backfill from the existing JSON arrays,
which must be idempotent and re-runnable, and a decision on whether `mitre_techniques`
stays as the write path with the table derived, or the table becomes authoritative and the
JSON column is dropped. Keeping both means keeping them consistent, which is a trigger or
an application invariant — worth deciding deliberately rather than by default.

**Sequencing.** After the chain repair and after `iocs.scoring_model_version`, since the
rescore is the higher priority (it is a UAT blocker) and this is a latency improvement for
a corpus size not yet reached.

### 6.2 Also waiting on this repair

- **`iocs.scoring_model_version`** — what lets `scripts/rescore_corpus.py` target stale
  rows rather than the whole table. `SCORING_MODEL_VERSION` is at 9 and stored scores were
  written under at least four superseded models. See PROJECT_SUMMARY.md §8 item 16.
- **`iocs.manual_score_override`** — the hook exists in `calculate_threat_score` and is
  inert until the column does. Must be populated *after* the first rescore, or those rows
  are skipped permanently.
- **`users.failed_login_attempts` / `users.locked_until`** — the per-account throttle in
  SECURITY_REVIEW.md item 8, which no amount of correct `X-Forwarded-For` handling can
  substitute for.
