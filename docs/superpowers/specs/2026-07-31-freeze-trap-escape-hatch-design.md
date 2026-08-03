# Design — Freeze-Trap Escape Hatch

**Date:** 2026-07-31
**Status:** design only. Agreed shape needed before Section 1 builds anything.
**Why now:** Sections 1, 2 and 6 all change the scoring model, and after Section 3
there is no automatic path by which a model change reaches an existing row.

---

## 1. The trap, and it is not prospective

Spec 5 §4 frames this as a hazard Section 3 *creates*, arising later from Spec 2
§4.7's `threat_score >= 51` enrichment selection. It is already live, in a different
form, and Section 3 closed the last remaining escape.

Three gates, each individually correct, composing into a one-way door:

| Gate | Where | Effect |
|---|---|---|
| `WHERE Enrichment.id IS NULL` | `api/feeds.py:224-230` | an IOC enriched **once** is never selected again, so `_rescore_from_enrichment` never fires for it again |
| re-read gate | `feed_ingestion._rescore_reason` | an IOC whose evidence has not changed is not re-scored |
| `threat_score >= 51` | Spec 2 §4.7, not yet built | low-scoring IOCs would never be enriched |

Before Section 3, ingestion re-scored every row on every sync, which accidentally
propagated model changes — badly (it destroyed enrichment evidence, §8 item 0a) but it
propagated them. Removing that was right. It also means:

**An IOC scored under an old or buggy model stays at that score permanently, and the
low-scoring population is exactly where a scoring bug hides.** Self-reinforcing: a bug
that under-scores an indicator also guarantees nothing will ever look at it again.

Concretely, with today's code: a hash scored 36 under the pre-Section-1 model is not
re-read (MalwareBazaar's `first_seen_utc` never advances), not re-enriched (it has an
enrichment row), and not rescored. Its score is final until someone runs a script.

## 2. Requirement

Any model change must reach every existing row **without** re-introducing either
defect it replaced: not by re-scoring on every re-read (destroys evidence, floods
writes), and not by re-enriching everything (API quota).

Note the asymmetry that makes this tractable: **re-scoring is free, re-enriching is
not.** Re-scoring reads rows already in the database and calls a pure function.
Re-enriching spends third-party API calls against free-tier limits. So the escape
hatch should make *re-scoring* cheap and routine, and treat *re-enrichment* as the
separately-budgeted thing it is.

Spec 5 offers two candidates. Costed below, plus a third.

## 3. Option A — secondary selection in `enrichment/step`

Give the enrichment step a second query for never-enriched IOCs regardless of score,
with a small per-invocation quota.

| | |
|---|---|
| **Cost** | one extra query per invocation; API calls bounded by the quota |
| **Fixes** | the `threat_score >= 51` gate, prospectively |
| **Does not fix** | anything already enriched — which is the frozen population. `Enrichment.id IS NULL` is what excludes them, and this option keeps that predicate |

**Rejected as the primary mechanism.** It addresses the gate that does not exist yet
and leaves the one that does. It is still worth doing as part of Phase 4's selection
fix — `no enrichment row OR expires_at passed` already covers it — but it is not an
escape hatch for stale *scores*.

## 4. Option B — `scored_at` plus a model-version constant

Add `iocs.scored_at DATETIME` and `iocs.scoring_model_version SMALLINT`, stamped
whenever `threat_score` is written. Bump a module constant in `scoring_engine` when
the model changes. The rescore then targets `WHERE scoring_model_version < :current`.

| | |
|---|---|
| **Cost** | one migration, two columns; both writes are already happening so no extra statements; ~4 bytes + 8 bytes per row |
| **Fixes** | stale scores directly and exactly — the query names the population |
| **Also gives** | "when was this score computed", which the dashboard cannot currently answer, and a bounded resumable unit of work |

**Adopt.** It makes the frozen population *addressable*, which is the actual problem.
Everything else follows from being able to write the query.

Design details worth fixing now rather than discovering:

- **Bump the version in the same commit as the model change.** A constant that lags
  is worse than no constant, because the query then reports a clean corpus.

  **But the guard must be scoped and inverted, not a whole-module hash.** Two
  failure modes with very different costs:

  | | Cost |
  |---|---|
  | **False positive** — version bumped when scores did not change | Under Option C this triggers a **full corpus rescore for a docstring edit**. Expensive, and it happens silently. |
  | **False negative** — model changed without a bump | A test fails at build time and a human looks at it. Cheap. |

  So the guard should err toward under-triggering:

  1. **Scope the hash to what actually changes scores** — `WEIGHT_PROFILES` and the
     bodies of the sub-score functions (`_base_reputation_score`,
     `_source_diversity_score`, `_recency_score`, `_sighting_frequency_score`,
     `_enrichment_risk_score`, `_context_score`, `_reached_a_verdict` and the
     reputation-evidence helpers). Extract those via `ast` and hash the unparsed
     nodes, so comments, docstrings, import order and formatting are all invisible.
     `ast.get_docstring` makes stripping docstrings straightforward.
  2. **Invert the assertion.** The test does not compute the version; it fails when
     the scoped hash changed and `SCORING_MODEL_VERSION` did not, with a message
     naming which function moved. A human then decides whether the change was
     semantic. Auto-bumping would make the expensive mistake automatically.
  3. **Store the expected hash beside the constant**, so the diff shows both moving
     together and review sees the pair.

  Worth stating the residual: a change that alters scores *without* touching those
  functions — a new enricher whose payload reaches an existing branch, say — bumps
  nothing. That is a real gap, and it is the reason the guard is a backstop for
  forgetfulness rather than a substitute for judgement. Section 2's MalwareBazaar
  branch is exactly such a change and must bump the version by hand.
- **Stamp on every write, including ingestion's**, or newly-ingested rows look stale
  immediately.
- **`scored_at` is not `updated_at`.** `updated_at` moves for tag merges and sighting
  changes too; conflating them makes the query wrong in the permissive direction.
- **Nullable, no backfill.** `NULL` means "scored before this column existed", which
  the rescore treats as stale — correct, since every existing row *is*.

## 5. Option C — make `rescore_corpus.py` a scheduled job

Independent of A and B, and the operational half of the answer.

The script is already chunked, resumable, idempotent and statement-budgeted at four
per chunk. With Option B's version column it becomes cheap and targeted rather than a
full-table sweep: normally zero rows, and after a model change exactly the affected
population.

| | |
|---|---|
| **Cost** | one cron entry; a no-op run is a single indexed query |
| **Fixes** | closes the loop — a model change propagates without anyone remembering to run anything |
| **Risk** | it writes scores unattended, so it must respect `manual_score_override` (it already does) and must never run mid-migration |

**Adopt, with a gate.** It should refuse to run when
`scoring_model_version` is `NULL` for more than some threshold fraction of the
corpus, since that indicates a first-ever run over the whole table — which is a
sign-off decision, not a cron job.

## 6. Recommendation

**B + C, with A folded into Phase 4's selection fix.**

1. **Phase 4** adds `scored_at` and `scoring_model_version` alongside its other
   columns, and fixes the enrichment selection to `no enrichment row OR expires_at
   passed` (which subsumes A).
2. **Sections 1, 2 and 6 stamp the version as they go**, so the columns are populated
   by the same passes that change the model rather than needing a follow-up sweep.
   This is why the design had to precede Section 1.
3. **`rescore_corpus.py` becomes standing tooling**, scheduled, with the
   all-NULL guard.

Ordering constraint: the columns cannot land before the migration chain is repaired,
which is blocked on the owner queries. So Sections 1–2 should **write the constant
into the code** and record in their commit messages which version they represent, so
that when the column arrives the rescore can target correctly. That costs nothing and
avoids a second pass.

## 6.5 Per-section acceptance criterion — bump the version

Implemented ahead of the columns: `SCORING_MODEL_VERSION` and
`SCORING_MODEL_FINGERPRINT` now live in `scoring_engine`, currently at **3**, with the
History comment recording what each version represents. The guard is
`tests/test_scoring_and_export.py::TestScoringModelVersion`.

**The guard is a backstop, not the mechanism.** It hashes the weight tables and the
sub-score function bodies, so it cannot see a change that alters scores without
touching those — and Sections 1 and 2 are both exactly that: adding an `assessed`
contract changes what reaches `total_signals`, and a new MalwareBazaar branch adds a
signal, without necessarily editing a hashed body.

So every scoring change set ends with this, as a checklist item rather than something
to remember:

- [ ] bump `SCORING_MODEL_VERSION`
- [ ] update `SCORING_MODEL_FINGERPRINT` to the value the guard reports
- [ ] add a History line naming what changed
- [ ] state in the commit message that a rescore is required

Applies to **Sections 1, 2 and 6**. A refactor with genuinely identical behaviour
updates the fingerprint only, and says so — a spurious bump costs a full corpus
rescore.

**Guard verified by mutation, not by inspection.** It fires on a sum-preserving weight
redistribution, a diversity threshold change and a `NEUTRAL_REPUTATION` change; it
stays silent on comment edits and on docstring edits inside hashed functions. That
exercise found a real defect in the first version: `WEIGHT_PROFILES` carries a type
annotation, so it is an `ast.AnnAssign` rather than an `ast.Assign` and an
Assign-only check omitted the weight tables entirely — the single most likely thing
to change.

## 7. Consequences to record in the Phase 6 deploy checklist

- `rescore_corpus.py` is **standing operational tooling**, not a one-off migration
  script. It needs a scheduled invocation, a runbook entry, and its `--dry-run`
  distribution reviewed after any model change.
- A scoring-model change is now a **two-part deployment**: ship the code, then run the
  rescore. Shipping only the code leaves the corpus split across two models, which is
  worse than either — the dashboard would rank rows scored under different rules
  against each other.
- The three-way corpus state from §8 item 0a (recently-re-read, aged-out-corrupted,
  never-enriched) becomes queryable once `scoring_model_version` exists. Worth adding
  to `dashboard/feed-health` or a maintenance endpoint.

## 8. Cross-references

- The live trap and its measurements: `PROJECT_SUMMARY.md` §8 items 0a, 0d, 0e
- Enrichment selection and quota sizing: [2026-07-30-phase4-scheduling-design-notes.md](2026-07-30-phase4-scheduling-design-notes.md) §2.6
- Rescore script and ordering: [2026-07-30-sighting-count-and-recency-design.md](2026-07-30-sighting-count-and-recency-design.md) §4
- Migration chain blocker: [2026-07-30-migration-chain-repair-design.md](2026-07-30-migration-chain-repair-design.md)
