


# Re-enrichment steps

A feed failure runbook, written for someone who has not run it
before.

## Before you start

Confirm that every external source the pass depends on
is actually reachable. A source that is configured but
unavailable stores an error against each value it is
asked about, and those stored errors are cached, so a
bad pass is expensive to undo.

```
check the credentials, then run a single value end to end
```

If the single value comes back with real data, the pass
is safe to start.

## If the pass is interrupted

Nothing resumes on its own. Progress is held in memory, so a
restart loses the counters entirely and the pass has to be
started again by hand. The work already done is not lost: values
enriched by the first attempt are still within their cache window
and are skipped rather than re-fetched, so the second run is
shorter than the first.

