


# Recovery procedure

A enrichment backfill runbook. Follow it in order; the early steps are cheap
and rule out the common causes.

## A source has gone quiet

1. Read the recorded status of every source and note
   which ones last finished successfully.
2. Check whether the scheduled trigger fired at all. A
   trigger that never ran looks identical to a source
   that returned nothing.
3. Only then look at the source itself.



## Backing out a partial sync

A run that stopped midway leaves the rows it had already
committed in place. That is deliberate -- the work is chunked
so a failure costs one chunk rather than the whole run -- but
it means the counts are real and simply incomplete.

Re-run the source rather than deleting anything. Values already
present are recognised and gain a sighting instead of a
duplicate row.

