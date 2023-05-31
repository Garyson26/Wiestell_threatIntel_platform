


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

