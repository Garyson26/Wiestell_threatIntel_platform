


# Field reference

The shared threat-intel vocabulary as tables, for looking up rather than for
reading start to finish.

## Supported types

| Type | Example shape | Enriched by |
| --- | --- | --- |
| address | a single routable host | geolocation, reputation |
| domain | a registrable name | registration records, resolution |
| digest | a fixed-width hex string | sample repositories |



## Severity bands

The bucket a composite score falls into. The dashboard badges
are drawn straight from these boundaries, so moving one here
without moving it there produces a page that disagrees with
itself.

| Band | Score |
| --- | --- |
| critical | the top quarter |
| high | the upper middle |
| medium | the lower middle |
| low | everything remaining |

