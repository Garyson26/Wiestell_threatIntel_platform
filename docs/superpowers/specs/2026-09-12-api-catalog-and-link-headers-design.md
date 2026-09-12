# Design Note — RFC 9727 API Catalog and RFC 8288 Link Headers

**Date:** 2026-09-12
**Status:** **DESIGN ONLY — NOT IMPLEMENTED.** Nothing in this note is built.
**Gates:** two, and both must be open — the public lookup API existing, and
`TRUSTED_PROXY_HOPS` measured and set. See §6.
**Verdict:** viable, and the standards are real — RFC 9727 (Standards Track,
June 2025) and RFC 8288 are both published, unlike most of the scan that
prompted this. The blocker is not the spec, it is that there is no public API
to catalogue yet. The genuine design work is §2.3: how a curated public OpenAPI
document avoids drifting from the routes it describes.

---

## 1. Why this is not shipped today

An API catalog's value is almost entirely the `service-desc` relation — the
link to a machine-readable description. Wiestell cannot supply one today.

Production sets `ENABLE_API_DOCS=false` (`render.yaml`, and the default in
`app/config.py`), which constructs FastAPI with
`docs_url=None, redoc_url=None, openapi_url=None`. `/docs`, `/redoc` and
`/openapi.json` all 404. That was a deliberate decision from the original
security review (SECURITY_REVIEW.md, the `ENABLE_API_DOCS` finding), not an
oversight, and nginx returns 404 for those paths independently.

That leaves three options, two of which are wrong:

| Option | Verdict |
|---|---|
| Set `ENABLE_API_DOCS=true` in production | **No.** The auto-generated spec describes every authenticated endpoint, admin routes included. This reverses a security decision to satisfy a discoverability checklist. |
| Publish a catalog whose `service-desc` 404s | **No.** Worse than no catalog: it costs an agent a request and misrepresents the system. |
| Hand-curate a minimal public-only OpenAPI document, served separately from FastAPI's auto-generated spec | **Yes**, and it is the rest of this note. |

The third is real work and it belongs *with* the public API, not ahead of it.

Today the only genuinely unauthenticated surfaces are `/health` and
`/api/v1/health` (registered directly on `app` in `main.py`, so they bypass the
router-level `Depends(get_current_user)`), plus the public halves of `/users`
and `/contact`. The IOC lookup endpoint the catalog would exist to advertise —
`/api/v1/iocs/lookup` — is currently behind `_authenticated` at the router level
in `backend/app/api/__init__.py`. A catalog anchoring only two health checks is
not worth publishing.

---

## 2. The public OpenAPI document

### 2.1 Where it lives

Served at **`https://wiestell.com/openapi-public.json`**, from a committed file
at `frontend/public/openapi-public.json`.

Two constraints drive that path:

- **Not under `/api/`.** `next.config.js` rewrites `/api/:path*` to the backend
  origin. Filesystem routes do win over a rewrite returned as a plain array —
  the CSP-report comment already in `next.config.js` establishes that ordering —
  but relying on that precedence for a published, externally-linked URL is a
  trap for whoever next touches the rewrite. Keep the two namespaces disjoint.
- **Not under `/.well-known/`.** That tree is for URIs registered with IANA.
  `api-catalog` belongs there; an OpenAPI document does not.

**Trade-off, stated plainly.** Committing a generated artifact into the frontend
tree means a backend API change needs a frontend deploy to become visible. The
alternative — serving it live from the backend through the `/api/*` rewrite —
keeps it automatically in step, but puts a discovery document behind a Render
free-tier cold start and, more importantly, lets the public contract change
without review. A curated public API surface *should* require a deliberate
commit. Take the staleness risk and close it with §2.3.

### 2.2 How it is produced — filter, do not hand-write

Hand-writing the YAML guarantees drift. Instead, generate it by **filtering**
FastAPI's in-memory `app.openapi()` down to an explicit allowlist, and commit
the result.

```
backend/scripts/gen_public_openapi.py   # writes frontend/public/openapi-public.json
backend/app/public_api.py               # PUBLIC_PATHS — the allowlist, single source of truth
```

The script, roughly:

1. Build the app with `ENABLE_API_DOCS=True` **in-process only** — never in a
   deployed environment — so `app.openapi()` is populated.
2. Keep only paths in `PUBLIC_PATHS`, and within them only the listed methods.
3. Prune `components.schemas` to the transitive closure of the `$ref`s actually
   reachable from the kept paths. This is the step that stops an admin-only
   response model leaking in as a dangling definition.
4. Drop `securitySchemes` and any `security` blocks — by construction nothing
   here needs auth.
5. Rewrite `servers` to `[{"url": "https://wiestell.com"}]`, not the Render
   backend origin. Callers should use the same-origin path the rewrite serves.
6. Replace title and description with public-facing text rather than the
   internal app title.

### 2.3 How it stays in sync — the part that matters

Three tests under `backend/tests/`, all cheap, all failing loudly. This is the
mechanism that makes a hand-curated document safe rather than merely convenient.

| Test | Asserts | Catches |
|---|---|---|
| **Drift** | Re-running the generator reproduces the committed `openapi-public.json` byte for byte | A route signature or response model changed and nobody regenerated. Same shape as the existing `len(app.routes) == 62` check in PROJECT_SUMMARY.md §7. |
| **Allowlist is real** | Every entry in `PUBLIC_PATHS` resolves to a route that actually exists on the app | An allowlisted path was renamed or deleted — i.e. the catalog is advertising a 404. The "do not publish metadata describing capabilities the platform does not have" rule, enforced in CI rather than trusted. |
| **Allowlist is genuinely public** | No route reachable from `PUBLIC_PATHS` carries `get_current_user`, or any other auth dependency, in its resolved dependency tree | Someone adds auth to a listed endpoint, so the spec now lies — or, far worse, the allowlist grows to include something authenticated. |

The third test is the security-relevant one and should be written first. It must
inspect the **resolved** dependency tree: auth is applied at the router level in
`api/__init__.py`, not on individual route decorators, so a test that only reads
route decorators would pass happily on an authenticated endpoint.

### 2.3.1 Proving the auth check — mutation tests

The one failure mode that matters is a check that *looks* thorough and still
passes on an authenticated endpoint. Writing it is not enough; it has to be
mutation-proved, and the obvious mutation is not sufficient on its own.

**What the walk must cover.** FastAPI nests sub-dependencies and `Security`
scopes several levels deep, so the check reads `route.dependant` — the
*resolved* object — and recurses:

- `Dependant.dependencies`, recursively. Router-level `dependencies=[...]` are
  merged into the route's `dependant` and do **not** appear on the decorator, so
  reading `route.dependencies` alone misses the only auth this app actually
  applies.
- `Dependant.security_requirements`, which is where `Security(...)` lands. It is
  a separate list from `.dependencies`; walking only the latter misses it.
- A `visited` set keyed on the sub-dependant's `call`. Shared dependencies form
  a diamond, not a tree, and an unguarded walk re-traverses them.

**Compare resolved callables by identity, not by name.** `dep.call is
get_current_user`, or membership in a set of callables — never a substring or
`__name__` match. This project has tripped on substring-matching guards
repeatedly (`_running` matching inside `_sweep_running`; `sentinel-api` matching
inside the comment explaining the rename). A rename would silently disarm a
name-matching check here, and the thing it guards is the public/authenticated
boundary.

**Prefer an allowlist over a denylist.** Asserting "none of these known auth
dependencies appears" fails open the day somebody adds `get_current_api_key`.
Assert instead that the transitive dependency closure of every public path is a
**subset of an explicitly permitted set** (`get_db`, the rate limiter, and
whatever else is genuinely harmless). A new dependency of any kind then fails
the test until someone classifies it. That is the same safe-by-default posture
`api/__init__.py` already takes at the router level, applied one layer out.

**Mutations, and what each one actually proves:**

| # | Mutation | Must | Proves |
|---|---|---|---|
| 1 | Add an authenticated path (e.g. `/api/v1/iocs/lookup`) to `PUBLIC_PATHS` | fail | The check binds at all. **Necessary but not sufficient** — see below. |
| 2 | Wrap `get_current_user` in a pass-through dependency one level down, and allowlist the wrapper | fail | The walk **recurses**. This is the mutation that matters. |
| 3 | Express the auth as `Security(get_current_user, scopes=[...])` instead of `Depends(...)` | fail | `security_requirements` is walked, not just `.dependencies`. |
| 4 | Truncate the walk to depth 1 | fail (at least #2) | The recursion is exercised, not merely written. |
| 5 | Swap identity comparison for a name match, then rename the dependency | fail | The check survives a rename. |

**Why mutation 1 alone would mislead.** The auth dependency this app applies
sits at the router level, so in the resolved `dependant` it lands at **depth 1**.
A shallow, non-recursive check catches it and passes mutation 1 — looking
correct while being unable to see auth nested any deeper. Mutation 2 is what
separates a real tree walk from a one-level lookup, and it is the one to write
first if only one gets written.

### 2.4 Scope of the first version

Only what exists and is public at the time it ships: the free lookup endpoint,
and `/api/v1/health`. Nothing speculative.

---

## 3. The `/.well-known/api-catalog` document

Per RFC 9727: media type `application/linkset+json`, a top-level `linkset`
array, one object per API anchored at its base URI.

```json
{
  "linkset": [
    {
      "anchor": "https://wiestell.com/api/v1",
      "service-desc": [
        {
          "href": "https://wiestell.com/openapi-public.json",
          "type": "application/json",
          "title": "Wiestell public lookup API — OpenAPI description"
        }
      ],
      "service-doc": [
        {
          "href": "https://wiestell.com/docs/api",
          "type": "text/html",
          "title": "Wiestell public lookup API — documentation"
        }
      ],
      "status": [
        {
          "href": "https://wiestell.com/api/v1/health",
          "type": "application/json"
        }
      ]
    }
  ]
}
```

**`service-doc` is conditional.** `https://wiestell.com/docs/api` does not exist.
Either that page ships alongside the catalog, or the `service-doc` relation is
omitted entirely. Do not include the key pointing at a page nobody has written —
that is precisely the failure mode this triage exists to avoid.

### 3.1 Two serving gotchas, both Vercel-specific

1. **Content type.** The file would be `frontend/public/.well-known/api-catalog`,
   with no extension, so Vercel will not infer `application/linkset+json`.
   RFC 9727 requires it. Set it explicitly in the `headers()` block of
   `next.config.js` (or in `vercel.json`) for that exact path, and verify with
   `curl -sI https://wiestell.com/.well-known/api-catalog` before believing it.
2. **Dot-directories in `public/`.** Confirm at implementation time that Next 16
   actually serves `public/.well-known/`. If it does not, the fallback is a route
   handler plus a rewrite. Do not assume — check on a preview deployment first.

RFC 9727 also requires that a `HEAD` on the catalog URI return the `Link` header.
Static assets on Vercel answer `HEAD` and `headers()` applies to both methods, so
this comes free — but include it in the curl check above rather than assuming.

---

## 4. Link headers (RFC 8288)

Added to `commonHeaders()` in `next.config.js`, alongside the existing security
headers:

```
Link: </.well-known/api-catalog>; rel="api-catalog"
```

On the homepage at minimum. Applying it to every route via `commonHeaders()` is
also defensible and is less likely to be quietly missed.

**Note the contrast with the CSP warning already in that file.** The existing
comment warns that two matching `source` patterns emit two
`Content-Security-Policy` headers and the browser enforces the *intersection* —
which is neither policy. `Link` does not behave that way: multiple `Link` headers
are explicitly valid under RFC 8288 and are merged, not intersected. So `Link`
can safely live in `commonHeaders()` even though both the marketing and app rules
apply it. Do not let the CSP caution scare anyone into duplicating header logic
that does not need duplicating.

---

## 5. What does not need to change

- **CSP.** A static JSON document loads no subresources; neither `CSP_APP` nor
  `CSP_MARKETING` needs an edit. For the record, `/.well-known/api-catalog`
  matches `APP_SOURCE` (`/((?!api/|about$|contact$).+)`) and will therefore be
  served with `CSP_APP` — harmless for JSON, and better known than rediscovered.
- **`robots.txt` and the sitemap.** The catalog is for agents following a
  well-known URI, not for crawlers. It needs no sitemap entry and no `Allow`
  rule; the existing `Allow: /` already covers it.
- **Backend auth.** Nothing here is authenticated and nothing here touches
  `api/__init__.py`.

---

## 6. Gates and open questions

There are **two** gates, not one. Both must be open.

### Gate 1 — the public lookup API exists

A catalog that anchors only health checks advertises nothing. Today the only
genuinely unauthenticated surfaces are `/health` and `/api/v1/health`;
`/api/v1/iocs/lookup` is behind `_authenticated` at the router level (§1). That
is the whole reason to wait — not a schedule.

### Gate 2 — `TRUSTED_PROXY_HOPS` is measured and set

**This dependency is named nowhere else, and is not obvious from either side.**

A public lookup API means *unauthenticated* endpoints, which need rate limiting
that can tell callers apart. Today it cannot:

- `TRUSTED_PROXY_HOPS` defaults to `0` (`config.py:134`), and at `0`
  `deps.py::_client_ip` ignores `X-Forwarded-For` entirely and falls back to the
  socket peer — deliberately fail-closed, pending measurement.
- On Render the socket peer is the edge address, so **every caller presents as
  the same IP**. SECURITY_REVIEW.md says so plainly in its "Missing entirely"
  list, item 2 — the per-IP rate limits "do not currently bind at all on
  Render, where every caller presents as the edge address" — and §R-06 records
  the same thing as a deploy-time availability consequence.
- `DEPLOY_CHECKLIST.md` §4 carries the measurement step and the value (`1` on
  Render), with the warning that too *high* is worse than too low — a
  client-supplied header value gets trusted and an attacker rotates their own
  bucket at will.

So a per-IP limiter in front of a public endpoint is currently **one global
bucket**, and that leaves no good setting. Low enough to be a real limit and a
single aggressive agent locks out every other caller — a trivial denial of
service. High enough to avoid that and it is not a limit. The existing
`ioc-lookup` 60/60s limiter does not rescue this: it is applied to
authenticated callers, where the bucket key is not the problem.

Publishing an api-catalog makes this worse rather than merely leaving it
unfixed. The entire purpose of the catalog is to attract automated clients to
the endpoint, which is precisely the traffic shape a single shared bucket
cannot survive. **Advertising the endpoint is what promotes `TRUSTED_PROXY_HOPS`
from deferred hardening to a prerequisite.** From the catalog side this looks
like a pure metadata task; from the rate-limiting side the hop count looks like
a hardening item with no consumer. It is written down here because neither view
shows the coupling.

### Open at that point

1. Does `/docs/api` exist? If not, drop `service-doc` (§3).
2. The rate-limit *budget* for unauthenticated callers — a separate decision
   from Gate 2, which only makes the bucket *key* correct. Note that a correct
   key is necessary but not sufficient: SECURITY_REVIEW.md's same list observes
   that an attacker rotating source IPs defeats a per-IP bucket even with a
   perfectly measured hop count. Decide the budget, and whether per-IP is the
   right dimension at all, before advertising the endpoint rather than after.
3. Re-check the ARD manifest draft (PROJECT_SUMMARY.md §10). It was a draft at
   triage time and was deferred to this same gate; if it has gained real
   adopters by then it is cheap to add next to the catalog. If it has not, leave
   it alone.
