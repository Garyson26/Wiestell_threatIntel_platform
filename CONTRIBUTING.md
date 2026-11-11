# Contributing to Wiestell

Thanks for your interest in Wiestell! Bug reports, feature ideas, docs fixes, new feed connectors and new enrichers are all welcome.

## Ways to contribute

- **Report a bug.** Open an issue with steps to reproduce it, what you expected, what happened, and your environment (OS, Python and Node versions, Docker or not).
- **Suggest a feature.** Open an issue describing the problem it solves before you write a large change, so we can agree on the approach first.
- **Send a pull request.** Small, focused PRs are reviewed fastest.

### Reporting security issues

**Do not open a public issue for a vulnerability.** Report it privately through GitHub's [Report a vulnerability](https://github.com/Garyson26/Wiestell_threatIntel_platform/security/advisories/new) form. Include the affected component, reproduction steps and the impact you expect.

## Development setup

You need Python 3.11+, Node.js 20+, and Docker (optional for the default test suite, required for the database tests). Follow the [Quick start](README.md#quick-start) in the README to get the stack running, or run each part on its own:

```bash
# Backend (from backend/)
pip install -r requirements-dev.txt   # also installs requirements.txt
alembic upgrade head
uvicorn app.main:app --reload --port 8000

# Frontend (from frontend/)
npm ci
npm run dev
```

The backend will not start without `DATABASE_URL` and `SECRET_KEY`. See [`.env.example`](.env.example).

> **PowerShell users:** `VAR=value command` and `&&` do not work in Windows PowerShell 5.1. Set variables with `$env:NAME = "value"` on their own line, and run commands on separate lines.

## Running the tests

```bash
cd backend
python -m pytest                          # default tier, about 5 seconds, no database
python -m pytest tests/test_enrichers.py  # a single file
python -m pytest -k "cvss or kev"         # filter by name
```

The **database tier** runs against a real MariaDB container and covers behaviour a mocked session cannot check:

```bash
docker compose up -d db
cd backend
python -m pytest -m mysql                 # about 80 seconds
```

These tests skip with a clear message when the container is not running.

Frontend checks:

```bash
cd frontend
npm run lint
npx tsc --noEmit
npm run build
```

## Pull request checklist

- [ ] The change is focused, and the PR description explains **what** changed and **why**.
- [ ] `python -m pytest` passes. If you touched queries, ingestion or datetimes, `python -m pytest -m mysql` passes too.
- [ ] `npm run lint` and `npx tsc --noEmit` pass for frontend changes.
- [ ] New behaviour has tests. A bug fix includes a test that fails without the fix.
- [ ] No secrets, `.env` files, GeoIP databases (`*.mmdb`) or other binaries are committed.
- [ ] Schema changes include an Alembic migration (`alembic revision -m "..."`). This project writes migrations by hand and does not use autogenerate.
- [ ] Any change that moves threat scores bumps `SCORING_MODEL_VERSION` in `services/scoring_engine.py`.

## Codebase conventions

[CLAUDE.md](CLAUDE.md) has the detailed notes. These are the rules that cause real bugs when missed:

**The database is MySQL/MariaDB, not PostgreSQL.**
- `tags`, `metadata` and `mitre_techniques` are `JSON` columns. Filter them with `func.json_contains(col, func.json_quote(value)) == 1`, not `.any()` or `.overlap()`.
- Store datetimes as timezone-naive UTC: `datetime.now(timezone.utc).replace(tzinfo=None)`.
- IDs are `CHAR(36)` UUID strings, so path parameters are typed `str`.

**Transactions.** `get_db()` commits when the request finishes, so handlers call `await db.flush()`, never `commit()`.

**Authorization.** Routes inherit their router's auth dependency. The `/users` and `/contact` routers are deliberately unguarded because they mix public and private routes, so add the role dependency explicitly there. Frontend route guards are only UX, not security.

**Errors.** Pass any exception string that is stored or returned through `utils/sanitize.redact_secrets()`, because driver errors can contain connection strings.

**Frontend requests.** Go through `lib/api.ts::fetchAPI` so the auth token is attached. Never log response bodies or search parameters on the client.

### Adding a threat feed

1. Subclass `feeds/base.py::BaseFeed` and set `slug`, `feed_type`, `url` and `name`. `parse()` must return plain dicts built with `_make_ioc()`.
2. Register the slug in `services/feed_scheduler.py::FEED_CONNECTORS`.
3. Add a row to `scripts/seed_feeds.py`.
4. If the feed needs an API key, add the variable name to `config.ALLOWED_FEED_API_KEY_ENVS` and document it in `.env.example`.

### Adding an enricher

1. Subclass `BaseEnricher` in `app/enrichers/` and register it in `build_registry()` in `__init__.py`. Registration order is the order sources are tried in.
2. `enrich()` must never raise. Return a dict, `None` for "not applicable", or `{"error": ...}`.
3. Only register the enricher when its credentials are configured.
4. If it produces a risk signal, return an `assessed` list of the signals it evaluated, and add matching entries to `RISK_SIGNALS` in the scoring engine.
5. Run blocking libraries through `run_in_executor` so they don't stall the event loop.

## Commit messages

Write a short summary line in the imperative mood ("Add ThreatFox CSV fallback", not "Added…"), followed by a body explaining the reasoning where it isn't obvious.

## License

By contributing, you agree that your contributions are licensed under the [Apache License 2.0](LICENSE), the same license as the project.
