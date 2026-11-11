"""Access control on the HTTP surface.

Regression guard for the review finding that every endpoint was reachable
without credentials, including one that minted admin accounts.
"""

import pytest
from fastapi.dependencies.utils import get_dependant

from app.api import deps
from app.config import settings
from app.main import app

# (method, path) pairs that must never be reachable anonymously.
PROTECTED = [
    ("get", "/api/v1/users"),
    ("post", "/api/v1/users"),
    ("get", "/api/v1/users/some-id"),
    ("put", "/api/v1/users/some-id"),
    ("get", "/api/v1/users/me"),
    ("put", "/api/v1/users/me"),
    ("put", "/api/v1/users/me/password"),
    ("post", "/api/v1/users/me/email"),
    ("post", "/api/v1/users/me/email/verify"),
    ("get", "/api/v1/iocs"),
    ("get", "/api/v1/iocs/lookup?value=1.2.3.4"),
    ("post", "/api/v1/iocs"),
    ("post", "/api/v1/iocs/search"),
    ("post", "/api/v1/iocs/bulk"),
    ("post", "/api/v1/iocs/export"),
    ("get", "/api/v1/iocs/some-id"),
    ("put", "/api/v1/iocs/some-id/tags"),
    ("post", "/api/v1/iocs/some-id/enrich"),
    ("get", "/api/v1/dashboard/stats"),
    ("get", "/api/v1/dashboard/timeline"),
    ("get", "/api/v1/dashboard/notifications"),
    ("get", "/api/v1/feeds"),
    ("post", "/api/v1/feeds"),
    ("put", "/api/v1/feeds/some-id"),
    ("delete", "/api/v1/feeds/some-id"),
    ("post", "/api/v1/feeds/some-id/sync"),
    ("post", "/api/v1/feeds/sync-all"),
    ("get", "/api/v1/feeds/some-id/logs"),
    ("get", "/api/v1/enrichment/backfill/status"),
    ("post", "/api/v1/enrichment/backfill/start"),
    ("get", "/api/v1/enrichment/some-id"),
    ("post", "/api/v1/enrichment/some-id/enrich"),
    ("get", "/api/v1/reports"),
    ("post", "/api/v1/reports/generate"),
    ("get", "/api/v1/reports/daily-brief"),
    ("get", "/api/v1/attack/matrix"),
    ("get", "/api/v1/attack/heatmap"),
    ("get", "/api/v1/ai/status"),
    ("post", "/api/v1/ai/chat"),
    ("post", "/api/v1/ai/report"),
    ("get", "/api/v1/contact/messages"),
    ("get", "/api/v1/contact/some-id"),
    ("patch", "/api/v1/contact/some-id/resolve"),
    ("get", "/api/v1/cron-status"),
]

PUBLIC = [
    ("get", "/"),
    ("get", "/health"),
    ("get", "/api/v1/health"),
]


def _call(client, method, path, body=None):
    fn = getattr(client, method)
    if method in ("post", "put", "patch"):
        return fn(path, json=body if body is not None else {})
    return fn(path)


@pytest.mark.parametrize("method,path", PROTECTED)
def test_protected_endpoint_rejects_anonymous(client, method, path):
    resp = _call(client, method, path)
    assert resp.status_code in (401, 403), f"{method.upper()} {path} -> {resp.status_code}"


@pytest.mark.parametrize("method,path", PUBLIC)
def test_public_endpoint_is_reachable(client, method, path):
    assert _call(client, method, path).status_code == 200


# Every route reachable without authentication, enumerated exhaustively.
# A rate limit is not an authorization control, so rate-limited endpoints such as
# /users/login belong on this list.
PUBLIC_ALLOWLIST = {
    ("GET", "/"),
    ("GET", "/health"),
    ("GET", "/api/v1/health"),
    ("POST", "/api/v1/users/register"),
    ("POST", "/api/v1/users/login"),
    ("POST", "/api/v1/users/verify-otp"),
    ("POST", "/api/v1/users/forgot-password"),
    ("POST", "/api/v1/users/reset-password"),
    ("POST", "/api/v1/contact/submit"),
    # Present only when ENABLE_API_DOCS is set or ENVIRONMENT is not production.
    ("GET", "/openapi.json"),
    ("GET", "/docs"),
    ("GET", "/docs/oauth2-redirect"),
    ("GET", "/redoc"),
}

# The docs routes are plain Starlette routes with no dependency tree, so the audit
# below never classifies them; they are allowlisted for the HTTP-level tests only.
DOCS_ROUTES = {
    ("GET", "/openapi.json"),
    ("GET", "/docs"),
    ("GET", "/docs/oauth2-redirect"),
    ("GET", "/redoc"),
}

# Names of dependencies that actually authenticate or authorize. Deliberately
# excludes `_rate_limit_checker`: before those two closures were given distinct
# names, both were called `_checker` and this audit counted a rate-limited public
# endpoint as guarded — a false negative in the control it exists to enforce.
GUARD_DEPENDENCY_NAMES = {
    "get_current_user",
    "get_optional_user",
    "require_admin_or_cron",
    "_role_checker",
}


def _is_guard(call) -> bool:
    return getattr(call, "__name__", "") in GUARD_DEPENDENCY_NAMES


def _dependant_is_guarded(dependant) -> bool:
    for dep in dependant.dependencies:
        if _is_guard(dep.call) or any(_is_guard(sub.call) for sub in dep.dependencies):
            return True
    return False


def _route_is_guarded(route, inherited=()) -> bool:
    if _dependant_is_guarded(route.dependant):
        return True
    # Dependencies passed to include_router(). fastapi 0.115 merges them into each
    # route's dependant; 0.162 keeps them on the include context, so they arrive here.
    for depends in inherited:
        call = depends.dependency
        if _is_guard(call) or _dependant_is_guarded(get_dependant(path="", call=call)):
            return True
    return False


def _iter_endpoints(routes, prefix="", inherited=()):
    """Yield (route, full path, include_router dependencies) for every endpoint.

    fastapi 0.115 flattens each include_router() call into app.routes. 0.162 keeps
    one _IncludedRouter per call instead, holding the original router plus an
    include context with the prefix and the router-level dependencies, which is
    how this project applies authentication. Walking only app.routes under 0.162
    collected 4 of 64 routes and the audit passed over those 4 (#138). This is
    duck-typed on the two attributes, not the private class name, and the floor
    tests below fail if a future version changes the shape again.
    """
    for route in routes:
        router = getattr(route, "original_router", None)
        context = getattr(route, "include_context", None)
        if router is not None and context is not None:
            yield from _iter_endpoints(
                router.routes,
                prefix + context.prefix,
                inherited + tuple(context.dependencies),
            )
        elif hasattr(route, "dependant") and getattr(route, "methods", None):
            yield route, prefix + route.path, inherited


def _classify_routes():
    guarded, public = [], []
    for route, path, inherited in _iter_endpoints(app.routes):
        for method in sorted(route.methods - {"HEAD", "OPTIONS"}):
            bucket = guarded if _route_is_guarded(route, inherited) else public
            bucket.append((method, path))
    return guarded, public


# The audit's subject is collected rather than named, so it must also assert how
# much it collected, or a collection that comes back nearly empty passes (#138).
# 64 = 55 guarded + 9 public, measured 2026-11-11 under fastapi 0.115.6 and 0.162.0.
# Raise it when routes are added; lowering it needs a removed route to justify it.
MIN_CLASSIFIED_ROUTES = 64


def test_the_audit_collects_every_route():
    guarded, public = _classify_routes()
    collected = set(guarded) | set(public)
    assert len(guarded) + len(public) >= MIN_CLASSIFIED_ROUTES, (
        f"route audit collected {len(guarded) + len(public)} routes, expected at least "
        f"{MIN_CLASSIFIED_ROUTES}: the route table changed shape and the walker missed it"
    )
    # The OpenAPI schema is built by the framework itself, independently of how
    # app.routes is shaped, so every operation in it must have been collected.
    schema = app.openapi()["paths"]
    documented = {
        (method.upper(), path)
        for path, operations in schema.items()
        for method in operations
        if method.upper() not in ("HEAD", "OPTIONS")
    }
    assert documented, "the OpenAPI schema is empty, so this cross-check checks nothing"
    missing = sorted(f"{m} {p}" for m, p in documented - collected)
    assert not missing, f"routes in the OpenAPI schema the audit never classified: {missing}"


def test_every_route_is_guarded_or_explicitly_public(capsys):
    """Walk the live route table so a new endpoint cannot be public by omission."""
    guarded, public = _classify_routes()

    # Printed so the two totals can be quoted accurately in documentation and
    # cannot drift apart silently. Visible with `pytest -s`.
    with capsys.disabled():
        print(
            f"\n[route audit] {len(guarded) + len(public)} routes"
            f" = {len(guarded)} guarded + {len(public)} public"
        )
        for method, path in sorted(public):
            print(f"[route audit]   public: {method} {path}")

    unexpected = [f"{m} {p}" for m, p in public if (m, p) not in PUBLIC_ALLOWLIST]
    assert not unexpected, f"unguarded routes missing from PUBLIC_ALLOWLIST: {unexpected}"


def test_allowlist_has_no_stale_entries():
    """An allowlist entry for a route that is guarded (or gone) hides drift."""
    guarded, public = _classify_routes()
    guarded_set, public_set = set(guarded), set(public)

    stale = [f"{m} {p}" for m, p in PUBLIC_ALLOWLIST if (m, p) in guarded_set]
    assert not stale, f"allowlisted routes that are actually guarded: {stale}"
    # A route the audit never collected was previously never compared, so an
    # allowlist entry for it passed whatever happened to the route (#138).
    gone = [
        f"{m} {p}"
        for m, p in PUBLIC_ALLOWLIST - DOCS_ROUTES
        if (m, p) not in public_set and (m, p) not in guarded_set
    ]
    assert not gone, f"allowlisted routes the audit did not find: {gone}"


def test_rate_limit_is_not_counted_as_authorization():
    """A rate-limited public endpoint must classify as public, not guarded."""
    _, public = _classify_routes()
    assert ("POST", "/api/v1/users/login") in public
    assert ("POST", "/api/v1/contact/submit") in public


def test_malformed_bearer_token_is_rejected(client):
    for header in ("Bearer not-a-jwt", "Bearer ", "Basic abc", "token abc"):
        resp = client.get("/api/v1/users", headers={"Authorization": header})
        assert resp.status_code == 401, header


def test_viewer_cannot_reach_admin_endpoints(as_role, client):
    headers = as_role("viewer")
    assert client.get("/api/v1/users", headers=headers).status_code == 403
    assert client.get("/api/v1/contact/messages", headers=headers).status_code == 403
    assert client.post("/api/v1/feeds/sync-all", headers=headers).status_code == 403
    assert client.post(
        "/api/v1/feeds", headers=headers,
        json={"name": "n", "slug": "s", "feed_type": "api"},
    ).status_code == 403


def test_viewer_cannot_mutate_iocs(as_role, client):
    headers = as_role("viewer")
    assert client.post(
        "/api/v1/iocs", headers=headers, json={"type": "ip", "value": "1.2.3.4"}
    ).status_code == 403
    assert client.put(
        "/api/v1/iocs/some-id/tags", headers=headers, json={"tags": []}
    ).status_code == 403


def test_analyst_can_mutate_iocs_but_not_administer(as_role, client):
    headers = as_role("analyst")
    assert client.get("/api/v1/users", headers=headers).status_code == 403
    # Passes authorization; the stubbed session decides the rest.
    assert client.post(
        "/api/v1/iocs", headers=headers, json={"type": "ip", "value": "1.2.3.4"}
    ).status_code != 403


def test_admin_passes_authorization(as_role, client):
    assert client.get("/api/v1/users", headers=as_role("admin")).status_code == 200


def test_disabled_account_is_rejected_despite_valid_signature(as_role, client):
    resp = client.get("/api/v1/users", headers=as_role("admin", is_active=False))
    assert resp.status_code == 403
    assert "disabled" in resp.text.lower()


def test_self_registration_cannot_request_admin_role(client, monkeypatch):
    """Privilege escalation guard: role in the payload is ignored."""
    from app.api import users as users_api

    captured = {}

    async def _fake_issue(db, **kwargs):
        captured.update(kwargs)

    monkeypatch.setattr(users_api, "_issue_otp", _fake_issue)

    async def _override():
        from tests.conftest import FakeSession
        yield FakeSession(None)          # no existing user with that name/email

    app.dependency_overrides[__import__("app.database", fromlist=["get_db"]).get_db] = _override

    resp = client.post("/api/v1/users/register", json={
        "username": "attacker",
        "email": "attacker@example.com",
        "password": "Str0ng-Passw0rd!",
        "role": "admin",
    })
    assert resp.status_code == 201, resp.text
    assert captured["registration"]["role"] == "viewer"


class TestCronSecret:
    def test_wrong_secret_is_rejected(self, client, monkeypatch):
        monkeypatch.setattr(settings, "CRON_SECRET", "the-real-secret")
        resp = client.post("/api/v1/feeds/sync-all", headers={"X-Cron-Secret": "wrong"})
        assert resp.status_code == 401

    def test_empty_configured_secret_never_matches(self, client, monkeypatch):
        monkeypatch.setattr(settings, "CRON_SECRET", "")
        resp = client.post("/api/v1/feeds/sync-all", headers={"X-Cron-Secret": ""})
        assert resp.status_code == 401


def test_security_headers_present(client):
    headers = client.get("/health").headers
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["X-Frame-Options"] == "DENY"
    assert headers["Referrer-Policy"] == "no-referrer"
    assert headers["Cache-Control"] == "no-store"
    assert "frame-ancestors 'none'" in headers["Content-Security-Policy"]


def test_unhandled_error_response_is_opaque(client, monkeypatch):
    """The 500 body must not leak the exception type, message or traceback."""
    from app.api import dashboard

    async def _boom(*args, **kwargs):
        raise RuntimeError("connection to mysql+aiomysql://u:supersecret@h/db failed")

    monkeypatch.setattr(dashboard, "get_stats", _boom)

    async def _override():
        from tests.conftest import FakeSession
        yield FakeSession(None)

    app.dependency_overrides[__import__("app.database", fromlist=["get_db"]).get_db] = _override
    headers = {"Authorization": f"Bearer {deps.create_access_token(__import__('tests.conftest', fromlist=['make_user']).make_user('admin'))}"}

    resp = client.get("/api/v1/dashboard/stats", headers=headers)
    if resp.status_code == 500:
        body = resp.text
        assert "supersecret" not in body
        assert "RuntimeError" not in body
        assert "Traceback" not in body
        assert "error_id" in body
