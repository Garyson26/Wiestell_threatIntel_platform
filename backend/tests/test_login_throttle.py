"""Per-account failed-password counter with escalating back-off (issue #127).

The per-IP ``rate_limit`` cannot protect a password from someone rotating source
addresses, so the control lives on the account row: ``failed_login_attempts`` and
``locked_until``. Requirements pinned here, from the issue:

- escalating back-off, not a hard lock (a hard lock on a known admin email is a
  DoS primitive), capped so the worst case is bounded
- the response is identical whether the account is throttled or the password is
  simply wrong, and a throttled attempt still spends a bcrypt verification so
  latency does not tell them apart either
- unknown emails are rejected immediately and write nothing
- the request IP is never consulted
- every gate that checks a user's own password shares the one counter, or the
  token-authenticated gates become an unthrottled oracle around it
- an attempt is reserved with a compare-and-swap and COMMITTED before the verdict:
  ``get_db`` rolls back on the 401, which would otherwise erase the increment,
  and parallel requests that all read the same count must not each get a guess
"""

from datetime import datetime, timedelta, timezone

import pytest

from app.api import deps, users
from app.config import settings
from app.database import get_db
from app.main import app
from app.models.user import User
from app.services import password_throttle
from app.services.password_throttle import backoff_seconds, verify_password_throttled
from tests.inmemory_session import InMemorySession, dependency

PASSWORD = "Correct-Horse-Battery-9!"
HASH = users.pwd_context.hash(PASSWORD)
EMAIL = "owner@example.com"
FREE = settings.LOGIN_FREE_ATTEMPTS
BASE = settings.LOGIN_BACKOFF_BASE_SECONDS
CAP = settings.LOGIN_BACKOFF_MAX_SECONDS


def _now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _user(user_id="owner-id", email=EMAIL, role="viewer"):
    return User(
        id=user_id, username=user_id, email=email, hashed_password=HASH,
        full_name="Owner", role=role, is_active=True, created_at=datetime(2026, 1, 1),
        failed_login_attempts=0, locked_until=None,
    )


@pytest.fixture
def world(client, monkeypatch):
    sent = []

    async def fake_otp(to_email, otp, username, **kwargs):
        sent.append(to_email)
        return True

    monkeypatch.setattr(users, "send_otp_email", fake_otp)
    monkeypatch.setattr(deps.rate_limiter, "check_rate_limit", lambda *a, **k: True)

    owner = _user()
    admin = _user("admin-id", "admin@example.com", role="admin")
    db = InMemorySession(owner, admin)
    app.dependency_overrides[get_db] = dependency(db)
    return {"client": client, "db": db, "owner": owner, "admin": admin, "sent": sent}


def _login(w, password, email=EMAIL):
    return w["client"].post("/api/v1/users/login", json={"email": email, "password": password})


def _auth(user):
    return {"Authorization": f"Bearer {deps.create_access_token(user)}"}


def _lock_until_seconds(user):
    return (user.locked_until - _now()).total_seconds()


# ── Before #127: the hole ─────────────────────────────────────────────────────

class TestPasswordGuessingIsBounded:
    def test_many_wrong_guesses_then_the_right_one_is_refused(self, world):
        """Pre-#127 this issued an OTP: per-IP limits were the only control."""
        for _ in range(FREE + 10):
            _login(world, "wrong-guess")
        assert _login(world, PASSWORD).status_code == 401
        assert world["sent"] == []


# ── Back-off schedule ─────────────────────────────────────────────────────────

class TestBackoff:
    def test_schedule_doubles_from_the_base_and_is_capped(self):
        assert [backoff_seconds(n) for n in range(1, FREE)] == [0] * (FREE - 1)
        assert backoff_seconds(FREE) == BASE
        assert backoff_seconds(FREE + 1) == 2 * BASE
        assert backoff_seconds(FREE + 2) == 4 * BASE
        assert backoff_seconds(FREE + 50) == CAP
        assert backoff_seconds(10 ** 6) == CAP  # no overflow on a long-abused account

    def test_free_attempts_then_a_lock(self, world):
        for i in range(1, FREE):
            assert _login(world, "wrong").status_code == 401
            assert world["owner"].failed_login_attempts == i, "increment lost to the 401 rollback"
            assert world["owner"].locked_until is None
        assert _login(world, "wrong").status_code == 401
        assert world["owner"].failed_login_attempts == FREE
        assert BASE - 5 <= _lock_until_seconds(world["owner"]) <= BASE

    def test_expiry_allows_exactly_one_attempt_and_the_next_lock_doubles(self, world):
        world["owner"].failed_login_attempts = FREE
        world["owner"].locked_until = _now() - timedelta(seconds=1)
        assert _login(world, "wrong").status_code == 401
        assert world["owner"].failed_login_attempts == FREE + 1
        assert 2 * BASE - 5 <= _lock_until_seconds(world["owner"]) <= 2 * BASE
        before = world["owner"].failed_login_attempts
        assert _login(world, "wrong").status_code == 401
        assert world["owner"].failed_login_attempts == before, "a refused attempt must not extend the lock"

    def test_success_resets_the_counter(self, world):
        for _ in range(FREE - 1):
            _login(world, "wrong")
        assert _login(world, PASSWORD).status_code == 200
        assert world["owner"].failed_login_attempts == 0
        assert world["owner"].locked_until is None
        assert world["sent"] == [EMAIL]


# ── No oracle ─────────────────────────────────────────────────────────────────

class TestNoOracle:
    def test_throttled_and_wrong_password_responses_are_identical(self, world):
        wrong = _login(world, "wrong")
        world["owner"].failed_login_attempts = FREE
        world["owner"].locked_until = _now() + timedelta(seconds=BASE)
        throttled = _login(world, PASSWORD)
        unknown = _login(world, "wrong", email="nobody@example.com")
        assert throttled.status_code == wrong.status_code == unknown.status_code == 401
        assert throttled.json() == wrong.json() == unknown.json()
        assert "retry-after" not in {k.lower() for k in throttled.headers}

    def test_a_throttled_attempt_still_spends_a_hash(self, world, monkeypatch):
        calls = []
        real = users.pwd_context.dummy_verify
        monkeypatch.setattr(users.pwd_context, "dummy_verify",
                            lambda *a, **k: calls.append(1) or real(*a, **k))
        world["owner"].failed_login_attempts = FREE
        world["owner"].locked_until = _now() + timedelta(seconds=BASE)
        _login(world, PASSWORD)
        assert calls, "a locked account answered without hashing - faster than a wrong password"

    def test_unknown_email_writes_nothing(self, world):
        before = world["db"].commits
        assert _login(world, "x", email="nobody@example.com").status_code == 401
        assert world["db"].commits == before


class TestNotKeyedOnIP:
    def test_rotating_source_address_does_not_reset_anything(self, world, monkeypatch):
        """Real limiter, a fresh address per request: only the account counter can stop this."""
        monkeypatch.undo()  # restore the real rate limiter and email sender
        sent = []

        async def fake_otp(to_email, otp, username, **kwargs):
            sent.append(to_email)
            return True

        monkeypatch.setattr(users, "send_otp_email", fake_otp)
        addresses = iter(f"198.51.100.{i}" for i in range(1, 250))
        monkeypatch.setattr(deps, "_client_ip", lambda request: next(addresses))
        for _ in range(FREE + 5):
            _login(world, "wrong")
        assert _login(world, PASSWORD).status_code == 401
        assert sent == []


# ── Every own-password gate shares the counter ────────────────────────────────

class TestSharedCounter:
    def test_failures_at_change_password_lock_login(self, world):
        for _ in range(FREE):
            world["client"].put("/api/v1/users/me/password", headers=_auth(world["owner"]),
                                json={"current_password": "wrong", "new_password": "N3w-Passw0rd-long!"})
        assert world["owner"].failed_login_attempts == FREE
        assert _login(world, PASSWORD).status_code == 401

    def test_failures_at_email_change_lock_login(self, world):
        for _ in range(FREE):
            world["client"].post("/api/v1/users/me/email", headers=_auth(world["owner"]),
                                 json={"new_email": "x@example.com", "current_password": "wrong"})
        assert _login(world, PASSWORD).status_code == 401

    def test_locked_account_cannot_change_password_even_with_the_right_one(self, world):
        world["owner"].failed_login_attempts = FREE
        world["owner"].locked_until = _now() + timedelta(seconds=BASE)
        r = world["client"].put("/api/v1/users/me/password", headers=_auth(world["owner"]),
                                json={"current_password": PASSWORD, "new_password": "N3w-Passw0rd-long!"})
        assert r.status_code == 400
        assert users.pwd_context.verify(PASSWORD, world["owner"].hashed_password)

    def test_admin_email_change_counts_against_the_admin(self, world):
        for _ in range(FREE):
            world["client"].put("/api/v1/users/owner-id", headers=_auth(world["admin"]),
                                json={"email": "moved@example.com", "current_password": "wrong"})
        assert world["admin"].failed_login_attempts == FREE
        assert world["owner"].email == EMAIL


# ── The reservation is a compare-and-swap ─────────────────────────────────────

class TestReservation:
    @pytest.mark.asyncio
    async def test_a_stale_read_loses_the_race_even_with_the_right_password(self):
        """Two requests read count FREE-1; the first reserves; the second must not evaluate."""
        row = _user()
        row.failed_login_attempts = FREE
        row.locked_until = _now() + timedelta(seconds=BASE)
        db = InMemorySession(row)
        stale = _user()  # same id, the snapshot an earlier SELECT returned
        stale.failed_login_attempts = FREE - 1
        assert await verify_password_throttled(db, stale, PASSWORD, users.pwd_context) is False
        assert row.failed_login_attempts == FREE, "the losing request must not write"

    @pytest.mark.asyncio
    async def test_parallel_reads_in_the_free_window_get_one_guess_between_them(self):
        """The real race: N requests all read count 0 before any writes.

        Without the equality in the WHERE each would 'reserve' by writing 1, all N
        passwords would be evaluated, and the counter would end at 1. Here the row is
        unlocked, so only the equality can refuse the stale reader.
        """
        row = _user()
        db = InMemorySession(row)
        reads = [_user() for _ in range(10)]  # ten snapshots of count 0, same id
        results = [await verify_password_throttled(db, r, "wrong", users.pwd_context)
                   for r in reads]
        assert results.count(False) == 10
        assert row.failed_login_attempts == 1, "nine stale readers were evaluated"
        assert await verify_password_throttled(db, _user(), PASSWORD, users.pwd_context) is False

    @pytest.mark.asyncio
    async def test_success_resets_the_stored_row_not_just_the_loaded_object(self):
        row = _user()
        row.failed_login_attempts = 2
        db = InMemorySession(row)
        loaded = _user()
        loaded.failed_login_attempts = 2
        assert await verify_password_throttled(db, loaded, PASSWORD, users.pwd_context) is True
        assert row.failed_login_attempts == 0
        assert row.locked_until is None

    @pytest.mark.asyncio
    async def test_the_reservation_is_committed_before_the_verdict(self):
        row = _user()
        db = InMemorySession(row)
        await verify_password_throttled(db, row, "wrong", users.pwd_context)
        await db.rollback()  # what get_db does when the handler then raises 401
        assert row.failed_login_attempts == 1

    def test_module_never_reads_the_request(self):
        import inspect
        source = inspect.getsource(password_throttle)
        assert source.strip(), "nothing extracted - the check below would pass vacuously"
        assert "fastapi" not in source.lower(), "no access to a Request object, so no IP"
        assert "_client_ip" not in source
