"""Changing an account's email must need more than a bearer token (issue #123).

The attack this pins: a stolen JWT (12 h, no revocation, in localStorage) sets the
account email to an attacker's address, then /forgot-password sends the reset code
there. A token-only email change turns a 12-hour credential into permanent
takeover. So a change now needs the current password AND a code delivered to the
new address, the old address is told, and the admin route cannot be used as a
side door around either.
"""

from datetime import datetime

import pytest

from app.api import deps, users
from app.database import get_db
from app.main import app
from app.models.otp import OTP
from app.models.user import User
from tests.inmemory_session import InMemorySession, dependency

PASSWORD = "Correct-Horse-Battery-9!"
HASH = users.pwd_context.hash(PASSWORD)
OLD = "owner@example.com"
NEW = "new-home@example.com"
ATTACKER = "attacker@example.com"


def _user(user_id, email, role="viewer", username=None):
    return User(
        id=user_id,
        username=username or user_id,
        email=email,
        hashed_password=HASH,
        full_name="Owner",
        role=role,
        is_active=True,
        created_at=datetime(2026, 1, 1),
    )


@pytest.fixture
def mail(monkeypatch):
    """Capture outgoing mail instead of calling Resend."""
    sent = {"otp": [], "notice": []}

    async def fake_otp(to_email, otp, username, **kwargs):
        sent["otp"].append({"to": to_email, "otp": otp, **kwargs})
        return True

    async def fake_notice(to_email, subject, message):
        sent["notice"].append({"to": to_email, "subject": subject, "message": message})
        return True

    monkeypatch.setattr(users, "send_otp_email", fake_otp)
    monkeypatch.setattr(users, "send_notification_email", fake_notice)
    monkeypatch.setattr(deps.rate_limiter, "check_rate_limit", lambda *a, **k: True)
    return sent


@pytest.fixture
def world(client, mail):
    """Owner, a second user, and an admin, in a session that evaluates WHERE clauses."""
    owner = _user("owner-id", OLD)
    other = _user("other-id", "other@example.com")
    admin = _user("admin-id", "admin@example.com", role="admin")
    db = InMemorySession(owner, other, admin)
    app.dependency_overrides[get_db] = dependency(db)

    def auth(user):
        return {"Authorization": f"Bearer {deps.create_access_token(user)}"}

    return {"db": db, "owner": owner, "other": other, "admin": admin, "auth": auth,
            "client": client, "mail": mail}


def _request(w, new=NEW, password=PASSWORD, who="owner"):
    return w["client"].post(
        "/api/v1/users/me/email",
        headers=w["auth"](w[who]),
        json={"new_email": new, "current_password": password},
    )


def _verify(w, otp, new=NEW, who="owner"):
    return w["client"].post(
        "/api/v1/users/me/email/verify",
        headers=w["auth"](w[who]),
        json={"new_email": new, "otp": otp},
    )


# ── The takeover itself ───────────────────────────────────────────────────────

class TestTokenAloneCannotChangeEmail:
    def test_put_me_refuses_a_different_email(self, world):
        r = world["client"].put(
            "/api/v1/users/me", headers=world["auth"](world["owner"]),
            json={"email": ATTACKER},
        )
        assert r.status_code == 400
        assert world["owner"].email == OLD
        assert world["mail"]["otp"] == []

    def test_put_me_still_saves_the_name_when_email_is_unchanged(self, world):
        # The profile page always sends the current email alongside the name.
        r = world["client"].put(
            "/api/v1/users/me", headers=world["auth"](world["owner"]),
            json={"full_name": "Renamed", "email": OLD},
        )
        assert r.status_code == 200, r.text
        assert world["owner"].full_name == "Renamed"
        assert world["owner"].email == OLD

    def test_request_with_wrong_password_sends_nothing(self, world):
        r = _request(world, new=ATTACKER, password="not-the-password")
        assert r.status_code == 400
        assert world["mail"]["otp"] == []
        assert world["db"].of(OTP) == []
        assert world["owner"].email == OLD

    def test_full_chain_is_closed(self, world):
        """Token-only: neither route moves the email, so forgot-password cannot follow."""
        world["client"].put("/api/v1/users/me", headers=world["auth"](world["owner"]),
                            json={"email": ATTACKER})
        _request(world, new=ATTACKER, password="guess")
        assert world["owner"].email == OLD


# ── The legitimate flow ───────────────────────────────────────────────────────

class TestVerifiedEmailChange:
    def test_request_mails_a_code_to_the_new_address_only(self, world):
        r = _request(world)
        assert r.status_code == 200, r.text
        assert [m["to"] for m in world["mail"]["otp"]] == [NEW]
        assert world["owner"].email == OLD, "the switch must wait for the code"

        (row,) = world["db"].of(OTP)
        assert row.purpose == users.PURPOSE_EMAIL_CHANGE
        assert row.user_id == "owner-id"
        assert row.email == NEW
        assert row.otp != world["mail"]["otp"][0]["otp"], "code must be stored hashed"

    def test_correct_code_switches_and_tells_the_old_address(self, world):
        _request(world)
        code = world["mail"]["otp"][0]["otp"]
        r = _verify(world, code)
        assert r.status_code == 200, r.text
        assert r.json()["email"] == NEW
        assert world["owner"].email == NEW
        assert [n["to"] for n in world["mail"]["notice"]] == [OLD]
        assert code not in world["mail"]["notice"][0]["message"]

    def test_code_is_single_use(self, world):
        _request(world)
        code = world["mail"]["otp"][0]["otp"]
        assert _verify(world, code).status_code == 200
        assert _verify(world, code).status_code == 401

    def test_wrong_code_does_not_switch(self, world):
        _request(world)
        code = world["mail"]["otp"][0]["otp"]
        wrong = "000000" if code != "000000" else "111111"
        assert _verify(world, wrong).status_code == 401
        assert world["owner"].email == OLD

    def test_code_for_a_different_new_address_does_not_switch(self, world):
        _request(world)
        code = world["mail"]["otp"][0]["otp"]
        assert _verify(world, code, new=ATTACKER).status_code == 401
        assert world["owner"].email == OLD

    def test_same_address_is_rejected(self, world):
        assert _request(world, new=OLD).status_code == 400

    def test_address_owned_by_another_account_is_rejected(self, world):
        assert _request(world, new="other@example.com").status_code == 409
        assert world["mail"]["otp"] == []

    def test_address_claimed_between_request_and_verify_is_rejected(self, world):
        _request(world)
        code = world["mail"]["otp"][0]["otp"]
        world["db"].add(_user("late-id", NEW, username="late"))
        assert _verify(world, code).status_code == 409
        assert world["owner"].email == OLD


# ── Codes must not cross users or purposes ────────────────────────────────────

class TestCodesStayInTheirLane:
    def test_another_users_code_cannot_confirm_my_change(self, world):
        """Both users target the same new address; each code belongs to its requester."""
        _request(world, who="other")
        other_code = world["mail"]["otp"][0]["otp"]
        assert _verify(world, other_code, who="owner").status_code == 401
        assert world["owner"].email == OLD

    def test_my_pending_change_survives_another_users_request(self, world):
        _request(world, who="owner")
        owner_code = world["mail"]["otp"][0]["otp"]
        _request(world, who="other")
        assert _verify(world, owner_code, who="owner").status_code == 200
        assert world["owner"].email == NEW

    def test_a_login_code_cannot_confirm_an_email_change(self, world):
        world["db"].add(OTP(
            user_id="owner-id", email=NEW, otp=users._hash_otp(NEW, "123456"),
            purpose=users.PURPOSE_LOGIN, attempts=0,
            expires_at=datetime(2099, 1, 1), verified="pending",
        ))
        assert _verify(world, "123456").status_code == 401
        assert world["owner"].email == OLD

    def test_an_email_change_code_cannot_mint_a_session(self, world):
        _request(world)
        code = world["mail"]["otp"][0]["otp"]
        r = world["client"].post("/api/v1/users/verify-otp", json={"email": NEW, "otp": code})
        assert r.status_code == 401

    def test_codes_issued_to_the_old_address_die_with_the_change(self, world):
        """A login code mailed to the old address must not outlive the move away from it."""
        world["db"].add(OTP(
            user_id="owner-id", email=OLD, otp=users._hash_otp(OLD, "654321"),
            purpose=users.PURPOSE_LOGIN, attempts=0,
            expires_at=datetime(2099, 1, 1), verified="pending",
        ))
        _request(world)
        code = world["mail"]["otp"][0]["otp"]
        assert _verify(world, code).status_code == 200
        r = world["client"].post("/api/v1/users/verify-otp", json={"email": OLD, "otp": "654321"})
        assert r.status_code == 401
        assert not [o for o in world["db"].of(OTP) if o.verified == "pending"]

    def test_admin_change_also_kills_codes_for_the_old_address(self, world):
        world["db"].add(OTP(
            user_id="owner-id", email=OLD, otp=users._hash_otp(OLD, "654321"),
            purpose=users.PURPOSE_LOGIN, attempts=0,
            expires_at=datetime(2099, 1, 1), verified="pending",
        ))
        changed = world["client"].put(
            "/api/v1/users/owner-id", headers=world["auth"](world["admin"]),
            json={"email": NEW, "current_password": PASSWORD},
        )
        assert changed.status_code == 200, changed.text  # else the 401 below proves nothing
        r = world["client"].post("/api/v1/users/verify-otp", json={"email": OLD, "otp": "654321"})
        assert r.status_code == 401

    def test_attempts_are_capped(self, world):
        _request(world)
        code = world["mail"]["otp"][0]["otp"]
        wrong = "000000" if code != "000000" else "111111"
        for _ in range(users.settings.OTP_MAX_ATTEMPTS):
            _verify(world, wrong)
        assert _verify(world, code).status_code in (401, 429)
        assert world["owner"].email == OLD


# ── The admin route is not a side door ────────────────────────────────────────

class TestAdminRoute:
    def _put(self, w, target_id, body):
        return w["client"].put(f"/api/v1/users/{target_id}",
                               headers=w["auth"](w["admin"]), json=body)

    def test_admin_token_alone_cannot_change_another_users_email(self, world):
        r = self._put(world, "owner-id", {"email": ATTACKER})
        assert r.status_code == 400
        assert world["owner"].email == OLD

    def test_admin_with_wrong_password_cannot_change_it(self, world):
        r = self._put(world, "owner-id", {"email": ATTACKER, "current_password": "nope"})
        assert r.status_code == 400
        assert world["owner"].email == OLD

    def test_admin_with_password_can_change_it_and_the_user_is_told(self, world):
        r = self._put(world, "owner-id", {"email": NEW, "current_password": PASSWORD})
        assert r.status_code == 200, r.text
        assert world["owner"].email == NEW
        assert [n["to"] for n in world["mail"]["notice"]] == [OLD]

    def test_admin_cannot_change_their_own_email_here(self, world):
        r = self._put(world, "admin-id", {"email": NEW, "current_password": PASSWORD})
        assert r.status_code == 400
        assert world["admin"].email == "admin@example.com"

    def test_admin_can_still_rename_without_a_password(self, world):
        r = self._put(world, "owner-id", {"full_name": "Renamed"})
        assert r.status_code == 200, r.text
        assert world["owner"].full_name == "Renamed"
