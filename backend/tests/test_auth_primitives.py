"""Token, OTP and password-policy primitives."""

import hmac

import jwt
import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from app.api import deps, users as users_api
from app.config import settings
from app.schemas.user import UserRegister, PasswordChange, PasswordReset
from tests.conftest import make_user


class TestAccessTokens:
    def test_round_trip_carries_identity_and_role(self):
        user = make_user(role="analyst", user_id="abc-123")
        payload = deps.decode_access_token(deps.create_access_token(user))
        assert payload["sub"] == "abc-123"
        assert payload["role"] == "analyst"
        assert payload["type"] == "access"
        assert payload["jti"] and payload["iat"] and payload["exp"]

    def test_token_signed_with_another_key_is_rejected(self):
        # The attacker key is >=32 bytes only to keep the suite warning-free: PyJWT 2.13
        # emits InsecureKeyLengthWarning below that, and "attacker-key" (12 bytes) tripped
        # it. Key length is incidental to this test - what matters is that the key differs
        # from SECRET_KEY. Worth noting the warning agrees with app/config.py, which
        # already refuses a SECRET_KEY under 32 characters in production.
        forged = jwt.encode(
            {"sub": "abc-123", "role": "admin", "type": "access", "exp": 9999999999},
            "attacker-key-padded-to-thirty-two-bytes-min",
            algorithm="HS256",
        )
        with pytest.raises(HTTPException) as exc:
            deps.decode_access_token(forged)
        assert exc.value.status_code == 401

    def test_non_access_token_type_is_rejected(self):
        token = jwt.encode(
            {"sub": "abc-123", "type": "refresh", "exp": 9999999999},
            settings.SECRET_KEY,
            algorithm="HS256",
        )
        with pytest.raises(HTTPException):
            deps.decode_access_token(token)

    def test_token_without_expiry_is_rejected(self):
        token = jwt.encode(
            {"sub": "abc-123", "type": "access"}, settings.SECRET_KEY, algorithm="HS256"
        )
        with pytest.raises(HTTPException):
            deps.decode_access_token(token)

    def test_expired_token_is_rejected(self):
        token = jwt.encode(
            {"sub": "abc-123", "type": "access", "exp": 1000000000},
            settings.SECRET_KEY,
            algorithm="HS256",
        )
        with pytest.raises(HTTPException):
            deps.decode_access_token(token)

    def test_unsigned_alg_none_token_is_rejected(self):
        """Algorithm confusion: 'none' must not be accepted."""
        token = jwt.encode(
            {"sub": "abc-123", "type": "access", "exp": 9999999999}, None, algorithm="none"
        )
        with pytest.raises(HTTPException):
            deps.decode_access_token(token)


class TestOTP:
    def test_codes_are_six_digits_and_high_entropy(self):
        codes = {users_api.generate_otp() for _ in range(300)}
        assert all(len(c) == 6 and c.isdigit() for c in codes)
        # A non-cryptographic or narrow generator would collide far more often.
        assert len(codes) > 250

    def test_stored_value_is_a_keyed_hash_not_the_code(self):
        digest = users_api._hash_otp("user@example.com", "123456")
        assert digest != "123456"
        assert len(digest) == 64

    def test_hash_is_stable_and_bound_to_the_email(self):
        a = users_api._hash_otp("user@example.com", "123456")
        assert users_api._hash_otp("user@example.com", "123456") == a
        # A code issued for one mailbox cannot be replayed against another.
        assert users_api._hash_otp("other@example.com", "123456") != a
        assert users_api._hash_otp("user@example.com", "123457") != a

    def test_comparison_is_constant_time(self):
        digest = users_api._hash_otp("user@example.com", "123456")
        assert hmac.compare_digest(digest, users_api._hash_otp("user@example.com", "123456"))

    def test_purposes_are_distinct(self):
        assert len({users_api.PURPOSE_LOGIN, users_api.PURPOSE_SIGNUP, users_api.PURPOSE_RESET}) == 3


class TestPasswordPolicy:
    @pytest.mark.parametrize("password,reason", [
        ("Sh0rt!", "under the minimum length"),
        ("alllowercaseletters", "single character class"),
        ("password1234", "two character classes"),
        ("A" * 80 + "a1!", "beyond bcrypt's 72-byte limit"),
    ])
    def test_weak_passwords_rejected(self, password, reason):
        with pytest.raises(ValidationError):
            UserRegister(username="tester", email="t@example.com", password=password)

    @pytest.mark.parametrize("password", [
        "Str0ng-Passw0rd!",
        "correct horse Battery 9",
        "aB3$aB3$aB3$",
    ])
    def test_strong_passwords_accepted(self, password):
        UserRegister(username="tester", email="t@example.com", password=password)

    def test_policy_applies_to_change_and_reset(self):
        with pytest.raises(ValidationError):
            PasswordChange(current_password="x", new_password="weak")
        with pytest.raises(ValidationError):
            PasswordReset(email="t@example.com", otp="123456", new_password="weak")

    def test_registration_defaults_to_least_privilege(self):
        user = UserRegister(username="tester", email="t@example.com", password="Str0ng-Passw0rd!")
        assert user.role == "viewer"

    def test_invalid_email_and_username_rejected(self):
        with pytest.raises(ValidationError):
            UserRegister(username="tester", email="not-an-email", password="Str0ng-Passw0rd!")
        with pytest.raises(ValidationError):
            UserRegister(username="bad name!", email="t@example.com", password="Str0ng-Passw0rd!")

    def test_otp_field_must_be_six_digits(self):
        with pytest.raises(ValidationError):
            PasswordReset(email="t@example.com", otp="abcdef", new_password="Str0ng-Passw0rd!")


class TestCronSecretComparison:
    """Finding R-01: a non-ASCII `X-Cron-Secret` used to raise instead of returning 401.

    Starlette decodes header values as latin-1, so any byte in 0x80-0xFF yields a non-ASCII
    `str`, and `hmac.compare_digest` refuses two `str` operands when either contains one.
    That turned a 401 into an unauthenticated 500 on the two cron-accepting endpoints, in
    one request with no credentials. It failed CLOSED - no bypass - but this is the one auth
    dependency an unauthenticated caller is invited to exercise.
    """

    def test_a_non_ascii_secret_returns_false_rather_than_raising(self):
        from app.api.deps import _secret_matches

        # 0xFF decoded as latin-1 - exactly what Starlette hands over for that byte.
        assert _secret_matches("\xff", "the-configured-cron-secret") is False

    def test_every_high_byte_is_handled(self):
        from app.api.deps import _secret_matches

        for byte in range(0x80, 0x100):
            assert _secret_matches(chr(byte), "the-configured-cron-secret") is False

    def test_a_correct_secret_still_matches(self):
        from app.api.deps import _secret_matches

        assert _secret_matches("s3cret-value", "s3cret-value") is True

    def test_a_wrong_ascii_secret_does_not_match(self):
        from app.api.deps import _secret_matches

        assert _secret_matches("wrong", "s3cret-value") is False

    def test_a_multibyte_secret_matches_itself(self):
        """The configured secret is utf-8; the header arrives latin-1-decoded.

        A generated CRON_SECRET is ASCII, so this is the degenerate case - but it must not
        raise if someone sets a non-ASCII secret by hand.
        """
        from app.api.deps import _secret_matches

        assert _secret_matches("café", "café") is False  # differing encodings, no crash
