"""User management and authentication API endpoints."""

import hashlib
import hmac
import secrets
import string
from datetime import datetime, timezone, timedelta

import structlog
from fastapi import APIRouter, Depends, HTTPException, status
from passlib.context import CryptContext
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import (
    ROLE_VIEWER,
    create_access_token,
    get_current_user,
    rate_limit,
    require_admin,
)
from app.config import settings
from app.database import get_db
from app.models.otp import OTP
from app.models.user import User
from app.services.password_throttle import verify_password_throttled
from app.schemas.user import (
    UserRegister, UserUpdate, AdminUserUpdate, UserLogin, UserResponse,
    TokenResponse, UserListResponse, OTPVerify, OTPResponse,
    PasswordChange, PasswordResetRequest, PasswordReset,
    EmailChangeRequest, EmailChangeVerify,
)
from app.utils.email_service import send_notification_email, send_otp_email

logger = structlog.get_logger()

router = APIRouter()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OTP purposes — an OTP issued for one purpose can never be redeemed for another.
PURPOSE_LOGIN = "login"
PURPOSE_SIGNUP = "signup"
PURPOSE_RESET = "password_reset"
# Sent to the NEW address and bound to the requesting user. Never accepted by
# /verify-otp, so it cannot mint a session.
PURPOSE_EMAIL_CHANGE = "email_change"

_GENERIC_OTP_MESSAGE = "If the details are valid, a one-time code has been sent to the email address."
_INVALID_CREDENTIALS = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password"
)


# ── OTP helpers ───────────────────────────────────────────────────────────────

def generate_otp() -> str:
    """Generate a cryptographically secure 6-digit OTP."""
    return "".join(secrets.choice(string.digits) for _ in range(6))


def _hash_otp(email: str, otp: str) -> str:
    """Keyed hash of an OTP so the database never stores a usable code."""
    return hmac.new(
        settings.SECRET_KEY.encode(),
        f"{email.lower()}:{otp}".encode(),
        hashlib.sha256,
    ).hexdigest()


def _naive_utcnow() -> datetime:
    """Current UTC time as a naive datetime (MySQL DateTime columns are naive)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


async def _clear_pending_otps(
    db: AsyncSession, email: str, purpose: str, user_id: str | None = None
) -> None:
    # Email-change codes are keyed to the requesting USER, not the address: two
    # accounts may target the same new address, and one must not cancel the other's.
    scope = OTP.user_id == user_id if purpose == PURPOSE_EMAIL_CHANGE else OTP.email == email
    existing = (await db.execute(
        select(OTP).where(scope, OTP.purpose == purpose)
    )).scalars().all()
    for old in existing:
        await db.delete(old)


async def _issue_otp(
    db: AsyncSession,
    *,
    email: str,
    username: str,
    purpose: str,
    ttl_minutes: int,
    user_id: str | None = None,
    registration: dict | None = None,
) -> None:
    """Create an OTP row and email the code.

    The plaintext code is only ever held in memory and sent to the registered
    address — it is never logged and never returned in an API response.
    """
    await _clear_pending_otps(db, email, purpose, user_id)

    otp_code = generate_otp()
    record = OTP(
        user_id=user_id,
        email=email,
        otp=_hash_otp(email, otp_code),
        purpose=purpose,
        attempts=0,
        expires_at=_naive_utcnow() + timedelta(minutes=ttl_minutes),
        verified="pending",
        **(registration or {}),
    )
    db.add(record)
    await db.commit()

    # Key shape follows Resend's <event-type>/<entity-id> guidance. The OTP row id is
    # unique and stable, and `purpose` distinguishes a login code from a reset code issued
    # to the same address. Deliberately contains NO code, NO address and NO timestamp: the
    # code would leak into a header, the address is PII, and a timestamp would make the key
    # differ on retry - which is the one thing that must not happen.
    idempotency_key = f"otp/{purpose}/{record.id}"

    if not await send_otp_email(
        email,
        otp_code,
        username,
        is_password_reset=(purpose == PURPOSE_RESET),
        is_email_change=(purpose == PURPOSE_EMAIL_CHANGE),
        idempotency_key=idempotency_key,
    ):
        logger.error("otp_email_delivery_failed", purpose=purpose)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Unable to send the verification email. Please try again later.",
        )

    logger.info("otp_issued", purpose=purpose)


async def _consume_otp(
    db: AsyncSession, email: str, otp: str, purpose: str, user_id: str | None = None
) -> OTP:
    """Validate an OTP for a purpose and mark it used, or raise 401.

    ``user_id`` additionally binds the code to one account — required for
    email-change codes, whose address may be pending for more than one user.
    """
    criteria = [OTP.email == email, OTP.purpose == purpose, OTP.verified == "pending"]
    if user_id is not None:
        criteria.append(OTP.user_id == user_id)
    result = await db.execute(
        select(OTP).where(*criteria).order_by(OTP.created_at.desc())
    )
    record = result.scalars().first()
    if record is None:
        raise HTTPException(status_code=401, detail="Invalid or expired code")

    if _naive_utcnow() > record.expires_at:
        record.verified = "expired"
        await db.commit()
        raise HTTPException(status_code=401, detail="Invalid or expired code")

    if (record.attempts or 0) >= settings.OTP_MAX_ATTEMPTS:
        record.verified = "locked"
        await db.commit()
        raise HTTPException(
            status_code=429,
            detail="Too many incorrect attempts. Request a new code.",
        )

    if not hmac.compare_digest(record.otp, _hash_otp(email, otp)):
        record.attempts = (record.attempts or 0) + 1
        if record.attempts >= settings.OTP_MAX_ATTEMPTS:
            record.verified = "locked"
        await db.commit()
        raise HTTPException(status_code=401, detail="Invalid or expired code")

    record.verified = "verified"
    return record


# ── Registration / login ──────────────────────────────────────────────────────

@router.post(
    "/register",
    response_model=OTPResponse,
    status_code=201,
    dependencies=[Depends(rate_limit("register", max_requests=5))],
)
async def register_user(data: UserRegister, db: AsyncSession = Depends(get_db)):
    """Store registration data and send an OTP. The user is created after verification."""
    existing = await db.execute(
        select(User).where((User.username == data.username) | (User.email == data.email))
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Username or email already registered")

    # Self-service registration can never mint a privileged account; roles are
    # assigned by an administrator through POST /api/v1/users.
    await _issue_otp(
        db,
        email=data.email,
        username=data.username,
        purpose=PURPOSE_SIGNUP,
        ttl_minutes=settings.OTP_TTL_MINUTES,
        registration={
            "username": data.username,
            "hashed_password": pwd_context.hash(data.password),
            "full_name": data.full_name,
            "role": ROLE_VIEWER,
        },
    )

    return OTPResponse(message=_GENERIC_OTP_MESSAGE, otp_required=True)


@router.post(
    "/login",
    response_model=OTPResponse,
    dependencies=[Depends(rate_limit("login"))],
)
async def login_user(data: UserLogin, db: AsyncSession = Depends(get_db)):
    """Verify credentials and send a login OTP."""
    result = await db.execute(select(User).where(User.email == data.email))
    user = result.scalar_one_or_none()

    if user is None:
        # Burn an equivalent amount of hashing time so a missing account is not
        # distinguishable from a wrong password by response latency.
        pwd_context.dummy_verify()
        logger.info("login_failed", reason="unknown_email")
        raise _INVALID_CREDENTIALS

    # Unknown emails are rejected above with no counter and no delay (#127): delaying
    # only real accounts would rebuild the account-existence oracle from timing.
    if not await verify_password_throttled(db, user, data.password, pwd_context) \
            or not user.is_active:
        # A disabled account, a throttled account and a bad password all return the
        # same error, so the endpoint confirms neither existence nor lock state.
        logger.info("login_failed", reason="bad_password_or_disabled", user_id=str(user.id))
        raise _INVALID_CREDENTIALS

    await _issue_otp(
        db,
        email=user.email,
        username=user.username,
        purpose=PURPOSE_LOGIN,
        ttl_minutes=settings.OTP_TTL_MINUTES,
        user_id=user.id,
    )

    return OTPResponse(message=_GENERIC_OTP_MESSAGE, otp_required=True)


@router.post(
    "/verify-otp",
    response_model=TokenResponse,
    dependencies=[Depends(rate_limit("verify-otp"))],
)
async def verify_otp(data: OTPVerify, db: AsyncSession = Depends(get_db)):
    """Verify a login or signup OTP and return an access token."""
    # Resolve which flow this code belongs to from the newest pending record.
    # A password-reset code is never redeemable for a session token here.
    pending = (await db.execute(
        select(OTP)
        .where(
            OTP.email == data.email,
            OTP.purpose.in_([PURPOSE_LOGIN, PURPOSE_SIGNUP]),
            OTP.verified == "pending",
        )
        .order_by(OTP.created_at.desc())
    )).scalars().first()

    if pending is None:
        raise HTTPException(status_code=401, detail="Invalid or expired code")

    record = await _consume_otp(db, data.email, data.otp, pending.purpose)

    if record.purpose == PURPOSE_SIGNUP:
        if not all([record.username, record.hashed_password, record.email]):
            raise HTTPException(status_code=400, detail="Invalid registration data")
        user = User(
            username=record.username,
            email=record.email,
            hashed_password=record.hashed_password,
            full_name=record.full_name,
            role=record.role or ROLE_VIEWER,
            is_active=True,
        )
        db.add(user)
        await db.flush()
    else:
        result = await db.execute(select(User).where(User.id == record.user_id))
        user = result.scalar_one_or_none()
        if not user:
            raise HTTPException(status_code=401, detail="Invalid or expired code")
        # A verified OTP proves control of the mailbox — it must not re-enable an
        # account an administrator has deliberately disabled.
        if not user.is_active:
            raise HTTPException(status_code=403, detail="Account is disabled")

    user.last_login = _naive_utcnow()
    await db.commit()

    logger.info("login_succeeded", user_id=str(user.id), role=user.role)
    return TokenResponse(
        access_token=create_access_token(user),
        user=UserResponse.model_validate(user),
    )


# ── Password reset ────────────────────────────────────────────────────────────

@router.post(
    "/forgot-password",
    response_model=OTPResponse,
    dependencies=[Depends(rate_limit("forgot-password", max_requests=5))],
)
async def forgot_password(data: PasswordResetRequest, db: AsyncSession = Depends(get_db)):
    """Request a password reset code. The response never reveals whether the email exists."""
    result = await db.execute(select(User).where(User.email == data.email))
    user = result.scalar_one_or_none()

    if user and user.is_active:
        try:
            await _issue_otp(
                db,
                email=user.email,
                username=user.username,
                purpose=PURPOSE_RESET,
                ttl_minutes=settings.OTP_RESET_TTL_MINUTES,
                user_id=user.id,
            )
        except HTTPException:
            # ── FINDING C-04. DO NOT REMOVE THIS except. ──────────────────────────
            # `_issue_otp` raises 503 on delivery failure, and login and registration let
            # that reach the client. THIS endpoint must not, because the 503 would only
            # ever be raised for an address that EXISTS - an address with no account never
            # reaches `_issue_otp` at all. So a visible error here turns password reset
            # into an account-existence oracle: probe an address, and a 503 means "real
            # account, mail failed" while a 200 means "no such account".
            #
            # Swallowing it is therefore the oracle protection, not defensive tidying, and
            # the endpoint returns the same generic body either way. Making this failure
            # "helpful" reintroduces C-04.
            #
            # Note this property is INVISIBLE from utils/email_service.py: the asymmetry
            # lives here, in the caller, so a reader of the email code cannot see it.
            # Pinned by tests/test_email_service.py and the users API tests.
            logger.error("password_reset_email_failed")

    return OTPResponse(message=_GENERIC_OTP_MESSAGE, otp_required=True)


@router.post(
    "/reset-password",
    response_model=dict,
    dependencies=[Depends(rate_limit("reset-password"))],
)
async def reset_password(data: PasswordReset, db: AsyncSession = Depends(get_db)):
    """Reset a password using a password-reset OTP."""
    record = await _consume_otp(db, data.email, data.otp, PURPOSE_RESET)

    user_result = await db.execute(select(User).where(User.email == data.email))
    user = user_result.scalar_one_or_none()
    if not user or str(user.id) != str(record.user_id):
        raise HTTPException(status_code=401, detail="Invalid or expired code")

    user.hashed_password = pwd_context.hash(data.new_password)
    await db.commit()

    logger.info("password_reset_completed", user_id=str(user.id))
    return {"message": "Password reset successfully"}


# ── Current user ──────────────────────────────────────────────────────────────

@router.get("/me", response_model=UserResponse)
async def get_me(user: User = Depends(get_current_user)):
    """Get the authenticated user's profile."""
    return UserResponse.model_validate(user)


@router.put("/me", response_model=UserResponse)
async def update_me(
    data: UserUpdate,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Update the authenticated user's own profile (name only).

    Issue #123: this used to change ``email`` on the token alone, which turns a stolen
    JWT into permanent takeover via /forgot-password. ``email`` is still accepted when
    it equals the current address, because the profile form always sends it; a real
    change must go through POST /me/email and /me/email/verify.
    """
    if data.email is not None and data.email != user.email:
        raise HTTPException(
            status_code=400,
            detail="Changing your email needs your password and a code sent to the new "
                   "address. Use the Change email form.",
        )
    if data.full_name is not None:
        user.full_name = data.full_name

    await db.flush()
    return UserResponse.model_validate(user)


async def _email_in_use(db: AsyncSession, email: str, exclude_user_id: str) -> bool:
    clash = await db.execute(
        select(User).where(User.email == email, User.id != exclude_user_id)
    )
    return clash.scalars().first() is not None


async def _invalidate_pending_otps(db: AsyncSession, user_id: str, old_email: str) -> None:
    """Kill every pending code for the account once its address moves.

    A login code already mailed to the OLD address would otherwise stay redeemable at
    /verify-otp (which resolves the user from ``record.user_id``) for its whole TTL — so
    whoever holds the old mailbox keeps a way in after the owner has moved away from it.
    """
    stale = (await db.execute(
        select(OTP).where(
            OTP.verified == "pending",
            (OTP.user_id == user_id) | (OTP.email == old_email),
        )
    )).scalars().all()
    for record in stale:
        await db.delete(record)


async def _notify_email_changed(old_email: str, username: str, by_admin: bool) -> None:
    """Tell the OLD address its account moved. Best effort: never fails the request.

    This is the owner's only chance to notice a change they didn't make, so it goes
    to the address being replaced, and deliberately carries no code and no link.
    """
    who = "an administrator" if by_admin else "someone signed in to your account"
    message = (
        f"Hello {username},\n\n"
        f"The email address on your Wiestell account was just changed by {who}. "
        "Sign-in codes and password resets now go to the new address.\n\n"
        "If you did not expect this, contact your Wiestell administrator immediately.\n"
    )
    try:
        if not await send_notification_email(
            old_email, "Wiestell - Your account email was changed", message
        ):
            logger.warning("email_change_notice_failed")
    except Exception as e:  # never let a notice failure undo a verified change
        logger.warning("email_change_notice_failed", error_type=type(e).__name__)


@router.post(
    "/me/email",
    response_model=OTPResponse,
    dependencies=[Depends(rate_limit("email-change", max_requests=5))],
)
async def request_email_change(
    data: EmailChangeRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Step 1 of an email change: re-check the password, mail a code to the new address."""
    if not await verify_password_throttled(db, user, data.current_password, pwd_context):
        logger.info("email_change_rejected", reason="bad_password", user_id=str(user.id))
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    if data.new_email == user.email:
        raise HTTPException(status_code=400, detail="That is already your email address")
    if await _email_in_use(db, data.new_email, user.id):
        raise HTTPException(status_code=409, detail="Email already in use")

    await _issue_otp(
        db,
        email=data.new_email,
        username=user.username,
        purpose=PURPOSE_EMAIL_CHANGE,
        ttl_minutes=settings.OTP_RESET_TTL_MINUTES,
        user_id=user.id,
    )
    return OTPResponse(
        message="A confirmation code has been sent to the new address.", otp_required=True
    )


@router.post(
    "/me/email/verify",
    response_model=UserResponse,
    dependencies=[Depends(rate_limit("email-change-verify"))],
)
async def verify_email_change(
    data: EmailChangeVerify,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Step 2: a code proving control of the new address switches the account to it."""
    await _consume_otp(db, data.new_email, data.otp, PURPOSE_EMAIL_CHANGE, user_id=user.id)

    # Re-checked: the address may have been registered since the code was sent.
    if await _email_in_use(db, data.new_email, user.id):
        raise HTTPException(status_code=409, detail="Email already in use")

    old_email = user.email
    user.email = data.new_email
    await _invalidate_pending_otps(db, user.id, old_email)
    await db.flush()

    logger.info("email_changed", user_id=str(user.id), by_admin=False)
    await _notify_email_changed(old_email, user.username, by_admin=False)
    return UserResponse.model_validate(user)


@router.put("/me/password", response_model=dict)
async def change_password(
    data: PasswordChange,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Change the authenticated user's password."""
    if not await verify_password_throttled(db, user, data.current_password, pwd_context):
        raise HTTPException(status_code=400, detail="Current password is incorrect")

    user.hashed_password = pwd_context.hash(data.new_password)
    await db.commit()

    logger.info("password_changed", user_id=str(user.id))
    return {"message": "Password changed successfully"}


# ── Administration (admin role required) ──────────────────────────────────────

@router.get("", response_model=UserListResponse, dependencies=[Depends(require_admin)])
async def list_users(db: AsyncSession = Depends(get_db)):
    """List all users. Admin only."""
    result = await db.execute(select(User).order_by(User.created_at.desc()))
    users = result.scalars().all()
    return UserListResponse(
        items=[UserResponse.model_validate(u) for u in users],
        total=len(users),
    )


@router.post(
    "",
    response_model=UserResponse,
    status_code=201,
    dependencies=[Depends(require_admin)],
)
async def admin_create_user(data: UserRegister, db: AsyncSession = Depends(get_db)):
    """Create a user without OTP verification. Admin only."""
    existing = await db.execute(
        select(User).where((User.username == data.username) | (User.email == data.email))
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Username or email already registered")

    user = User(
        username=data.username,
        email=data.email,
        hashed_password=pwd_context.hash(data.password),
        full_name=data.full_name,
        role=data.role or ROLE_VIEWER,
        is_active=True,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return UserResponse.model_validate(user)


@router.get("/{user_id}", response_model=UserResponse, dependencies=[Depends(require_admin)])
async def get_user(user_id: str, db: AsyncSession = Depends(get_db)):
    """Get a specific user profile. Admin only."""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return UserResponse.model_validate(user)


@router.put("/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: str,
    data: AdminUserUpdate,
    actor: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Update another user's profile. Admin only.

    An email change here needs the ADMIN's current password (issue #123): without it,
    a stolen admin token could move any account's mailbox — another admin's included —
    and then reset its password, outliving the token. An admin's own address goes
    through the self-service flow, which also proves control of the new mailbox.
    """
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    old_email = None
    if data.email is not None and data.email != user.email:
        if str(user.id) == str(actor.id):
            raise HTTPException(
                status_code=400,
                detail="Change your own email from your profile, which verifies the new address.",
            )
        # Counts against the ADMIN's own back-off, so a stolen admin token cannot use
        # this route to brute-force the admin's password either.
        if not data.current_password or not await verify_password_throttled(
            db, actor, data.current_password, pwd_context
        ):
            logger.info("admin_email_change_rejected", actor_id=str(actor.id))
            raise HTTPException(
                status_code=400,
                detail="Changing a user's email requires your current password.",
            )
        if await _email_in_use(db, data.email, user.id):
            raise HTTPException(status_code=409, detail="Email already in use")
        old_email = user.email
        user.email = data.email
        await _invalidate_pending_otps(db, user.id, old_email)

    if data.full_name is not None:
        user.full_name = data.full_name

    await db.flush()
    logger.info("user_updated_by_admin", actor_id=str(actor.id), target_id=str(user.id),
                email_changed=old_email is not None)
    if old_email is not None:
        await _notify_email_changed(old_email, user.username, by_admin=True)
    return UserResponse.model_validate(user)
