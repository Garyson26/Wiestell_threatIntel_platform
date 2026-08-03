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
from app.schemas.user import (
    UserRegister, UserUpdate, UserLogin, UserResponse,
    TokenResponse, UserListResponse, OTPVerify, OTPResponse,
    PasswordChange, PasswordResetRequest, PasswordReset,
)
from app.utils.email_service import send_otp_email

logger = structlog.get_logger()

router = APIRouter()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OTP purposes — an OTP issued for one purpose can never be redeemed for another.
PURPOSE_LOGIN = "login"
PURPOSE_SIGNUP = "signup"
PURPOSE_RESET = "password_reset"

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


async def _clear_pending_otps(db: AsyncSession, email: str, purpose: str) -> None:
    existing = (await db.execute(
        select(OTP).where(OTP.email == email, OTP.purpose == purpose)
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
    await _clear_pending_otps(db, email, purpose)

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

    if not send_otp_email(email, otp_code, username, is_password_reset=(purpose == PURPOSE_RESET)):
        logger.error("otp_email_delivery_failed", purpose=purpose)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Unable to send the verification email. Please try again later.",
        )

    logger.info("otp_issued", purpose=purpose)


async def _consume_otp(db: AsyncSession, email: str, otp: str, purpose: str) -> OTP:
    """Validate an OTP for a purpose and mark it used, or raise 401."""
    result = await db.execute(
        select(OTP)
        .where(OTP.email == email, OTP.purpose == purpose, OTP.verified == "pending")
        .order_by(OTP.created_at.desc())
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

    if not pwd_context.verify(data.password, user.hashed_password) or not user.is_active:
        # A disabled account returns the same error as a bad password so the
        # endpoint does not confirm which accounts exist.
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
            # Swallow delivery failures so the endpoint stays a non-oracle.
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
    """Update the authenticated user's own profile."""
    if data.full_name is not None:
        user.full_name = data.full_name
    if data.email is not None and data.email != user.email:
        clash = await db.execute(
            select(User).where(User.email == data.email, User.id != user.id)
        )
        if clash.scalar_one_or_none():
            raise HTTPException(status_code=409, detail="Email already in use")
        user.email = data.email

    await db.commit()
    await db.refresh(user)
    return UserResponse.model_validate(user)


@router.put("/me/password", response_model=dict)
async def change_password(
    data: PasswordChange,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Change the authenticated user's password."""
    if not pwd_context.verify(data.current_password, user.hashed_password):
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
    data: UserUpdate,
    actor: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Update another user's profile. Admin only."""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if data.full_name is not None:
        user.full_name = data.full_name
    if data.email is not None and data.email != user.email:
        clash = await db.execute(
            select(User).where(User.email == data.email, User.id != user.id)
        )
        if clash.scalar_one_or_none():
            raise HTTPException(status_code=409, detail="Email already in use")
        user.email = data.email

    await db.commit()
    await db.refresh(user)
    logger.info("user_updated_by_admin", actor_id=str(actor.id), target_id=str(user.id))
    return UserResponse.model_validate(user)
