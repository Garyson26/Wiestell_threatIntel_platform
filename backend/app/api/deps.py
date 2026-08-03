"""Shared API dependencies: authentication, authorization and rate limiting.

Every non-public endpoint resolves the caller through :func:`get_current_user`,
which validates the bearer token, loads the user and rejects disabled accounts.
Role checks are expressed with :func:`require_roles` so authorization lives on
the server instead of relying on the React route guards.
"""

from __future__ import annotations

import hmac
import uuid
from datetime import datetime, timedelta, timezone
from typing import Iterable, Optional

import jwt
from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db
from app.models.user import User
from app.utils.rate_limiter import rate_limiter

# Role hierarchy used by the platform.
ROLE_ADMIN = "admin"
ROLE_ANALYST = "analyst"
ROLE_VIEWER = "viewer"
ALL_ROLES = (ROLE_ADMIN, ROLE_ANALYST, ROLE_VIEWER)

_CREDENTIALS_ERROR = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Not authenticated",
    headers={"WWW-Authenticate": "Bearer"},
)


# ── Token helpers ─────────────────────────────────────────────────────────────

def create_access_token(user: User) -> str:
    """Issue a short-lived signed access token for a user."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user.id),
        "role": user.role or ROLE_VIEWER,
        "type": "access",
        "iat": now,
        "exp": now + timedelta(minutes=settings.JWT_EXPIRE_MINUTES),
        "jti": str(uuid.uuid4()),
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def decode_access_token(token: str) -> dict:
    """Decode and validate an access token, or raise 401."""
    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
            options={"require": ["exp", "sub"]},
        )
    except jwt.PyJWTError:
        raise _CREDENTIALS_ERROR

    if payload.get("type") != "access":
        raise _CREDENTIALS_ERROR
    return payload


def _bearer_token(request: Request) -> str:
    auth = request.headers.get("Authorization", "")
    scheme, _, token = auth.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise _CREDENTIALS_ERROR
    return token.strip()


# ── Authentication ────────────────────────────────────────────────────────────

async def get_current_user(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> User:
    """Resolve the authenticated user from the Authorization header."""
    payload = decode_access_token(_bearer_token(request))
    user_id = payload.get("sub")

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if user is None:
        raise _CREDENTIALS_ERROR
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account is disabled")
    return user


async def get_optional_user(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> Optional[User]:
    """Same as :func:`get_current_user` but returns None when no token is sent."""
    if not request.headers.get("Authorization"):
        return None
    return await get_current_user(request, db)


# ── Authorization ─────────────────────────────────────────────────────────────

def require_roles(*roles: str):
    """Dependency factory enforcing that the caller holds one of ``roles``.

    The returned callable is named ``_role_checker`` deliberately: the
    route-guard audit in ``tests/test_access_control.py`` identifies guards by
    function name, so an authorization dependency must not share a name with a
    non-authorizing one (see :func:`rate_limit`).
    """
    allowed = set(roles)

    async def _role_checker(user: User = Depends(get_current_user)) -> User:
        if (user.role or ROLE_VIEWER) not in allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires role: {', '.join(sorted(allowed))}",
            )
        return user

    return _role_checker


require_authenticated = get_current_user
require_admin = require_roles(ROLE_ADMIN)
require_analyst = require_roles(ROLE_ADMIN, ROLE_ANALYST)


async def require_admin_or_cron(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> Optional[User]:
    """Allow either an admin user or a scheduler holding the shared cron secret.

    The scheduler path is only available when ``CRON_SECRET`` is configured; an
    empty secret never matches, so an unconfigured deployment simply requires an
    admin token.
    """
    provided = request.headers.get("X-Cron-Secret", "")
    expected = settings.CRON_SECRET
    if expected and provided and hmac.compare_digest(provided, expected):
        return None

    user = await get_current_user(request, db)
    if (user.role or ROLE_VIEWER) != ROLE_ADMIN:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Requires role: admin")
    return user


# ── Rate limiting for unauthenticated endpoints ───────────────────────────────

def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def rate_limit(bucket: str, max_requests: Optional[int] = None, window_seconds: Optional[int] = None):
    """Dependency factory applying a per-IP request budget to an endpoint.

    A rate limit is **not** an authorization control. The returned callable is
    named distinctly from :func:`require_roles`'s so the route-guard audit
    cannot mistake a rate-limited public endpoint for an authenticated one.
    """
    limit = max_requests or settings.AUTH_RATE_LIMIT_MAX
    window = window_seconds or settings.AUTH_RATE_LIMIT_WINDOW

    async def _rate_limit_checker(request: Request) -> None:
        key = f"{bucket}:{_client_ip(request)}"
        if not rate_limiter.check_rate_limit(key, limit, window):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many requests. Please try again later.",
                headers={"Retry-After": str(window)},
            )

    return _rate_limit_checker


def enforce_role(user: User, *roles: Iterable[str]) -> None:
    """Imperative role check for use inside a handler body."""
    if (user.role or ROLE_VIEWER) not in set(roles):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient privileges")
