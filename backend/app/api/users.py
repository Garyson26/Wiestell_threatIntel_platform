"""User management API endpoints."""

from datetime import datetime, timezone, timedelta
from uuid import UUID
import random
import string

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from passlib.context import CryptContext
from jose import jwt, JWTError

from app.config import settings
from app.database import get_db
from app.models.user import User
from app.models.otp import OTP
from app.schemas.user import (
    UserRegister, UserUpdate, UserLogin, UserResponse,
    TokenResponse, UserListResponse, OTPVerify, OTPResponse,
)
from app.utils.email_service import send_otp_email

router = APIRouter()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

JWT_SECRET = settings.SECRET_KEY
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_HOURS = 24


def generate_otp() -> str:
    """Generate a 6-digit OTP."""
    return ''.join(random.choices(string.digits, k=6))


def create_access_token(user_id: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRE_HOURS)
    return jwt.encode({"sub": user_id, "exp": expire}, JWT_SECRET, algorithm=JWT_ALGORITHM)


@router.post("/register", response_model=TokenResponse, status_code=201)
async def register_user(data: UserRegister, db: AsyncSession = Depends(get_db)):
    """Register a new user and return a token."""
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
        role=data.role,
    )
    db.add(user)
    await db.flush()

    token = create_access_token(str(user.id))
    return TokenResponse(
        access_token=token,
        user=UserResponse.model_validate(user),
    )


@router.post("/login", response_model=OTPResponse)
async def login_user(data: UserLogin, db: AsyncSession = Depends(get_db)):
    """Authenticate a user and send OTP."""
    result = await db.execute(
        select(User).where(User.email == data.email)
    )
    user = result.scalar_one_or_none()

    if not user or not pwd_context.verify(data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account is disabled")

    # Delete any existing OTPs for this user
    await db.execute(
        select(OTP).where(OTP.email == data.email)
    )
    existing_otps = (await db.execute(
        select(OTP).where(OTP.email == data.email)
    )).scalars().all()
    for old_otp in existing_otps:
        await db.delete(old_otp)

    # Generate and store OTP in database
    otp_code = generate_otp()
    otp_record = OTP(
        user_id=user.id,
        email=data.email,
        otp=otp_code,
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
        verified="pending"
    )
    db.add(otp_record)
    await db.commit()
    
    # Send OTP via email
    email_sent = send_otp_email(user.email, otp_code, user.username)
    
    if not email_sent:
        # If email fails, still log it for development
        print(f"⚠️ Email failed. OTP for {data.email}: {otp_code}")
        return OTPResponse(
            message=f"OTP generated but email failed. For demo: {otp_code}",
            otp_required=True
        )
    
    # Also log for development purposes
    print(f"✓ OTP sent to {user.email}: {otp_code}")
    
    return OTPResponse(
        message="OTP has been sent to your registered email address.",
        otp_required=True
    )


@router.post("/verify-otp", response_model=TokenResponse)
async def verify_otp(data: OTPVerify, db: AsyncSession = Depends(get_db)):
    """Verify OTP and return JWT token."""
    # Get OTP from database
    result = await db.execute(
        select(OTP).where(
            OTP.email == data.email,
            OTP.verified == "pending"
        ).order_by(OTP.created_at.desc())
    )
    otp_record = result.scalar_one_or_none()
    
    if not otp_record:
        raise HTTPException(status_code=401, detail="OTP not found or already used")
    
    # Check if OTP is expired
    if datetime.now(timezone.utc) > otp_record.expires_at:
        otp_record.verified = "expired"
        await db.commit()
        raise HTTPException(status_code=401, detail="OTP has expired")
    
    # Verify OTP
    if otp_record.otp != data.otp:
        raise HTTPException(status_code=401, detail="Invalid OTP")
    
    # Get user
    result = await db.execute(
        select(User).where(User.id == otp_record.user_id)
    )
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Mark OTP as verified
    otp_record.verified = "verified"
    
    # Update last login
    user.last_login = datetime.now(timezone.utc)
    await db.commit()
    
    # Generate token
    token = create_access_token(str(user.id))
    return TokenResponse(
        access_token=token,
        user=UserResponse.model_validate(user),
    )


from fastapi import Request


@router.get("/me", response_model=UserResponse)
async def get_me(request: Request, db: AsyncSession = Depends(get_db)):
    """Get current user profile from JWT token."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")

    token = auth.split(" ", 1)[1]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

    result = await db.execute(select(User).where(User.id == UUID(user_id)))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return UserResponse.model_validate(user)


@router.get("", response_model=UserListResponse)
async def list_users(db: AsyncSession = Depends(get_db)):
    """List all users."""
    result = await db.execute(select(User).order_by(User.created_at.desc()))
    users = result.scalars().all()
    return UserListResponse(
        items=[UserResponse.model_validate(u) for u in users],
        total=len(users),
    )


@router.get("/{user_id}", response_model=UserResponse)
async def get_user(user_id: UUID, db: AsyncSession = Depends(get_db)):
    """Get a specific user profile."""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return UserResponse.model_validate(user)


@router.put("/{user_id}", response_model=UserResponse)
async def update_user(user_id: UUID, data: UserUpdate, db: AsyncSession = Depends(get_db)):
    """Update user profile."""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if data.full_name is not None:
        user.full_name = data.full_name
    if data.email is not None:
        user.email = data.email

    await db.flush()
    return UserResponse.model_validate(user)
