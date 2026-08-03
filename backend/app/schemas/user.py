"""Pydantic schemas for User operations."""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, EmailStr, Field, field_validator

# bcrypt silently truncates anything past 72 bytes, so reject longer secrets
# outright instead of accepting a password whose tail is ignored.
MAX_PASSWORD_BYTES = 72
MIN_PASSWORD_LENGTH = 12


def _validate_password_strength(value: str) -> str:
    if len(value) < MIN_PASSWORD_LENGTH:
        raise ValueError(f"Password must be at least {MIN_PASSWORD_LENGTH} characters long")
    if len(value.encode("utf-8")) > MAX_PASSWORD_BYTES:
        raise ValueError(f"Password must be at most {MAX_PASSWORD_BYTES} bytes long")

    classes = sum([
        any(c.islower() for c in value),
        any(c.isupper() for c in value),
        any(c.isdigit() for c in value),
        any(not c.isalnum() for c in value),
    ])
    if classes < 3:
        raise ValueError(
            "Password must combine at least three of: lowercase, uppercase, digits, symbols"
        )
    return value


class UserRegister(BaseModel):
    username: str = Field(..., min_length=3, max_length=100, pattern=r"^[A-Za-z0-9._-]+$")
    email: EmailStr = Field(..., max_length=255)
    password: str = Field(..., min_length=MIN_PASSWORD_LENGTH, max_length=MAX_PASSWORD_BYTES)
    full_name: Optional[str] = Field(None, max_length=200)
    role: str = Field(default="viewer", pattern="^(admin|analyst|viewer)$")

    @field_validator("password")
    @classmethod
    def _check_password(cls, v: str) -> str:
        return _validate_password_strength(v)


class UserUpdate(BaseModel):
    full_name: Optional[str] = Field(None, max_length=200)
    email: Optional[EmailStr] = Field(None, max_length=255)


class PasswordChange(BaseModel):
    current_password: str = Field(..., min_length=1, max_length=MAX_PASSWORD_BYTES)
    new_password: str = Field(..., min_length=MIN_PASSWORD_LENGTH, max_length=MAX_PASSWORD_BYTES)

    @field_validator("new_password")
    @classmethod
    def _check_password(cls, v: str) -> str:
        return _validate_password_strength(v)


class PasswordResetRequest(BaseModel):
    email: EmailStr = Field(..., max_length=255)


class PasswordReset(BaseModel):
    email: EmailStr = Field(..., max_length=255)
    otp: str = Field(..., min_length=6, max_length=6, pattern=r"^\d{6}$")
    new_password: str = Field(..., min_length=MIN_PASSWORD_LENGTH, max_length=MAX_PASSWORD_BYTES)

    @field_validator("new_password")
    @classmethod
    def _check_password(cls, v: str) -> str:
        return _validate_password_strength(v)


class UserResponse(BaseModel):
    id: str
    username: str
    email: str
    full_name: Optional[str]
    role: str
    is_active: bool
    created_at: datetime
    last_login: Optional[datetime]

    class Config:
        from_attributes = True


class UserLogin(BaseModel):
    email: EmailStr = Field(..., max_length=255)
    password: str = Field(..., min_length=1, max_length=MAX_PASSWORD_BYTES)


class OTPVerify(BaseModel):
    email: EmailStr = Field(..., max_length=255)
    otp: str = Field(..., min_length=6, max_length=6, pattern=r"^\d{6}$")


class OTPResponse(BaseModel):
    message: str
    otp_required: bool = True


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse


class UserListResponse(BaseModel):
    items: list[UserResponse]
    total: int
