"""Authentication API — the seven Sprint 1 endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status

from app.config import get_settings
from app.core.deps import current_user
from app.core.firebase import revoke_refresh_tokens, verify_id_token
from app.core.security import create_access_token, create_refresh_token, decode_token
from app.db.repositories import otp_attempts, refresh_tokens, users
from app.models.auth import (
    AccountResponse,
    AuthSessionResponse,
    LogoutRequest,
    RefreshRequest,
    SendOtpRequest,
    SendOtpResponse,
    SocialLoginRequest,
    TestVerifyPhoneRequest,
    VerifyPhoneRequest,
)
from app.models.user import Role, User
from app.services.twilio_otp import check_otp_sms, send_otp_sms

router = APIRouter(prefix="/auth", tags=["auth"])


async def _issue_session(user: User) -> AuthSessionResponse:
    access_token, access_expires = create_access_token(user.id, user.role.value)
    refresh_token, token_id, refresh_expires = create_refresh_token(user.id, user.role.value)
    await refresh_tokens.store(token_id, user.id, refresh_expires)
    return AuthSessionResponse(
        token=access_token,
        refreshToken=refresh_token,
        expiresAt=access_expires.isoformat(),
        account=AccountResponse.from_user(user),
    )


async def _login_with_firebase(id_token: str, role: Role, provider: str | None = None) -> AuthSessionResponse:
    identity = verify_id_token(id_token)
    if provider and identity.get("provider") and provider not in str(identity["provider"]):
        raise HTTPException(status_code=400, detail=f"Expected a {provider} sign-in")
    try:
        user = await users.upsert_from_firebase(
            firebase_uid=identity["uid"],
            role=role,
            phone=identity.get("phone"),
            email=identity.get("email"),
            display_name=identity.get("display_name"),
            photo_url=identity.get("photo_url"),
        )
    except PermissionError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    return await _issue_session(user)


def _normalize_phone(phone: str) -> str:
    cleaned = phone.strip()
    digits = "".join(ch for ch in cleaned if ch.isdigit())
    if len(digits) == 10:
        return f"+91{digits}"
    if not cleaned.startswith("+") and digits:
        return f"+{digits}"
    return cleaned


@router.post("/phone/send-otp", response_model=SendOtpResponse)
async def send_otp(payload: SendOtpRequest) -> SendOtpResponse:
    """Sends a real OTP via Twilio Verify (falls back to Firebase client-side
    flow when Twilio isn't configured)."""
    settings = get_settings()
    phone = _normalize_phone(payload.phone)
    recent = await otp_attempts.sends_in_last_hour(phone)
    if recent >= settings.otp_max_sends_per_hour:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many OTP requests. Please try again later.",
        )
    await otp_attempts.record(phone, payload.role)
    existing = await users.by_phone(phone, payload.role)

    if settings.twilio_configured:
        try:
            send_otp_sms(phone)
        except Exception as exc:
            raise HTTPException(status_code=500, detail="Failed to send OTP") from exc

    return SendOtpResponse(
        expiresInSeconds=settings.otp_ttl_seconds,
        isNewAccount=existing is None,
    )


@router.post("/phone/verify", response_model=AuthSessionResponse)
async def verify_phone(payload: VerifyPhoneRequest) -> AuthSessionResponse:
    return await _login_with_firebase(payload.id_token, payload.role, provider="phone")


@router.post("/phone/verify-otp", response_model=AuthSessionResponse)
async def verify_otp_twilio(payload: TestVerifyPhoneRequest) -> AuthSessionResponse:
    """Verifies the Twilio Verify OTP and issues a session."""
    settings = get_settings()
    if not settings.twilio_configured:
        raise HTTPException(status_code=503, detail="OTP verification not configured")

    phone = _normalize_phone(payload.phone)
    ok = check_otp_sms(phone, payload.otp.strip())
    if not ok:
        raise HTTPException(status_code=401, detail="Invalid or expired code")

    fake_uid = f"phone:{payload.role.value}:{phone}"
    user = await users.upsert_from_firebase(
        firebase_uid=fake_uid,
        role=payload.role,
        phone=phone,
        email=None,
        display_name=None,
        photo_url=None,
    )
    return await _issue_session(user)


@router.post("/phone/test-verify", response_model=AuthSessionResponse)
async def test_verify_phone(payload: TestVerifyPhoneRequest) -> AuthSessionResponse:
    """Dev/staging-only: accepts one fixed OTP for any phone number, no Firebase.

    404s (not 403) when disabled, so it's indistinguishable from a route that
    doesn't exist at all on a production deploy.
    """
    settings = get_settings()
    if not settings.test_otp_enabled:
        raise HTTPException(status_code=404, detail="Not found")
    if payload.otp.strip() != settings.customer_test_otp.strip():
        raise HTTPException(status_code=401, detail="Invalid code")

    phone = _normalize_phone(payload.phone)
    fake_uid = f"test:{payload.role.value}:{phone}"
    user = await users.upsert_from_firebase(
        firebase_uid=fake_uid,
        role=payload.role,
        phone=phone,
        email=None,
        display_name=None,
        photo_url=None,
    )
    return await _issue_session(user)


@router.post("/google", response_model=AuthSessionResponse)
async def google_login(payload: SocialLoginRequest) -> AuthSessionResponse:
    return await _login_with_firebase(payload.id_token, payload.role, provider="google")


@router.post("/apple", response_model=AuthSessionResponse)
async def apple_login(payload: SocialLoginRequest) -> AuthSessionResponse:
    return await _login_with_firebase(payload.id_token, payload.role, provider="apple")


@router.get("/me", response_model=AccountResponse)
async def me(user: User = Depends(current_user)) -> AccountResponse:
    return AccountResponse.from_user(user)


@router.post("/refresh", response_model=AuthSessionResponse)
async def refresh(payload: RefreshRequest) -> AuthSessionResponse:
    claims = decode_token(payload.refresh_token, expected_type="refresh")
    token_id = str(claims.get("jti"))
    if not await refresh_tokens.is_active(token_id):
        raise HTTPException(status_code=401, detail="Refresh token revoked")
    user = await users.by_id(str(claims.get("sub")))
    if user is None:
        raise HTTPException(status_code=401, detail="Unauthorized")
    await refresh_tokens.revoke(token_id)  # rotation: one use per refresh token
    return await _issue_session(user)


@router.post("/logout")
async def logout(payload: LogoutRequest, user: User = Depends(current_user)) -> dict:
    if payload.refresh_token:
        try:
            claims = decode_token(payload.refresh_token, expected_type="refresh")
            await refresh_tokens.revoke(str(claims.get("jti")))
        except HTTPException:
            pass
    await refresh_tokens.revoke_all_for_user(user.id)
    revoke_refresh_tokens(user.firebase_uid)
    return {"ok": True}
EOF
