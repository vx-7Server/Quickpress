"""Twilio Verify-based OTP send/check."""

from __future__ import annotations

from twilio.base.exceptions import TwilioRestException
from twilio.rest import Client

from app.config import get_settings


def _client() -> Client:
    settings = get_settings()
    return Client(settings.twilio_account_sid, settings.twilio_auth_token)


def send_otp_sms(phone: str) -> None:
    settings = get_settings()
    client = _client()
    client.verify.v2.services(settings.twilio_verify_service_sid).verifications.create(
        to=phone, channel="sms"
    )


def check_otp_sms(phone: str, code: str) -> bool:
    settings = get_settings()
    client = _client()
    try:
        result = client.verify.v2.services(
            settings.twilio_verify_service_sid
        ).verification_checks.create(to=phone, code=code)
    except TwilioRestException:
        return False
    return result.status == "approved"
EOF
