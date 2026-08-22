"""Environment-driven settings. Nothing is hardcoded."""

import logging
from functools import lru_cache
from typing import List

from pydantic_settings import BaseSettings, SettingsConfigDict

_log = logging.getLogger(__name__)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # --- environment -------------------------------------------------
    app_env: str = "development"  # development | staging | production
    api_prefix: str = "/api"
    cors_origins: str = "http://localhost:8081,http://localhost:8082,http://localhost:8083,http://localhost:8084"

    # --- MongoDB Atlas ------------------------------------------------
    mongodb_uri: str = ""            # mongodb+srv://... (empty => in-memory preview store)
    mongodb_db_name: str = "quickpress"

    # --- Firebase Admin ----------------------------------------------
    firebase_project_id: str = ""
    firebase_credentials_file: str = ""
    firebase_credentials_json: str = ""

    # --- JWT ----------------------------------------------------------
    jwt_secret: str = ""
    jwt_refresh_secret: str = ""
    jwt_algorithm: str = "HS256"
    access_token_ttl_minutes: int = 30
    refresh_token_ttl_days: int = 30

    # --- Cloudinary ------------------------------------------------------
    cloudinary_cloud_name: str = ""
    cloudinary_api_key: str = ""
    cloudinary_api_secret: str = ""

    # --- OTP ------------------------------------------------------------
    otp_ttl_seconds: int = 60
    otp_max_sends_per_hour: int = 50

    # --- Twilio Verify (phone OTP) ---------------------------------------
    twilio_account_sid: str = ""
    twilio_auth_token: str = ""
    twilio_verify_service_sid: str = ""

    # --- Test-mode phone login (dev/staging only, never in production) ----
    customer_auth_mode: str = "production"
    customer_test_otp: str = ""

    # --- Razorpay (Phase 5 - Sprint 5.6) ---------------------------------
    razorpay_key_id: str = ""
    razorpay_key_secret: str = ""
    razorpay_webhook_secret: str = ""

    # --- Google Maps Platform --------------------------------------------
    google_maps_server_api_key: str = ""
    google_api_key: str = ""
    google_maps_api_key: str = ""
    delivery_radius_km: float = 8.0

    @property
    def cors_origin_list(self) -> List[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]

    @property
    def use_in_memory_db(self) -> bool:
        return not self.mongodb_uri.strip()

    @property
    def refresh_secret(self) -> str:
        return self.jwt_refresh_secret.strip() or self.jwt_secret

    @property
    def cloudinary_configured(self) -> bool:
        return bool(
            self.cloudinary_cloud_name.strip()
            and self.cloudinary_api_key.strip()
            and self.cloudinary_api_secret.strip()
        )

    @property
    def maps_server_key(self) -> str:
        return self.google_maps_server_api_key.strip() or self.google_api_key.strip()

    @property
    def google_maps_configured(self) -> bool:
        return bool(self.maps_server_key)

    @property
    def razorpay_configured(self) -> bool:
        return bool(self.razorpay_key_id.strip() and self.razorpay_key_secret.strip())

    @property
    def firebase_configured(self) -> bool:
        return bool(self.firebase_credentials_file.strip() or self.firebase_credentials_json.strip())

    @property
    def twilio_configured(self) -> bool:
        return bool(
            self.twilio_account_sid.strip()
            and self.twilio_auth_token.strip()
            and self.twilio_verify_service_sid.strip()
        )

    @property
    def test_otp_enabled(self) -> bool:
        if self.app_env == "production":
            return False
        return self.customer_auth_mode.strip().lower() in ("test", "development") and bool(
            self.customer_test_otp.strip()
        )


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    if settings.app_env == "production":
        missing = []
        if not settings.jwt_secret.strip():
            missing.append("JWT_SECRET")
        if not settings.mongodb_uri.strip():
            missing.append("MONGODB_URI")
        if not settings.mongodb_db_name.strip():
            missing.append("MONGODB_DB_NAME")
        origins = settings.cors_origin_list
        if not origins or any(
            o == "*" or "localhost" in o or "127.0.0.1" in o for o in origins
        ):
            missing.append("CORS_ORIGINS (explicit https frontend origins)")
        if missing:
            _log.warning(
                "QUICKPRESS PRODUCTION CONFIG WARNING - missing/invalid env vars: %s  "
                "Fix these in the Render dashboard - Environment tab.",
                ", ".join(missing),
            )
    return settings
