/**
 * Customer login adapter (frontend-local).
 *
 * The real provider flow (Firebase Phone Auth → FastAPI JWT pair) is always
 * tried first. Only if that fails do we fall back to the backend's
 * dev/staging-only test-OTP bypass (`/api/auth/phone/test-verify`), which the
 * server refuses outright (404) unless CUSTOMER_AUTH_MODE is "test" or
 * "development" and CUSTOMER_TEST_OTP is set — so this fallback is inert
 * against a production backend.
 */

import { verifyOtp as verifyRealOtp } from "@/api/customer/auth-api";
import { verifyPhoneOtpTestMode } from "@/api/core/auth-service";
import { ApiError } from "@/api/core/errors";
import type { AuthSession } from "@/shared/types";

export async function verifyCustomerOtp(phone: string, code: string): Promise<AuthSession> {
  try {
    return await verifyRealOtp(phone, code);
  } catch (cause) {
    try {
      return await verifyPhoneOtpTestMode(phone, code);
    } catch (testModeCause) {
      // Test mode disabled (404) or wrong code (401) — surface the original
      // real-flow error, since that's what a genuine user actually hit.
      if (testModeCause instanceof ApiError && testModeCause.status === 401) {
        throw testModeCause;
      }
      throw cause;
    }
  }
}
