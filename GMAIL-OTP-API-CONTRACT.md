# Gmail/Email OTP API contract

POST /api/auth/request-otp
Body: { "email": "user@gmail.com" }
Response: success/message; never return the OTP.

POST /api/auth/verify-otp
Body: { "email": "user@gmail.com", "otp": "123456" }
Response: authenticated user/session/token.

Security requirements:
1. OTP must be cryptographically random 6 digits.
2. Store only a hash of the OTP where practical.
3. Expire OTP after OTP_EXPIRES_MINUTES.
4. Enforce OTP_RESEND_SECONDS cooldown.
5. Enforce OTP_MAX_ATTEMPTS.
6. Invalidate OTP after successful verification.
7. Rate-limit request and verify endpoints.
8. Normalize email addresses.
9. Never log OTP values.
10. Keep SMTP/API credentials server-side.
