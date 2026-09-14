Ludo Baji Admin Panel V9
Render: Build Command = npm install; Start Command = npm start
Admin: /admin

SECURE ADMIN CONFIGURATION
Set these environment variables before starting the server:
ADMIN_USERNAME=<your admin username>
ADMIN_PASSWORD=<your secure unique admin password>
ADMIN_SECRET=<long random secret, 32+ characters>
USER_SECRET=<different long random secret, 32+ characters>
ADMIN_ROLE=super_admin

The admin password and token secret are NOT stored in the source code.
Admin sidebar stays separate from homepage options. Main page only reads mainOptions from /api/site.

Step 5 - Deposit System:
- bKash: 01301470686 (configurable with BKASH_NUMBER)
- Nagad: 01806097369 (configurable with NAGAD_NUMBER)
- User submits amount, Transaction ID and payment screenshot.
- Admin can approve/reject deposits from Deposit Management.
- Approved deposits add to Gaming Balance; duplicate Transaction IDs are blocked.
- OTP/login, existing homepage and admin settings are preserved.

Step 1 - Withdrawal System:
- User can request withdrawal through bKash or Nagad.
- User selects Gaming Balance or Winning Balance.
- Amount is validated (default minimum ৳100, maximum ৳1,000,000; configurable with MIN_WITHDRAWAL and MAX_WITHDRAWAL).
- Balance is reserved/deducted when the request is submitted.
- Withdrawal remains Pending until Admin review.
- Admin can Approve or Reject with an optional note/reason.
- Rejected withdrawals automatically return the amount to the selected balance.
- Withdrawal history is available to the user and admin.
- Withdrawal transactions and notifications are recorded.

STEPS 3-35 COMPLETE
- Payment Method Management: bKash/Nagad settings, enable/disable, limits, instructions.
- Match lifecycle: create, list, schedule, join, My Matches, room ID/password, cancel/refund, result and prize approval.
- Wallet: entry fee, refund, prize credit and transaction records.
- User: management, block/unblock, gaming/winning balance adjustment.
- Notifications, referral display and customer support messaging.
- Admin: reports, audit log, roles/permissions configuration, banners, FAQ, rules/terms/pages, notices and system configuration.
- Existing Step 1 Withdrawal and Step 2 Wallet Statement features are preserved.

Production environment recommendations:
- Set DATABASE_URL for PostgreSQL.
- Set ADMIN_USERNAME, strong ADMIN_PASSWORD, ADMIN_SECRET, and a DIFFERENT USER_SECRET before starting. The server refuses to start when required secrets are missing/unsafe.
- Admin login is rate-limited, tokens expire, and logout revokes the active token.
- All /api/admin/* endpoints require authenticated admin access and role permissions.
- Configure TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN and TWILIO_FROM for real OTP SMS.
- Keep OTP_DEV_MODE disabled in production.
- Configure BKASH_NUMBER and NAGAD_NUMBER or update Payment Methods from Admin.


Payment Deposit UI:
- Deposit methods: bKash Personal, bKash Merchant, Nagad Personal.
- Current defaults: bKash Personal 01301470686, bKash Merchant 01301470686, Nagad Personal 01806097369.
- User can tap a method and copy its number; successful copy shows ✓ Copied.
- Admin > Payment Methods can customize method name, number, account name, logo, min/max deposit and instructions.
- Optional environment overrides: BKASH_PERSONAL_NUMBER, BKASH_MERCHANT_NUMBER, NAGAD_PERSONAL_NUMBER.


Phone Push Notification
- The Ludo Match feature sends the Room Code to both joined users when the second player joins.
- Phone push VAPID keys are generated and stored server-side automatically; optional VAPID_* environment variables can override them.
- The browser/PWA must be granted notification permission.
- package.json includes web-push; Render/npm install will install it during deployment.
