-- Ludo Baji database schema (PostgreSQL)
-- server.js/database.js also creates these tables automatically when DATABASE_URL is present.
-- This file is provided as the database reference/schema for the project.

CREATE TABLE IF NOT EXISTS app_config (key TEXT PRIMARY KEY, value JSONB NOT NULL, updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
CREATE TABLE IF NOT EXISTS admins (id BIGSERIAL PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT, role TEXT NOT NULL DEFAULT 'super_admin', active BOOLEAN NOT NULL DEFAULT TRUE, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
CREATE TABLE IF NOT EXISTS users (id BIGSERIAL PRIMARY KEY, user_code TEXT UNIQUE, email TEXT UNIQUE, phone TEXT UNIQUE, name TEXT, status TEXT NOT NULL DEFAULT 'active', otp_hash TEXT, otp_expires_at TIMESTAMPTZ, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
CREATE TABLE IF NOT EXISTS wallets (user_id BIGINT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE, gaming_balance NUMERIC(14,2) NOT NULL DEFAULT 0, winning_balance NUMERIC(14,2) NOT NULL DEFAULT 0, updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
CREATE TABLE IF NOT EXISTS transactions (id BIGSERIAL PRIMARY KEY, user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE, type TEXT NOT NULL, amount NUMERIC(14,2) NOT NULL, balance_type TEXT, reference TEXT, status TEXT NOT NULL DEFAULT 'pending', note TEXT, balance_before NUMERIC(14,2), balance_after NUMERIC(14,2), balance_change NUMERIC(14,2), created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
ALTER TABLE transactions ADD COLUMN IF NOT EXISTS balance_before NUMERIC(14,2);
ALTER TABLE transactions ADD COLUMN IF NOT EXISTS balance_after NUMERIC(14,2);
ALTER TABLE transactions ADD COLUMN IF NOT EXISTS balance_change NUMERIC(14,2);
CREATE TABLE IF NOT EXISTS deposits (id BIGSERIAL PRIMARY KEY, user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE, method TEXT NOT NULL, amount NUMERIC(14,2) NOT NULL, transaction_id TEXT, screenshot TEXT, status TEXT NOT NULL DEFAULT 'pending', reviewed_by BIGINT REFERENCES admins(id), created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), reviewed_at TIMESTAMPTZ);
CREATE UNIQUE INDEX IF NOT EXISTS uq_deposits_transaction_id ON deposits(transaction_id) WHERE transaction_id IS NOT NULL AND transaction_id <> '';
CREATE TABLE IF NOT EXISTS withdrawals (id BIGSERIAL PRIMARY KEY, user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE, method TEXT NOT NULL, account_number TEXT NOT NULL, amount NUMERIC(14,2) NOT NULL, balance_type TEXT NOT NULL DEFAULT 'winning', status TEXT NOT NULL DEFAULT 'pending', note TEXT, reviewed_by BIGINT REFERENCES admins(id), created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), reviewed_at TIMESTAMPTZ);
ALTER TABLE withdrawals ADD COLUMN IF NOT EXISTS balance_type TEXT NOT NULL DEFAULT 'winning';
ALTER TABLE withdrawals ADD COLUMN IF NOT EXISTS note TEXT;
CREATE TABLE IF NOT EXISTS matches (id BIGSERIAL PRIMARY KEY, match_code TEXT UNIQUE, title TEXT NOT NULL, entry_fee NUMERIC(14,2) NOT NULL DEFAULT 0, winning_amount NUMERIC(14,2) NOT NULL DEFAULT 0, room_id TEXT, status TEXT NOT NULL DEFAULT 'open', scheduled_at TIMESTAMPTZ, winner_user_id BIGINT REFERENCES users(id), created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
CREATE TABLE IF NOT EXISTS match_players (match_id BIGINT NOT NULL REFERENCES matches(id) ON DELETE CASCADE, user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE, slot SMALLINT NOT NULL, status TEXT NOT NULL DEFAULT 'joined', joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), PRIMARY KEY (match_id, user_id), UNIQUE (match_id, slot));
CREATE TABLE IF NOT EXISTS notifications (id BIGSERIAL PRIMARY KEY, user_id BIGINT REFERENCES users(id) ON DELETE CASCADE, title TEXT NOT NULL, message TEXT NOT NULL, read_at TIMESTAMPTZ, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
CREATE TABLE IF NOT EXISTS support_messages (id BIGSERIAL PRIMARY KEY, user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE, sender TEXT NOT NULL, message TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());

-- Feature configuration is stored in app_config for both PostgreSQL and local fallback:
-- paymentMethods, matches, banners, faqs, pages, referral, adminRoles, auditLogs, system.
CREATE TABLE IF NOT EXISTS admin_audit_logs (id BIGSERIAL PRIMARY KEY, admin_id BIGINT REFERENCES admins(id), action TEXT NOT NULL, target TEXT, detail JSONB, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
CREATE INDEX IF NOT EXISTS idx_audit_created ON admin_audit_logs(created_at DESC);

-- Phase 2 financial integrity constraints. Safe to run repeatedly.
DO $$ BEGIN ALTER TABLE wallets ADD CONSTRAINT wallets_gaming_nonnegative CHECK (gaming_balance >= 0); EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN ALTER TABLE wallets ADD CONSTRAINT wallets_winning_nonnegative CHECK (winning_balance >= 0); EXCEPTION WHEN duplicate_object THEN NULL; END $$;
DO $$ BEGIN ALTER TABLE transactions ADD CONSTRAINT transactions_amount_nonnegative CHECK (amount >= 0); EXCEPTION WHEN duplicate_object THEN NULL; END $$;
ALTER TABLE withdrawals ADD COLUMN IF NOT EXISTS balance_before NUMERIC(14,2);
ALTER TABLE withdrawals ADD COLUMN IF NOT EXISTS balance_after NUMERIC(14,2);
CREATE INDEX IF NOT EXISTS idx_transactions_reference ON transactions(reference) WHERE reference IS NOT NULL AND reference <> '';
