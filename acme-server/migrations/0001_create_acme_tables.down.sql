-- Rollback migration for ACME tables
DROP TABLE IF EXISTS acme_challenges;
DROP TABLE IF EXISTS acme_orders;
DROP TABLE IF EXISTS acme_accounts;