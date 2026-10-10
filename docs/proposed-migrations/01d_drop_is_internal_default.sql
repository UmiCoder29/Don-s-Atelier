-- ==============================================================================
-- PROPOSED MIGRATION 01d: Drop default value on custom_order_status_history.isInternal
-- Description: Executed after code deployment and backfill completion.
--              Drops `DEFAULT false` so that all subsequent writes MUST explicitly
--              provide `isInternal` (true for admin notes, false for customer messages).
--              Any forgotten insert fails at the database level as well as compile time.
-- Status: PROPOSED ONLY — DO NOT APPLY WITHOUT EXPLICIT USER APPROVAL
-- ==============================================================================

-- 1. Apply Migration
BEGIN;

ALTER TABLE "custom_order_status_history"
ALTER COLUMN "isInternal" DROP DEFAULT;

COMMIT;

-- ==============================================================================
-- ROLLBACK SECTION:
-- ==============================================================================
/*
BEGIN;

ALTER TABLE "custom_order_status_history"
ALTER COLUMN "isInternal" SET DEFAULT false;

COMMIT;
*/
