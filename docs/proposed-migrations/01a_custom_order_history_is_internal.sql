-- ==============================================================================
-- PROPOSED MIGRATION 01a: Add isInternal column to custom_order_status_history
-- Description: Adds a first-class boolean column "isInternal" to track internal
--              admin notes separately from customer-visible messages.
--              Matches the exact column naming style of custom_order_status_history
--              (e.g. "customOrderId", "fromStatus", "toStatus", "changedBy").
--              - NOT NULL DEFAULT false ensures backwards compatibility with zero-downtime.
--              - NO index added (boolean column with low selectivity).
--              - NO SQL UPDATE or regexp (notes are encrypted with AES-256-GCM;
--                backfill is handled safely in application code via scripts/backfill-is-internal.ts).
-- Status: PROPOSED ONLY — DO NOT APPLY WITHOUT EXPLICIT USER APPROVAL
-- ==============================================================================

-- 1. Apply Migration
BEGIN;

ALTER TABLE "custom_order_status_history"
ADD COLUMN IF NOT EXISTS "isInternal" BOOLEAN NOT NULL DEFAULT false;

COMMIT;

-- ==============================================================================
-- ROLLBACK SECTION:
-- ==============================================================================
/*
BEGIN;

ALTER TABLE "custom_order_status_history"
DROP COLUMN IF EXISTS "isInternal";

COMMIT;
*/
