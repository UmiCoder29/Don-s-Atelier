-- ==============================================================================
-- PROPOSED MIGRATION 01: Add isInternal flag to custom_order_status_history
-- Description: Adds a first-class boolean column `isInternal` to track internal
--              admin notes separately from customer-visible notes.
--              Backfills existing rows containing the '[INTERNAL]' marker,
--              strips the marker from the text note, and establishes a clean schema.
-- Status: PROPOSED ONLY — DO NOT APPLY WITHOUT EXPLICIT USER APPROVAL
-- ==============================================================================

-- 1. Apply Migration
BEGIN;

-- Add isInternal column with NOT NULL and default false
ALTER TABLE "custom_order_status_history"
ADD COLUMN IF NOT EXISTS "isInternal" BOOLEAN NOT NULL DEFAULT false;

-- Create an index to support fast queries filtering by visibility
CREATE INDEX IF NOT EXISTS "custom_order_status_history_isInternal_idx"
ON "custom_order_status_history"("isInternal");

-- Backfill: Identify rows where note starts with or contains '[INTERNAL]' marker
-- Mark as internal and strip the leading '[INTERNAL] ' prefix
UPDATE "custom_order_status_history"
SET
  "isInternal" = true,
  "note" = regexp_replace("note", '^\[INTERNAL\]\s*', '')
WHERE "note" LIKE '[INTERNAL]%';

COMMIT;

-- ==============================================================================
-- CODE FILES THAT MUST CHANGE TO ADOPT THIS MIGRATION:
-- 1. prisma/schema.prisma:
--    - Add `isInternal Boolean @default(false)` to model `CustomOrderStatusHistory`.
--    - Add `@@index([isInternal])` for query efficiency.
-- 2. src/services/bespoke/bespoke-service.ts:
--    - In `adminUpdateCustomOrder()`: When creating status history with internalNotes,
--      set `isInternal: true` and write `note: input.internalNotes` directly (without '[INTERNAL]' tag).
--    - In `getCustomOrderById()` and `listCustomOrders()`: Check `h.isInternal` directly
--      instead of string matching `decryptedNote.startsWith('[INTERNAL]')`.
-- 3. prisma/rls_policies.sql:
--    - Update RLS policy `status_history_select_own_or_admin` on `custom_order_status_history`
--      to enforce `AND ("isInternal" = false OR auth.jwt() ->> 'role' = 'admin')` at the database level.
-- 4. tests/bespoke-routes.test.ts:
--    - Update test fixtures or assertions that inspect status history note visibility.
-- ==============================================================================

-- ==============================================================================
-- ROLLBACK SECTION:
-- ==============================================================================
/*
BEGIN;

-- If needed, restore the '[INTERNAL] ' prefix to any rows marked as internal
UPDATE "custom_order_status_history"
SET "note" = '[INTERNAL] ' || "note"
WHERE "isInternal" = true AND "note" NOT LIKE '[INTERNAL]%';

-- Drop the index
DROP INDEX IF EXISTS "custom_order_status_history_isInternal_idx";

-- Drop the column
ALTER TABLE "custom_order_status_history"
DROP COLUMN IF EXISTS "isInternal";

COMMIT;
*/
