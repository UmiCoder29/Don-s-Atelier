-- ==============================================================================
-- PROPOSED MIGRATION 01c: Update RLS Policy on custom_order_status_history
-- Description: Ensures customer owners can ONLY read non-internal rows (isInternal = false).
--              Admins can read all rows via is_admin().
-- Status: PROPOSED ONLY — DO NOT APPLY WITHOUT EXPLICIT USER APPROVAL
-- ==============================================================================

-- 1. Apply Migration
DROP POLICY IF EXISTS "custom_order_status_history_select_policy" ON "custom_order_status_history";

CREATE POLICY "custom_order_status_history_select_policy"
ON "custom_order_status_history"
FOR SELECT
TO anon, authenticated
USING (
  is_admin()
  OR (
    "isInternal" = false
    AND EXISTS (
      SELECT 1 FROM custom_orders co
      WHERE co.id = custom_order_status_history."customOrderId"
        AND co."profileId" = (auth.uid())::text
    )
  )
);

-- ==============================================================================
-- ROLLBACK SECTION:
-- ==============================================================================
/*
DROP POLICY IF EXISTS "custom_order_status_history_select_policy" ON "custom_order_status_history";

CREATE POLICY "custom_order_status_history_select_policy"
ON "custom_order_status_history"
FOR SELECT
TO anon, authenticated
USING (
  (EXISTS (
    SELECT 1 FROM custom_orders co
    WHERE co.id = custom_order_status_history."customOrderId"
      AND co."profileId" = (auth.uid())::text
  ))
  OR is_admin()
);
*/
