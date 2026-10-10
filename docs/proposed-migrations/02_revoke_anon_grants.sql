-- ==============================================================================
-- PROPOSED MIGRATION 02: Revoke Anon & Authenticated Grants on Sensitive Tables
-- Description: Revokes table-level SELECT privileges from BOTH `anon` and
--              `authenticated` roles on all 14 sensitive application tables.
--              All client access is brokered server-side by Next.js API routes
--              using parameterized Prisma queries on the backend service connection.
--              - Tables remaining readable by anon & authenticated:
--                categories, products, product_images, product_variants (public catalog)
--              - Alters default privileges for the `postgres` role so future tables
--                in public are not automatically granted to anon or authenticated.
--              - Revokes unneeded EXECUTE privilege on public.rls_auto_enable().
--              - Enables RLS on _prisma_migrations as defense in depth.
-- Status: PROPOSED ONLY — DO NOT APPLY WITHOUT EXPLICIT USER APPROVAL
-- ==============================================================================

-- 1. Apply Migration
BEGIN;

-- ------------------------------------------------------------------------------
-- A. Revoke SELECT on the 14 sensitive tables from BOTH anon and authenticated
-- ------------------------------------------------------------------------------
REVOKE SELECT ON TABLE "profiles" FROM anon, authenticated;
REVOKE SELECT ON TABLE "addresses" FROM anon, authenticated;
REVOKE SELECT ON TABLE "orders" FROM anon, authenticated;
REVOKE SELECT ON TABLE "order_items" FROM anon, authenticated;
REVOKE SELECT ON TABLE "order_status_history" FROM anon, authenticated;
REVOKE SELECT ON TABLE "payments" FROM anon, authenticated;
REVOKE SELECT ON TABLE "carts" FROM anon, authenticated;
REVOKE SELECT ON TABLE "cart_items" FROM anon, authenticated;
REVOKE SELECT ON TABLE "custom_orders" FROM anon, authenticated;
REVOKE SELECT ON TABLE "custom_order_attachments" FROM anon, authenticated;
REVOKE SELECT ON TABLE "custom_order_status_history" FROM anon, authenticated;
REVOKE SELECT ON TABLE "measurements" FROM anon, authenticated;
REVOKE SELECT ON TABLE "audit_logs" FROM anon, authenticated;
REVOKE SELECT ON TABLE "processed_webhook_events" FROM anon, authenticated;

-- ------------------------------------------------------------------------------
-- B. Ensure catalog tables retain SELECT for public storefront browsing via RLS
-- ------------------------------------------------------------------------------
GRANT SELECT ON TABLE "categories" TO anon, authenticated;
GRANT SELECT ON TABLE "products" TO anon, authenticated;
GRANT SELECT ON TABLE "product_images" TO anon, authenticated;
GRANT SELECT ON TABLE "product_variants" TO anon, authenticated;

-- ------------------------------------------------------------------------------
-- C. Alter Default Privileges for role `postgres` in schema public
--    Ensures new tables created in public do not inherit anon/authenticated grants
-- ------------------------------------------------------------------------------
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public
REVOKE SELECT, INSERT, UPDATE, DELETE ON TABLES FROM anon, authenticated;

-- ------------------------------------------------------------------------------
-- D. Revoke unneeded EXECUTE grants on internal functions
-- ------------------------------------------------------------------------------
REVOKE EXECUTE ON FUNCTION public.rls_auto_enable() FROM PUBLIC, anon, authenticated;

-- ------------------------------------------------------------------------------
-- E. Defense-in-depth: Enable RLS on _prisma_migrations
-- ------------------------------------------------------------------------------
ALTER TABLE IF EXISTS "_prisma_migrations" ENABLE ROW LEVEL SECURITY;

COMMIT;

-- ==============================================================================
-- ROLLBACK SECTION:
-- ==============================================================================
/*
BEGIN;

-- Restore anon and authenticated SELECT grants on the 14 sensitive tables (original state was SELECT only)
GRANT SELECT ON TABLE "profiles" TO anon, authenticated;
GRANT SELECT ON TABLE "addresses" TO anon, authenticated;
GRANT SELECT ON TABLE "orders" TO anon, authenticated;
GRANT SELECT ON TABLE "order_items" TO anon, authenticated;
GRANT SELECT ON TABLE "order_status_history" TO anon, authenticated;
GRANT SELECT ON TABLE "payments" TO anon, authenticated;
GRANT SELECT ON TABLE "carts" TO anon, authenticated;
GRANT SELECT ON TABLE "cart_items" TO anon, authenticated;
GRANT SELECT ON TABLE "custom_orders" TO anon, authenticated;
GRANT SELECT ON TABLE "custom_order_attachments" TO anon, authenticated;
GRANT SELECT ON TABLE "custom_order_status_history" TO anon, authenticated;
GRANT SELECT ON TABLE "measurements" TO anon, authenticated;
GRANT SELECT ON TABLE "audit_logs" TO anon, authenticated;
GRANT SELECT ON TABLE "processed_webhook_events" TO anon, authenticated;

-- Reset default privileges for postgres role in schema public (original state had no grants to anon/authenticated)
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public
REVOKE SELECT, INSERT, UPDATE, DELETE ON TABLES FROM anon, authenticated;

-- Restore EXECUTE on rls_auto_enable
GRANT EXECUTE ON FUNCTION public.rls_auto_enable() TO PUBLIC, anon, authenticated;

-- Disable RLS on _prisma_migrations
ALTER TABLE IF EXISTS "_prisma_migrations" DISABLE ROW LEVEL SECURITY;

COMMIT;
*/
