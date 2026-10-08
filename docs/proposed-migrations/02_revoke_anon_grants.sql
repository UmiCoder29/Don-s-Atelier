-- ==============================================================================
-- PROPOSED MIGRATION 02: Revoke Anon & Unneeded Authenticated Table Grants
-- Description: Revokes SELECT table privileges from the `anon` role on all sensitive
--              tables in the `public` schema. All application operations are brokered
--              server-side via Next.js App Router API routes using parameterized Prisma
--              queries with the backend service connection. Keeping `anon` grants on
--              sensitive tables introduces an unnecessary PostgREST attack surface.
--              Row Level Security (RLS) remains ENABLED on every table.
-- Status: PROPOSED ONLY — DO NOT APPLY WITHOUT EXPLICIT USER APPROVAL
-- ==============================================================================

-- ------------------------------------------------------------------------------
-- GRANT AUDIT & ARCHITECTURAL JUSTIFICATION:
-- 1. Sensitive Tables:
--    - `profiles`: Contains PII (email, full name, phone number, role).
--    - `addresses`: Contains customer physical home/shipping addresses.
--    - `orders`, `order_items`, `order_status_history`: Financial and customer purchase records.
--    - `payments`: Financial transaction records.
--    - `carts`, `cart_items`: Private cart sessions.
--    - `custom_orders`, `custom_order_attachments`, `custom_order_status_history`: Bespoke orders & internal notes.
--    - `measurements`: Sensitive personal body measurements.
--    - `audit_logs`: Administrative compliance audit records.
--    - `processed_webhook_events`: Idempotency tracking table.
--    -> ACTION: REVOKE ALL grants from `anon` on all of these tables.
--               REVOKE ALL grants from `authenticated` on `audit_logs`, `payments`,
--               and `processed_webhook_events` (admin/server only).
--
-- 2. Catalog Tables:
--    - `categories`, `products`, `product_images`, `product_variants`:
--    -> JUSTIFICATION: These represent the public suit collection. While read by public
--       storefront visitors, Don's Atelier serves all catalog data through Next.js
--       APIs (/api/products, /api/categories) where Prisma executes queries server-side.
--       If direct Supabase client reads are desired in the future, SELECT may remain.
--       To minimize attack surface, anon can be revoked or restricted strictly to active rows.
-- ------------------------------------------------------------------------------

-- 1. Apply Migration
BEGIN;

-- Revoke anon access on all sensitive tables
REVOKE SELECT ON TABLE "profiles" FROM anon;
REVOKE SELECT ON TABLE "addresses" FROM anon;
REVOKE SELECT ON TABLE "orders" FROM anon;
REVOKE SELECT ON TABLE "order_items" FROM anon;
REVOKE SELECT ON TABLE "order_status_history" FROM anon;
REVOKE SELECT ON TABLE "payments" FROM anon;
REVOKE SELECT ON TABLE "carts" FROM anon;
REVOKE SELECT ON TABLE "cart_items" FROM anon;
REVOKE SELECT ON TABLE "custom_orders" FROM anon;
REVOKE SELECT ON TABLE "custom_order_attachments" FROM anon;
REVOKE SELECT ON TABLE "custom_order_status_history" FROM anon;
REVOKE SELECT ON TABLE "measurements" FROM anon;
REVOKE SELECT ON TABLE "audit_logs" FROM anon;
REVOKE SELECT ON TABLE "processed_webhook_events" FROM anon;

-- Revoke authenticated access on server-only sensitive tables
REVOKE SELECT ON TABLE "audit_logs" FROM authenticated;
REVOKE SELECT ON TABLE "payments" FROM authenticated;
REVOKE SELECT ON TABLE "processed_webhook_events" FROM authenticated;

-- Ensure RLS remains strictly enabled on every public table
ALTER TABLE "profiles" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "addresses" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "orders" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "order_items" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "order_status_history" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "payments" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "carts" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "cart_items" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "custom_orders" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "custom_order_attachments" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "custom_order_status_history" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "measurements" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "audit_logs" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "processed_webhook_events" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "categories" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "products" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "product_variants" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "product_images" ENABLE ROW LEVEL SECURITY;

COMMIT;

-- ==============================================================================
-- ROLLBACK SECTION:
-- ==============================================================================
/*
BEGIN;

-- Restore anon SELECT grants
GRANT SELECT ON TABLE "profiles" TO anon;
GRANT SELECT ON TABLE "addresses" TO anon;
GRANT SELECT ON TABLE "orders" TO anon;
GRANT SELECT ON TABLE "order_items" TO anon;
GRANT SELECT ON TABLE "order_status_history" TO anon;
GRANT SELECT ON TABLE "payments" TO anon;
GRANT SELECT ON TABLE "carts" TO anon;
GRANT SELECT ON TABLE "cart_items" TO anon;
GRANT SELECT ON TABLE "custom_orders" TO anon;
GRANT SELECT ON TABLE "custom_order_attachments" TO anon;
GRANT SELECT ON TABLE "custom_order_status_history" TO anon;
GRANT SELECT ON TABLE "measurements" TO anon;
GRANT SELECT ON TABLE "audit_logs" TO anon;
GRANT SELECT ON TABLE "processed_webhook_events" TO anon;

-- Restore authenticated SELECT grants
GRANT SELECT ON TABLE "audit_logs" TO authenticated;
GRANT SELECT ON TABLE "payments" TO authenticated;
GRANT SELECT ON TABLE "processed_webhook_events" TO authenticated;

COMMIT;
*/
