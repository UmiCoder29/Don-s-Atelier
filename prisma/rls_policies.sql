-- Don's Atelier - Supabase Row Level Security (RLS) Policies
-- Enforces customer isolation, public catalog visibility, and admin access control.

-- 1. Helper function for verifying ADMIN role in public.profiles
CREATE OR REPLACE FUNCTION public.is_admin()
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT COALESCE(
    (SELECT role = 'ADMIN' FROM public.profiles WHERE id = auth.uid()::text),
    false
  );
$$;

-- Grant execute to authenticated and anon roles
GRANT EXECUTE ON FUNCTION public.is_admin() TO authenticated, anon;

-- ==============================================================================
-- 1. PROFILES
-- ==============================================================================
ALTER TABLE "profiles" ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "profiles_select_own_or_admin" ON "profiles";
DROP POLICY IF EXISTS "profiles_update_own_or_admin" ON "profiles";
DROP POLICY IF EXISTS "profiles_insert_own_or_admin" ON "profiles";
DROP POLICY IF EXISTS "profiles_delete_admin" ON "profiles";

CREATE POLICY "profiles_select_own_or_admin" ON "profiles"
  FOR SELECT USING (auth.uid()::text = id OR public.is_admin());

CREATE POLICY "profiles_update_own_or_admin" ON "profiles"
  FOR UPDATE USING (auth.uid()::text = id OR public.is_admin())
  WITH CHECK (auth.uid()::text = id OR public.is_admin());

CREATE POLICY "profiles_insert_own_or_admin" ON "profiles"
  FOR INSERT WITH CHECK (auth.uid()::text = id OR public.is_admin());

CREATE POLICY "profiles_delete_admin" ON "profiles"
  FOR DELETE USING (public.is_admin());

-- ==============================================================================
-- 2. ADDRESSES
-- ==============================================================================
ALTER TABLE "addresses" ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "addresses_select_own_or_admin" ON "addresses";
DROP POLICY IF EXISTS "addresses_insert_own_or_admin" ON "addresses";
DROP POLICY IF EXISTS "addresses_update_own_or_admin" ON "addresses";
DROP POLICY IF EXISTS "addresses_delete_own_or_admin" ON "addresses";

CREATE POLICY "addresses_select_own_or_admin" ON "addresses"
  FOR SELECT USING (auth.uid()::text = "profileId" OR public.is_admin());

CREATE POLICY "addresses_insert_own_or_admin" ON "addresses"
  FOR INSERT WITH CHECK (auth.uid()::text = "profileId" OR public.is_admin());

CREATE POLICY "addresses_update_own_or_admin" ON "addresses"
  FOR UPDATE USING (auth.uid()::text = "profileId" OR public.is_admin())
  WITH CHECK (auth.uid()::text = "profileId" OR public.is_admin());

CREATE POLICY "addresses_delete_own_or_admin" ON "addresses"
  FOR DELETE USING (auth.uid()::text = "profileId" OR public.is_admin());

-- ==============================================================================
-- 3. CATEGORIES
-- ==============================================================================
ALTER TABLE "categories" ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "categories_select_public" ON "categories";
DROP POLICY IF EXISTS "categories_admin_all" ON "categories";

CREATE POLICY "categories_select_public" ON "categories"
  FOR SELECT USING (true);

CREATE POLICY "categories_admin_all" ON "categories"
  FOR ALL USING (public.is_admin()) WITH CHECK (public.is_admin());

-- ==============================================================================
-- 4. PRODUCTS
-- ==============================================================================
ALTER TABLE "products" ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "products_select_active_or_admin" ON "products";
DROP POLICY IF EXISTS "products_admin_all" ON "products";

CREATE POLICY "products_select_active_or_admin" ON "products"
  FOR SELECT USING (status = 'ACTIVE' OR public.is_admin());

CREATE POLICY "products_admin_all" ON "products"
  FOR ALL USING (public.is_admin()) WITH CHECK (public.is_admin());

-- ==============================================================================
-- 5. PRODUCT VARIANTS
-- ==============================================================================
ALTER TABLE "product_variants" ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "variants_select_active_or_admin" ON "product_variants";
DROP POLICY IF EXISTS "variants_admin_all" ON "product_variants";

CREATE POLICY "variants_select_active_or_admin" ON "product_variants"
  FOR SELECT USING (
    ((active = true) AND EXISTS (
      SELECT 1 FROM public.products p
      WHERE p.id = product_variants."productId" AND p.status = 'ACTIVE'
    ))
    OR public.is_admin()
  );

CREATE POLICY "variants_admin_all" ON "product_variants"
  FOR ALL USING (public.is_admin()) WITH CHECK (public.is_admin());

-- ==============================================================================
-- 6. PRODUCT IMAGES
-- ==============================================================================
ALTER TABLE "product_images" ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "images_select_active_or_admin" ON "product_images";
DROP POLICY IF EXISTS "images_admin_all" ON "product_images";

CREATE POLICY "images_select_active_or_admin" ON "product_images"
  FOR SELECT USING (
    EXISTS (
      SELECT 1 FROM public.products p
      WHERE p.id = product_images."productId" AND p.status = 'ACTIVE'
    )
    OR public.is_admin()
  );

CREATE POLICY "images_admin_all" ON "product_images"
  FOR ALL USING (public.is_admin()) WITH CHECK (public.is_admin());

-- ==============================================================================
-- 7. CARTS
-- ==============================================================================
ALTER TABLE "carts" ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "carts_select_own_or_admin" ON "carts";
DROP POLICY IF EXISTS "carts_insert_own_or_admin" ON "carts";
DROP POLICY IF EXISTS "carts_update_own_or_admin" ON "carts";
DROP POLICY IF EXISTS "carts_delete_own_or_admin" ON "carts";

CREATE POLICY "carts_select_own_or_admin" ON "carts"
  FOR SELECT USING (auth.uid()::text = "profileId" OR public.is_admin());

CREATE POLICY "carts_insert_own_or_admin" ON "carts"
  FOR INSERT WITH CHECK (auth.uid()::text = "profileId" OR public.is_admin());

CREATE POLICY "carts_update_own_or_admin" ON "carts"
  FOR UPDATE USING (auth.uid()::text = "profileId" OR public.is_admin())
  WITH CHECK (auth.uid()::text = "profileId" OR public.is_admin());

CREATE POLICY "carts_delete_own_or_admin" ON "carts"
  FOR DELETE USING (auth.uid()::text = "profileId" OR public.is_admin());

-- ==============================================================================
-- 8. CART ITEMS
-- ==============================================================================
ALTER TABLE "cart_items" ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "cart_items_select_own_or_admin" ON "cart_items";
DROP POLICY IF EXISTS "cart_items_insert_own_or_admin" ON "cart_items";
DROP POLICY IF EXISTS "cart_items_update_own_or_admin" ON "cart_items";
DROP POLICY IF EXISTS "cart_items_delete_own_or_admin" ON "cart_items";

CREATE POLICY "cart_items_select_own_or_admin" ON "cart_items"
  FOR SELECT USING (
    EXISTS (
      SELECT 1 FROM public.carts c
      WHERE c.id = cart_items."cartId" AND c."profileId" = auth.uid()::text
    )
    OR public.is_admin()
  );

CREATE POLICY "cart_items_insert_own_or_admin" ON "cart_items"
  FOR INSERT WITH CHECK (
    EXISTS (
      SELECT 1 FROM public.carts c
      WHERE c.id = cart_items."cartId" AND c."profileId" = auth.uid()::text
    )
    OR public.is_admin()
  );

CREATE POLICY "cart_items_update_own_or_admin" ON "cart_items"
  FOR UPDATE USING (
    EXISTS (
      SELECT 1 FROM public.carts c
      WHERE c.id = cart_items."cartId" AND c."profileId" = auth.uid()::text
    )
    OR public.is_admin()
  )
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM public.carts c
      WHERE c.id = cart_items."cartId" AND c."profileId" = auth.uid()::text
    )
    OR public.is_admin()
  );

CREATE POLICY "cart_items_delete_own_or_admin" ON "cart_items"
  FOR DELETE USING (
    EXISTS (
      SELECT 1 FROM public.carts c
      WHERE c.id = cart_items."cartId" AND c."profileId" = auth.uid()::text
    )
    OR public.is_admin()
  );

-- ==============================================================================
-- 9. ORDERS
-- ==============================================================================
ALTER TABLE "orders" ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "orders_select_own_or_admin" ON "orders";
DROP POLICY IF EXISTS "orders_insert_own_or_admin" ON "orders";
DROP POLICY IF EXISTS "orders_update_own_or_admin" ON "orders";
DROP POLICY IF EXISTS "orders_delete_admin" ON "orders";

CREATE POLICY "orders_select_own_or_admin" ON "orders"
  FOR SELECT USING (auth.uid()::text = "profileId" OR public.is_admin());

CREATE POLICY "orders_insert_own_or_admin" ON "orders"
  FOR INSERT WITH CHECK (auth.uid()::text = "profileId" OR public.is_admin());

CREATE POLICY "orders_update_own_or_admin" ON "orders"
  FOR UPDATE USING (auth.uid()::text = "profileId" OR public.is_admin())
  WITH CHECK (auth.uid()::text = "profileId" OR public.is_admin());

CREATE POLICY "orders_delete_admin" ON "orders"
  FOR DELETE USING (public.is_admin());

-- ==============================================================================
-- 10. ORDER ITEMS
-- ==============================================================================
ALTER TABLE "order_items" ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "order_items_select_own_or_admin" ON "order_items";
DROP POLICY IF EXISTS "order_items_insert_own_or_admin" ON "order_items";
DROP POLICY IF EXISTS "order_items_admin_all" ON "order_items";

CREATE POLICY "order_items_select_own_or_admin" ON "order_items"
  FOR SELECT USING (
    EXISTS (
      SELECT 1 FROM public.orders o
      WHERE o.id = order_items."orderId" AND o."profileId" = auth.uid()::text
    )
    OR public.is_admin()
  );

CREATE POLICY "order_items_insert_own_or_admin" ON "order_items"
  FOR INSERT WITH CHECK (
    EXISTS (
      SELECT 1 FROM public.orders o
      WHERE o.id = order_items."orderId" AND o."profileId" = auth.uid()::text
    )
    OR public.is_admin()
  );

CREATE POLICY "order_items_admin_all" ON "order_items"
  FOR ALL USING (public.is_admin()) WITH CHECK (public.is_admin());

-- ==============================================================================
-- 11. PAYMENTS
-- ==============================================================================
ALTER TABLE "payments" ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "payments_select_own_or_admin" ON "payments";
DROP POLICY IF EXISTS "payments_admin_all" ON "payments";

CREATE POLICY "payments_select_own_or_admin" ON "payments"
  FOR SELECT USING (
    EXISTS (
      SELECT 1 FROM public.orders o
      WHERE o.id = payments."orderId" AND o."profileId" = auth.uid()::text
    )
    OR public.is_admin()
  );

CREATE POLICY "payments_admin_all" ON "payments"
  FOR ALL USING (public.is_admin()) WITH CHECK (public.is_admin());

-- ==============================================================================
-- 12. CUSTOM ORDERS (BESPOKE)
-- ==============================================================================
ALTER TABLE "custom_orders" ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "custom_orders_select_own_or_admin" ON "custom_orders";
DROP POLICY IF EXISTS "custom_orders_insert_own_or_admin" ON "custom_orders";
DROP POLICY IF EXISTS "custom_orders_update_own_or_admin" ON "custom_orders";
DROP POLICY IF EXISTS "custom_orders_delete_admin" ON "custom_orders";

CREATE POLICY "custom_orders_select_own_or_admin" ON "custom_orders"
  FOR SELECT USING (auth.uid()::text = "profileId" OR public.is_admin());

CREATE POLICY "custom_orders_insert_own_or_admin" ON "custom_orders"
  FOR INSERT WITH CHECK (auth.uid()::text = "profileId" OR public.is_admin());

CREATE POLICY "custom_orders_update_own_or_admin" ON "custom_orders"
  FOR UPDATE USING (auth.uid()::text = "profileId" OR public.is_admin())
  WITH CHECK (auth.uid()::text = "profileId" OR public.is_admin());

CREATE POLICY "custom_orders_delete_admin" ON "custom_orders"
  FOR DELETE USING (public.is_admin());

-- ==============================================================================
-- 13. MEASUREMENTS
-- ==============================================================================
ALTER TABLE "measurements" ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "measurements_select_own_or_admin" ON "measurements";
DROP POLICY IF EXISTS "measurements_insert_own_or_admin" ON "measurements";
DROP POLICY IF EXISTS "measurements_update_own_or_admin" ON "measurements";
DROP POLICY IF EXISTS "measurements_admin_all" ON "measurements";

CREATE POLICY "measurements_select_own_or_admin" ON "measurements"
  FOR SELECT USING (
    EXISTS (
      SELECT 1 FROM public.custom_orders co
      WHERE co.id = measurements."customOrderId" AND co."profileId" = auth.uid()::text
    )
    OR public.is_admin()
  );

CREATE POLICY "measurements_insert_own_or_admin" ON "measurements"
  FOR INSERT WITH CHECK (
    EXISTS (
      SELECT 1 FROM public.custom_orders co
      WHERE co.id = measurements."customOrderId" AND co."profileId" = auth.uid()::text
    )
    OR public.is_admin()
  );

CREATE POLICY "measurements_update_own_or_admin" ON "measurements"
  FOR UPDATE USING (
    EXISTS (
      SELECT 1 FROM public.custom_orders co
      WHERE co.id = measurements."customOrderId" AND co."profileId" = auth.uid()::text
    )
    OR public.is_admin()
  )
  WITH CHECK (
    EXISTS (
      SELECT 1 FROM public.custom_orders co
      WHERE co.id = measurements."customOrderId" AND co."profileId" = auth.uid()::text
    )
    OR public.is_admin()
  );

CREATE POLICY "measurements_admin_all" ON "measurements"
  FOR ALL USING (public.is_admin()) WITH CHECK (public.is_admin());

-- ==============================================================================
-- 14. CUSTOM ORDER ATTACHMENTS
-- ==============================================================================
ALTER TABLE "custom_order_attachments" ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "custom_order_attachments_select_own_or_admin" ON "custom_order_attachments";
DROP POLICY IF EXISTS "custom_order_attachments_insert_own_or_admin" ON "custom_order_attachments";
DROP POLICY IF EXISTS "custom_order_attachments_admin_all" ON "custom_order_attachments";

CREATE POLICY "custom_order_attachments_select_own_or_admin" ON "custom_order_attachments"
  FOR SELECT USING (
    EXISTS (
      SELECT 1 FROM public.custom_orders co
      WHERE co.id = custom_order_attachments."customOrderId" AND co."profileId" = auth.uid()::text
    )
    OR public.is_admin()
  );

CREATE POLICY "custom_order_attachments_insert_own_or_admin" ON "custom_order_attachments"
  FOR INSERT WITH CHECK (
    EXISTS (
      SELECT 1 FROM public.custom_orders co
      WHERE co.id = custom_order_attachments."customOrderId" AND co."profileId" = auth.uid()::text
    )
    OR public.is_admin()
  );

CREATE POLICY "custom_order_attachments_admin_all" ON "custom_order_attachments"
  FOR ALL USING (public.is_admin()) WITH CHECK (public.is_admin());

-- ==============================================================================
-- 15. CUSTOM ORDER STATUS HISTORY
-- ==============================================================================
ALTER TABLE "custom_order_status_history" ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "status_history_select_own_or_admin" ON "custom_order_status_history";
DROP POLICY IF EXISTS "status_history_admin_all" ON "custom_order_status_history";

CREATE POLICY "status_history_select_own_or_admin" ON "custom_order_status_history"
  FOR SELECT USING (
    EXISTS (
      SELECT 1 FROM public.custom_orders co
      WHERE co.id = custom_order_status_history."customOrderId" AND co."profileId" = auth.uid()::text
    )
    OR public.is_admin()
  );

CREATE POLICY "status_history_admin_all" ON "custom_order_status_history"
  FOR ALL USING (public.is_admin()) WITH CHECK (public.is_admin());

-- ==============================================================================
-- 16. AUDIT LOGS
-- ==============================================================================
ALTER TABLE "audit_logs" ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "audit_logs_admin_select" ON "audit_logs";
DROP POLICY IF EXISTS "audit_logs_admin_manage" ON "audit_logs";

CREATE POLICY "audit_logs_admin_select" ON "audit_logs"
  FOR SELECT USING (public.is_admin());

CREATE POLICY "audit_logs_admin_manage" ON "audit_logs"
  FOR ALL USING (public.is_admin()) WITH CHECK (public.is_admin());
