-- ==============================================================================
-- PROPOSED MIGRATION 04: Set Fixed search_path on public.is_admin()
-- Description: Hardens public.is_admin() against search_path hijacking
--              by setting search_path = public, pg_temp and schema-qualifying tables.
--              Retains SECURITY DEFINER, STABLE, and existing EXECUTE grants.
-- Status: PROPOSED ONLY — DO NOT APPLY WITHOUT EXPLICIT USER APPROVAL
-- ==============================================================================

-- 1. Apply Migration
CREATE OR REPLACE FUNCTION public.is_admin()
RETURNS boolean
LANGUAGE sql
SECURITY DEFINER
STABLE
SET search_path = public, pg_temp
AS $$
  SELECT COALESCE(
    (SELECT role = 'ADMIN' FROM public.profiles WHERE id = auth.uid()::text),
    false
  );
$$;

-- EXECUTE grants remain intact (PUBLIC, anon, authenticated) so catalog RLS policies can evaluate it.

-- ==============================================================================
-- ROLLBACK SECTION:
-- ==============================================================================
/*
CREATE OR REPLACE FUNCTION public.is_admin()
RETURNS boolean
LANGUAGE sql
SECURITY DEFINER
STABLE
AS $$
  SELECT COALESCE(
    (SELECT role = 'ADMIN' FROM public.profiles WHERE id = auth.uid()::text),
    false
  );
$$;
*/
