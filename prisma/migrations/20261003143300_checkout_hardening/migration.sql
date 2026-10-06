-- DropIndex: Remove global unique index on idempotencyKey alone
DROP INDEX IF EXISTS "orders_idempotencyKey_key";

-- CreateTable: Audit trail for order status transitions
CREATE TABLE "order_status_history" (
    "id" TEXT NOT NULL,
    "orderId" TEXT NOT NULL,
    "fromStatus" "OrderStatus",
    "toStatus" "OrderStatus" NOT NULL,
    "changedBy" TEXT NOT NULL,
    "note" TEXT,
    "timestamp" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "order_status_history_pkey" PRIMARY KEY ("id")
);

-- CreateTable: Deduplication store for processed payment webhook events
CREATE TABLE "processed_webhook_events" (
    "id" TEXT NOT NULL,
    "eventId" TEXT NOT NULL,
    "provider" TEXT NOT NULL DEFAULT 'mock_stripe',
    "eventType" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "processed_webhook_events_pkey" PRIMARY KEY ("id")
);

-- Indexes for performance & integrity
CREATE INDEX "order_status_history_orderId_idx" ON "order_status_history"("orderId");
CREATE INDEX "order_status_history_timestamp_idx" ON "order_status_history"("timestamp");

-- Composite unique constraint: (provider, eventId) without duplicate single-column index
CREATE UNIQUE INDEX "processed_webhook_events_provider_eventId_key" ON "processed_webhook_events"("provider", "eventId");

-- Composite unique constraint: (profileId, idempotencyKey)
CREATE UNIQUE INDEX "orders_profileId_idempotencyKey_key" ON "orders"("profileId", "idempotencyKey");

-- Foreign key with ON DELETE RESTRICT
ALTER TABLE "order_status_history" ADD CONSTRAINT "order_status_history_orderId_fkey" FOREIGN KEY ("orderId") REFERENCES "orders"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- ==============================================================================
-- ROW LEVEL SECURITY (RLS) POLICIES
-- ==============================================================================

-- 1. processed_webhook_events: Enable RLS with ZERO client policies (Server-Only Access)
ALTER TABLE "processed_webhook_events" ENABLE ROW LEVEL SECURITY;

-- 2. order_status_history: Enable RLS with SELECT-only policy for parent order owner or admin
ALTER TABLE "order_status_history" ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "order_status_history_select_own_or_admin" ON "order_status_history";

CREATE POLICY "order_status_history_select_own_or_admin" ON "order_status_history"
  FOR SELECT USING (
    EXISTS (
      SELECT 1 FROM public.orders o
      WHERE o.id = order_status_history."orderId" AND o."profileId" = auth.uid()::text
    )
    OR public.is_admin()
  );
