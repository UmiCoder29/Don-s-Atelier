-- AlterTable
ALTER TABLE "measurements" DROP COLUMN IF EXISTS "additionalValues",
DROP COLUMN IF EXISTS "chest",
DROP COLUMN IF EXISTS "hip",
DROP COLUMN IF EXISTS "inseam",
DROP COLUMN IF EXISTS "jacketLength",
DROP COLUMN IF EXISTS "neck",
DROP COLUMN IF EXISTS "outseam",
DROP COLUMN IF EXISTS "shoulder",
DROP COLUMN IF EXISTS "sleeve",
DROP COLUMN IF EXISTS "waist",
DROP COLUMN IF EXISTS "unit",
ADD COLUMN     "key" TEXT NOT NULL,
ADD COLUMN     "value" TEXT NOT NULL,
ADD COLUMN     "unit" TEXT NOT NULL;

-- CreateIndex
CREATE INDEX "measurements_customOrderId_key_idx" ON "measurements"("customOrderId", "key");
