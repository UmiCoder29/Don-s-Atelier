/*
  Warnings:

  - You are about to drop the column `cardBrand` on the `payments` table. All the data in the column will be lost.
  - You are about to drop the column `cardLast4` on the `payments` table. All the data in the column will be lost.

*/
-- AlterTable
ALTER TABLE "payments" DROP COLUMN "cardBrand",
DROP COLUMN "cardLast4";
