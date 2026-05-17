/*
  Warnings:

  - The values [YAHOO] on the enum `EmailProviders` will be removed. If these variants are still used in the database, this will fail.

*/
-- CreateEnum
CREATE TYPE "AnalysisStatus" AS ENUM ('PENDING', 'COMPLETED', 'FAILED');

-- AlterEnum
BEGIN;
CREATE TYPE "EmailProviders_new" AS ENUM ('GMAIL', 'OUTLOOK', 'CUSTOM');
ALTER TABLE "MailBox" ALTER COLUMN "provider" TYPE "EmailProviders_new" USING ("provider"::text::"EmailProviders_new");
ALTER TYPE "EmailProviders" RENAME TO "EmailProviders_old";
ALTER TYPE "EmailProviders_new" RENAME TO "EmailProviders";
DROP TYPE "public"."EmailProviders_old";
COMMIT;

-- AlterEnum
ALTER TYPE "NotificationType" ADD VALUE 'FAILED_SYNC';

-- AlterTable
ALTER TABLE "Email" ADD COLUMN     "analysis_status" "AnalysisStatus" NOT NULL DEFAULT 'PENDING';

-- CreateIndex
CREATE INDEX "SyncLog_status_idx" ON "SyncLog"("status");

-- CreateIndex
CREATE INDEX "SyncLog_syncedAt_idx" ON "SyncLog"("syncedAt");
