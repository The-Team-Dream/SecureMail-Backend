/*
  Warnings:

  - You are about to drop the column `refreshToken` on the `UserSession` table. All the data in the column will be lost.

*/
-- AlterTable
ALTER TABLE "UserSession" DROP COLUMN "refreshToken",
ADD COLUMN     "deviceBrowser" TEXT,
ADD COLUMN     "deviceOs" TEXT,
ADD COLUMN     "loginAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP;

-- AlterTable
ALTER TABLE "UserSetting" ALTER COLUMN "updatedAt" DROP DEFAULT;

-- CreateIndex
CREATE INDEX "UserSession_userId_idx" ON "UserSession"("userId");

-- CreateIndex
CREATE INDEX "UserSession_expiresAt_idx" ON "UserSession"("expiresAt");

-- CreateIndex
CREATE INDEX "UserSetting_userId_idx" ON "UserSetting"("userId");
