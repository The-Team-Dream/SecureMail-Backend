-- CreateEnum
CREATE TYPE "ThemeMode" AS ENUM ('LIGHT', 'DARK');

-- AlterTable: Add 2FA fields to User
ALTER TABLE "User" ADD COLUMN "totpSecret" TEXT;
ALTER TABLE "User" ADD COLUMN "totpEnabled" BOOLEAN NOT NULL DEFAULT false;

-- AlterTable: Update UserSetting with themeMode and unique userId
ALTER TABLE "UserSetting" ADD COLUMN "themeMode" "ThemeMode" NOT NULL DEFAULT 'LIGHT';
ALTER TABLE "UserSetting" ADD COLUMN "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP;
ALTER TABLE "UserSetting" ALTER COLUMN "notificationsEnabled" SET DEFAULT true;

-- CreateIndex: Ensure one UserSetting per user
CREATE UNIQUE INDEX "UserSetting_userId_key" ON "UserSetting"("userId");
