/*
  Warnings:

  - You are about to drop the column `emailAccountId` on the `Email` table. All the data in the column will be lost.
  - You are about to drop the column `emailAccountId` on the `Folder` table. All the data in the column will be lost.
  - You are about to drop the column `emailAccountId` on the `ImapConfig` table. All the data in the column will be lost.
  - You are about to drop the column `emailAccountId` on the `Notification` table. All the data in the column will be lost.
  - You are about to drop the column `emailAccountId` on the `OauthToken` table. All the data in the column will be lost.
  - You are about to drop the column `emailAccountId` on the `SmtpConfig` table. All the data in the column will be lost.
  - You are about to drop the column `emailAccountId` on the `SyncLog` table. All the data in the column will be lost.
  - You are about to drop the `EmailAccount` table. If the table is not empty, all the data it contains will be lost.
  - A unique constraint covering the columns `[mailBoxId]` on the table `ImapConfig` will be added. If there are existing duplicate values, this will fail.
  - A unique constraint covering the columns `[mailBoxId]` on the table `OauthToken` will be added. If there are existing duplicate values, this will fail.
  - A unique constraint covering the columns `[mailBoxId]` on the table `SmtpConfig` will be added. If there are existing duplicate values, this will fail.
  - Added the required column `mailBoxId` to the `Email` table without a default value. This is not possible if the table is not empty.
  - Added the required column `mailBoxId` to the `Folder` table without a default value. This is not possible if the table is not empty.
  - Added the required column `mailBoxId` to the `ImapConfig` table without a default value. This is not possible if the table is not empty.
  - Added the required column `mailBoxId` to the `Notification` table without a default value. This is not possible if the table is not empty.
  - Added the required column `mailBoxId` to the `OauthToken` table without a default value. This is not possible if the table is not empty.
  - Added the required column `mailBoxId` to the `SmtpConfig` table without a default value. This is not possible if the table is not empty.
  - Added the required column `mailBoxId` to the `SyncLog` table without a default value. This is not possible if the table is not empty.

*/
-- DropForeignKey
ALTER TABLE "Email" DROP CONSTRAINT "Email_emailAccountId_fkey";

-- DropForeignKey
ALTER TABLE "EmailAccount" DROP CONSTRAINT "EmailAccount_userId_fkey";

-- DropForeignKey
ALTER TABLE "Folder" DROP CONSTRAINT "Folder_emailAccountId_fkey";

-- DropForeignKey
ALTER TABLE "ImapConfig" DROP CONSTRAINT "ImapConfig_emailAccountId_fkey";

-- DropForeignKey
ALTER TABLE "Notification" DROP CONSTRAINT "Notification_emailAccountId_fkey";

-- DropForeignKey
ALTER TABLE "OauthToken" DROP CONSTRAINT "OauthToken_emailAccountId_fkey";

-- DropForeignKey
ALTER TABLE "SmtpConfig" DROP CONSTRAINT "SmtpConfig_emailAccountId_fkey";

-- DropForeignKey
ALTER TABLE "SyncLog" DROP CONSTRAINT "SyncLog_emailAccountId_fkey";

-- DropIndex
DROP INDEX "Email_emailAccountId_idx";

-- DropIndex
DROP INDEX "Folder_emailAccountId_idx";

-- DropIndex
DROP INDEX "ImapConfig_emailAccountId_key";

-- DropIndex
DROP INDEX "Notification_emailAccountId_idx";

-- DropIndex
DROP INDEX "OauthToken_emailAccountId_key";

-- DropIndex
DROP INDEX "SmtpConfig_emailAccountId_key";

-- AlterTable
ALTER TABLE "Email" DROP COLUMN "emailAccountId",
ADD COLUMN     "mailBoxId" INTEGER NOT NULL;

-- AlterTable
ALTER TABLE "Folder" DROP COLUMN "emailAccountId",
ADD COLUMN     "mailBoxId" INTEGER NOT NULL;

-- AlterTable
ALTER TABLE "ImapConfig" DROP COLUMN "emailAccountId",
ADD COLUMN     "mailBoxId" INTEGER NOT NULL;

-- AlterTable
ALTER TABLE "Notification" DROP COLUMN "emailAccountId",
ADD COLUMN     "mailBoxId" INTEGER NOT NULL;

-- AlterTable
ALTER TABLE "OauthToken" DROP COLUMN "emailAccountId",
ADD COLUMN     "mailBoxId" INTEGER NOT NULL;

-- AlterTable
ALTER TABLE "SmtpConfig" DROP COLUMN "emailAccountId",
ADD COLUMN     "mailBoxId" INTEGER NOT NULL;

-- AlterTable
ALTER TABLE "SyncLog" DROP COLUMN "emailAccountId",
ADD COLUMN     "mailBoxId" INTEGER NOT NULL;

-- DropTable
DROP TABLE "EmailAccount";

-- CreateTable
CREATE TABLE "MailBox" (
    "id" SERIAL NOT NULL,
    "userId" INTEGER NOT NULL,
    "emailAddress" TEXT NOT NULL,
    "provider" "EmailProviders" NOT NULL,
    "displayName" TEXT NOT NULL,
    "isActive" BOOLEAN NOT NULL,
    "lastSyncedAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "MailBox_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "Email_mailBoxId_idx" ON "Email"("mailBoxId");

-- CreateIndex
CREATE INDEX "Folder_mailBoxId_idx" ON "Folder"("mailBoxId");

-- CreateIndex
CREATE UNIQUE INDEX "ImapConfig_mailBoxId_key" ON "ImapConfig"("mailBoxId");

-- CreateIndex
CREATE INDEX "Notification_mailBoxId_idx" ON "Notification"("mailBoxId");

-- CreateIndex
CREATE UNIQUE INDEX "OauthToken_mailBoxId_key" ON "OauthToken"("mailBoxId");

-- CreateIndex
CREATE UNIQUE INDEX "SmtpConfig_mailBoxId_key" ON "SmtpConfig"("mailBoxId");

-- AddForeignKey
ALTER TABLE "MailBox" ADD CONSTRAINT "MailBox_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ImapConfig" ADD CONSTRAINT "ImapConfig_mailBoxId_fkey" FOREIGN KEY ("mailBoxId") REFERENCES "MailBox"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "SmtpConfig" ADD CONSTRAINT "SmtpConfig_mailBoxId_fkey" FOREIGN KEY ("mailBoxId") REFERENCES "MailBox"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "OauthToken" ADD CONSTRAINT "OauthToken_mailBoxId_fkey" FOREIGN KEY ("mailBoxId") REFERENCES "MailBox"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Folder" ADD CONSTRAINT "Folder_mailBoxId_fkey" FOREIGN KEY ("mailBoxId") REFERENCES "MailBox"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Email" ADD CONSTRAINT "Email_mailBoxId_fkey" FOREIGN KEY ("mailBoxId") REFERENCES "MailBox"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Notification" ADD CONSTRAINT "Notification_mailBoxId_fkey" FOREIGN KEY ("mailBoxId") REFERENCES "MailBox"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "SyncLog" ADD CONSTRAINT "SyncLog_mailBoxId_fkey" FOREIGN KEY ("mailBoxId") REFERENCES "MailBox"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
