/*
  Warnings:

  - The values [NEW_EMAIL,SECURITY_ALERT] on the enum `NotificationType` will be removed. If these variants are still used in the database, this will fail.
  - Added the required column `message` to the `Notification` table without a default value. This is not possible if the table is not empty.
  - Added the required column `title` to the `Notification` table without a default value. This is not possible if the table is not empty.

*/
-- CreateEnum
CREATE TYPE "Role" AS ENUM ('USER', 'ADMIN');

-- CreateEnum
CREATE TYPE "AuditTargetType" AS ENUM ('USER', 'MAILBOX', 'EMAIL', 'NOTIFICATION');

-- AlterEnum
BEGIN;
CREATE TYPE "NotificationType_new" AS ENUM ('NEW_LOGIN_DETECTED', 'LOW_MAILBOX_SPACE', 'PASSWORD_CHANGED', 'WEEKLY_SECURITY_REPORT', 'NEW_EMAIL_RECEIVED', 'PHISHING_DETECTED');
ALTER TABLE "Notification" ALTER COLUMN "type" TYPE "NotificationType_new" USING ("type"::text::"NotificationType_new");
ALTER TYPE "NotificationType" RENAME TO "NotificationType_old";
ALTER TYPE "NotificationType_new" RENAME TO "NotificationType";
DROP TYPE "public"."NotificationType_old";
COMMIT;

-- DropForeignKey
ALTER TABLE "Attachment" DROP CONSTRAINT "Attachment_emailId_fkey";

-- DropForeignKey
ALTER TABLE "Email" DROP CONSTRAINT "Email_folderId_fkey";

-- DropForeignKey
ALTER TABLE "Email" DROP CONSTRAINT "Email_mailBoxId_fkey";

-- DropForeignKey
ALTER TABLE "EmailFlag" DROP CONSTRAINT "EmailFlag_emailId_fkey";

-- DropForeignKey
ALTER TABLE "Folder" DROP CONSTRAINT "Folder_mailBoxId_fkey";

-- DropForeignKey
ALTER TABLE "ImapConfig" DROP CONSTRAINT "ImapConfig_mailBoxId_fkey";

-- DropForeignKey
ALTER TABLE "MailBox" DROP CONSTRAINT "MailBox_userId_fkey";

-- DropForeignKey
ALTER TABLE "Notification" DROP CONSTRAINT "Notification_emailId_fkey";

-- DropForeignKey
ALTER TABLE "Notification" DROP CONSTRAINT "Notification_mailBoxId_fkey";

-- DropForeignKey
ALTER TABLE "Notification" DROP CONSTRAINT "Notification_userId_fkey";

-- DropForeignKey
ALTER TABLE "OauthToken" DROP CONSTRAINT "OauthToken_mailBoxId_fkey";

-- DropForeignKey
ALTER TABLE "SmtpConfig" DROP CONSTRAINT "SmtpConfig_mailBoxId_fkey";

-- DropForeignKey
ALTER TABLE "SyncLog" DROP CONSTRAINT "SyncLog_mailBoxId_fkey";

-- DropForeignKey
ALTER TABLE "UserSession" DROP CONSTRAINT "UserSession_userId_fkey";

-- DropForeignKey
ALTER TABLE "UserSetting" DROP CONSTRAINT "UserSetting_userId_fkey";

-- AlterTable
ALTER TABLE "Email" ALTER COLUMN "from_addr" DROP DEFAULT;

-- AlterTable
ALTER TABLE "Notification" ADD COLUMN     "message" TEXT NOT NULL,
ADD COLUMN     "metadata" JSONB,
ADD COLUMN     "title" TEXT NOT NULL,
ALTER COLUMN "emailId" DROP NOT NULL,
ALTER COLUMN "mailBoxId" DROP NOT NULL;

-- AlterTable
ALTER TABLE "User" ADD COLUMN     "bannedAt" TIMESTAMP(3),
ADD COLUMN     "deletedAt" TIMESTAMP(3),
ADD COLUMN     "role" "Role" NOT NULL DEFAULT 'USER';

-- CreateTable
CREATE TABLE "AuditLog" (
    "id" SERIAL NOT NULL,
    "adminId" INTEGER NOT NULL,
    "action" TEXT NOT NULL,
    "targetType" "AuditTargetType" NOT NULL,
    "targetId" INTEGER,
    "details" JSONB,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AuditLog_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "AuditLog_adminId_idx" ON "AuditLog"("adminId");

-- CreateIndex
CREATE INDEX "AuditLog_action_idx" ON "AuditLog"("action");

-- CreateIndex
CREATE INDEX "AuditLog_targetType_idx" ON "AuditLog"("targetType");

-- CreateIndex
CREATE INDEX "AuditLog_createdAt_idx" ON "AuditLog"("createdAt");

-- CreateIndex
CREATE INDEX "Notification_createdAt_idx" ON "Notification"("createdAt");

-- CreateIndex
CREATE INDEX "User_deletedAt_idx" ON "User"("deletedAt");

-- CreateIndex
CREATE INDEX "User_bannedAt_idx" ON "User"("bannedAt");

-- AddForeignKey
ALTER TABLE "UserSession" ADD CONSTRAINT "UserSession_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "UserSetting" ADD CONSTRAINT "UserSetting_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "MailBox" ADD CONSTRAINT "MailBox_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ImapConfig" ADD CONSTRAINT "ImapConfig_mailBoxId_fkey" FOREIGN KEY ("mailBoxId") REFERENCES "MailBox"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "SmtpConfig" ADD CONSTRAINT "SmtpConfig_mailBoxId_fkey" FOREIGN KEY ("mailBoxId") REFERENCES "MailBox"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "OauthToken" ADD CONSTRAINT "OauthToken_mailBoxId_fkey" FOREIGN KEY ("mailBoxId") REFERENCES "MailBox"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Folder" ADD CONSTRAINT "Folder_mailBoxId_fkey" FOREIGN KEY ("mailBoxId") REFERENCES "MailBox"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Email" ADD CONSTRAINT "Email_mailBoxId_fkey" FOREIGN KEY ("mailBoxId") REFERENCES "MailBox"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Email" ADD CONSTRAINT "Email_folderId_fkey" FOREIGN KEY ("folderId") REFERENCES "Folder"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "EmailFlag" ADD CONSTRAINT "EmailFlag_emailId_fkey" FOREIGN KEY ("emailId") REFERENCES "Email"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Attachment" ADD CONSTRAINT "Attachment_emailId_fkey" FOREIGN KEY ("emailId") REFERENCES "Email"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Notification" ADD CONSTRAINT "Notification_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Notification" ADD CONSTRAINT "Notification_mailBoxId_fkey" FOREIGN KEY ("mailBoxId") REFERENCES "MailBox"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Notification" ADD CONSTRAINT "Notification_emailId_fkey" FOREIGN KEY ("emailId") REFERENCES "Email"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "SyncLog" ADD CONSTRAINT "SyncLog_mailBoxId_fkey" FOREIGN KEY ("mailBoxId") REFERENCES "MailBox"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AuditLog" ADD CONSTRAINT "AuditLog_adminId_fkey" FOREIGN KEY ("adminId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
