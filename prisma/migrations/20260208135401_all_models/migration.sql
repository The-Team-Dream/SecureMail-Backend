-- CreateEnum
CREATE TYPE "EmailProviders" AS ENUM ('GMAIL', 'OUTLOOK', 'YAHOO', 'CUSTOM');

-- CreateEnum
CREATE TYPE "ImapAuthType" AS ENUM ('OAUTH', 'PASSWORD');

-- CreateEnum
CREATE TYPE "SmtpAuthType" AS ENUM ('OAUTH', 'PASSWORD');

-- CreateEnum
CREATE TYPE "FolderType" AS ENUM ('INBOX', 'SENT', 'SPAM', 'TRASH', 'CUSTOM');

-- CreateEnum
CREATE TYPE "RecipientType" AS ENUM ('FROM', 'TO', 'CC', 'BCC');

-- CreateEnum
CREATE TYPE "EmailFlagType" AS ENUM ('SEEN', 'FLAGGED', 'ANSWERED');

-- CreateEnum
CREATE TYPE "NotificationType" AS ENUM ('NEW_EMAIL', 'SECURITY_ALERT');

-- CreateEnum
CREATE TYPE "SyncStatus" AS ENUM ('SUCCESS', 'FAILED');

-- CreateTable
CREATE TABLE "User" (
    "id" SERIAL NOT NULL,
    "username" TEXT,
    "email" TEXT NOT NULL,
    "passwordHash" TEXT NOT NULL,
    "avatar" TEXT,
    "isVerified" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "User_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "UserSession" (
    "id" SERIAL NOT NULL,
    "userId" INTEGER NOT NULL,
    "refreshToken" TEXT NOT NULL,
    "userAgent" TEXT NOT NULL,
    "ipAddress" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "UserSession_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "UserSetting" (
    "id" SERIAL NOT NULL,
    "userId" INTEGER NOT NULL,
    "notificationsEnabled" BOOLEAN NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "UserSetting_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "EmailAccount" (
    "id" SERIAL NOT NULL,
    "userId" INTEGER NOT NULL,
    "emailAddress" TEXT NOT NULL,
    "provider" "EmailProviders" NOT NULL,
    "displayName" TEXT NOT NULL,
    "isActive" BOOLEAN NOT NULL,
    "lastSyncedAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "EmailAccount_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ImapConfig" (
    "id" SERIAL NOT NULL,
    "emailAccountId" INTEGER NOT NULL,
    "host" TEXT NOT NULL,
    "port" INTEGER NOT NULL,
    "secure" BOOLEAN NOT NULL,
    "authType" "ImapAuthType" NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ImapConfig_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "SmtpConfig" (
    "id" SERIAL NOT NULL,
    "emailAccountId" INTEGER NOT NULL,
    "host" TEXT NOT NULL,
    "port" INTEGER NOT NULL,
    "secure" TEXT NOT NULL,
    "authType" "SmtpAuthType" NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "SmtpConfig_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "OauthToken" (
    "id" SERIAL NOT NULL,
    "emailAccountId" INTEGER NOT NULL,
    "provider" TEXT NOT NULL,
    "accessTokenEncrypted" TEXT NOT NULL,
    "refreshTokenEncrypted" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "scope" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "OauthToken_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Folder" (
    "id" SERIAL NOT NULL,
    "emailAccountId" INTEGER NOT NULL,
    "name" TEXT NOT NULL,
    "type" "FolderType" NOT NULL,
    "remoteId" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Folder_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Email" (
    "id" SERIAL NOT NULL,
    "emailAccountId" INTEGER NOT NULL,
    "folderId" INTEGER NOT NULL,
    "messageId" TEXT NOT NULL,
    "subject" TEXT NOT NULL,
    "recipientType" "RecipientType"[],
    "bodyText" TEXT NOT NULL,
    "bodyHtml" TEXT NOT NULL,
    "isRead" BOOLEAN NOT NULL,
    "isFlagged" BOOLEAN NOT NULL,
    "isSpam" BOOLEAN NOT NULL,
    "receivedAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Email_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "EmailFlag" (
    "id" SERIAL NOT NULL,
    "emailId" INTEGER NOT NULL,
    "type" "EmailFlagType" NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "EmailFlag_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Attachment" (
    "id" SERIAL NOT NULL,
    "emailId" INTEGER NOT NULL,
    "mimiType" TEXT NOT NULL,
    "size" INTEGER NOT NULL,
    "storagePath" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Attachment_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Notification" (
    "id" SERIAL NOT NULL,
    "userId" INTEGER NOT NULL,
    "emailAccountId" INTEGER NOT NULL,
    "emailId" INTEGER NOT NULL,
    "type" "NotificationType" NOT NULL,
    "isRead" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Notification_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "SyncLog" (
    "id" SERIAL NOT NULL,
    "emailAccountId" INTEGER NOT NULL,
    "status" "SyncStatus" NOT NULL,
    "errorMessage" TEXT NOT NULL,
    "syncedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "SyncLog_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "User_email_key" ON "User"("email");

-- CreateIndex
CREATE UNIQUE INDEX "ImapConfig_emailAccountId_key" ON "ImapConfig"("emailAccountId");

-- CreateIndex
CREATE UNIQUE INDEX "SmtpConfig_emailAccountId_key" ON "SmtpConfig"("emailAccountId");

-- CreateIndex
CREATE UNIQUE INDEX "OauthToken_emailAccountId_key" ON "OauthToken"("emailAccountId");

-- CreateIndex
CREATE INDEX "Folder_emailAccountId_idx" ON "Folder"("emailAccountId");

-- CreateIndex
CREATE INDEX "Folder_remoteId_idx" ON "Folder"("remoteId");

-- CreateIndex
CREATE INDEX "Email_emailAccountId_idx" ON "Email"("emailAccountId");

-- CreateIndex
CREATE INDEX "Email_folderId_idx" ON "Email"("folderId");

-- CreateIndex
CREATE INDEX "Email_receivedAt_idx" ON "Email"("receivedAt");

-- CreateIndex
CREATE INDEX "Email_messageId_idx" ON "Email"("messageId");

-- CreateIndex
CREATE UNIQUE INDEX "EmailFlag_emailId_key" ON "EmailFlag"("emailId");

-- CreateIndex
CREATE INDEX "Notification_emailAccountId_idx" ON "Notification"("emailAccountId");

-- CreateIndex
CREATE INDEX "Notification_userId_idx" ON "Notification"("userId");

-- CreateIndex
CREATE INDEX "Notification_isRead_idx" ON "Notification"("isRead");

-- AddForeignKey
ALTER TABLE "UserSession" ADD CONSTRAINT "UserSession_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "UserSetting" ADD CONSTRAINT "UserSetting_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "EmailAccount" ADD CONSTRAINT "EmailAccount_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ImapConfig" ADD CONSTRAINT "ImapConfig_emailAccountId_fkey" FOREIGN KEY ("emailAccountId") REFERENCES "EmailAccount"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "SmtpConfig" ADD CONSTRAINT "SmtpConfig_emailAccountId_fkey" FOREIGN KEY ("emailAccountId") REFERENCES "EmailAccount"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "OauthToken" ADD CONSTRAINT "OauthToken_emailAccountId_fkey" FOREIGN KEY ("emailAccountId") REFERENCES "EmailAccount"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Folder" ADD CONSTRAINT "Folder_emailAccountId_fkey" FOREIGN KEY ("emailAccountId") REFERENCES "EmailAccount"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Email" ADD CONSTRAINT "Email_emailAccountId_fkey" FOREIGN KEY ("emailAccountId") REFERENCES "EmailAccount"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Email" ADD CONSTRAINT "Email_folderId_fkey" FOREIGN KEY ("folderId") REFERENCES "Folder"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "EmailFlag" ADD CONSTRAINT "EmailFlag_emailId_fkey" FOREIGN KEY ("emailId") REFERENCES "Email"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Attachment" ADD CONSTRAINT "Attachment_emailId_fkey" FOREIGN KEY ("emailId") REFERENCES "Email"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Notification" ADD CONSTRAINT "Notification_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Notification" ADD CONSTRAINT "Notification_emailAccountId_fkey" FOREIGN KEY ("emailAccountId") REFERENCES "EmailAccount"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Notification" ADD CONSTRAINT "Notification_emailId_fkey" FOREIGN KEY ("emailId") REFERENCES "Email"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "SyncLog" ADD CONSTRAINT "SyncLog_emailAccountId_fkey" FOREIGN KEY ("emailAccountId") REFERENCES "EmailAccount"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
