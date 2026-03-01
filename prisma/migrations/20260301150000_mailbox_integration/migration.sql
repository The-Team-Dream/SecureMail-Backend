-- AlterTable MailBox: add pushNotificationsEnabled
ALTER TABLE "MailBox" ADD COLUMN IF NOT EXISTS "pushNotificationsEnabled" BOOLEAN NOT NULL DEFAULT true;

-- AlterTable ImapConfig: add passwordEncrypted
ALTER TABLE "ImapConfig" ADD COLUMN IF NOT EXISTS "passwordEncrypted" TEXT;

-- AlterTable Email: add new columns
ALTER TABLE "Email" ADD COLUMN IF NOT EXISTS "from_addr" TEXT;
ALTER TABLE "Email" ADD COLUMN IF NOT EXISTS "to_addr" JSONB;
ALTER TABLE "Email" ADD COLUMN IF NOT EXISTS "cc_addr" JSONB;
ALTER TABLE "Email" ADD COLUMN IF NOT EXISTS "bcc_addr" JSONB;

-- Migrate existing data
UPDATE "Email" SET "from_addr" = '' WHERE "from_addr" IS NULL;
UPDATE "Email" SET "to_addr" = '[]'::jsonb WHERE "to_addr" IS NULL;
ALTER TABLE "Email" ALTER COLUMN "from_addr" SET DEFAULT '';
ALTER TABLE "Email" ALTER COLUMN "from_addr" SET NOT NULL;
ALTER TABLE "Email" ALTER COLUMN "to_addr" SET NOT NULL;

-- Make bodyText and bodyHtml nullable (use DO block for conditional rename)
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'Email' AND column_name = 'bodyText') THEN
    ALTER TABLE "Email" ALTER COLUMN "bodyText" DROP NOT NULL;
    ALTER TABLE "Email" RENAME COLUMN "bodyText" TO "body_text";
  END IF;
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'Email' AND column_name = 'bodyHtml') THEN
    ALTER TABLE "Email" ALTER COLUMN "bodyHtml" DROP NOT NULL;
    ALTER TABLE "Email" RENAME COLUMN "bodyHtml" TO "body_html";
  END IF;
END $$;

-- Drop recipientType column
ALTER TABLE "Email" DROP COLUMN IF EXISTS "recipientType";

-- Add unique constraint (drop if exists first to avoid errors)
DROP INDEX IF EXISTS "Email_mailBoxId_folderId_messageId_key";
CREATE UNIQUE INDEX "Email_mailBoxId_folderId_messageId_key" ON "Email"("mailBoxId", "folderId", "messageId");

-- AlterTable Attachment
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'Attachment' AND column_name = 'mimiType') THEN
    ALTER TABLE "Attachment" RENAME COLUMN "mimiType" TO "mime_type";
  END IF;
  IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'Attachment' AND column_name = 'storagePath') THEN
    ALTER TABLE "Attachment" RENAME COLUMN "storagePath" TO "storage_path";
  END IF;
END $$;
ALTER TABLE "Attachment" ADD COLUMN IF NOT EXISTS "filename" TEXT;

-- AlterTable SyncLog
ALTER TABLE "SyncLog" ALTER COLUMN "errorMessage" DROP NOT NULL;
