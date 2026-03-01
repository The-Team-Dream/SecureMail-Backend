-- AlterEnum
ALTER TYPE "FolderType" ADD VALUE 'PHISHING';

-- AlterTable
ALTER TABLE "Email" ADD COLUMN     "from_name" TEXT,
ADD COLUMN     "in_reply_to" TEXT,
ADD COLUMN     "is_phishing" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "phishing_score" INTEGER NOT NULL DEFAULT 0,
ADD COLUMN     "references" TEXT,
ADD COLUMN     "spam_score" INTEGER NOT NULL DEFAULT 0,
ALTER COLUMN "subject" SET DEFAULT '',
ALTER COLUMN "isRead" SET DEFAULT false,
ALTER COLUMN "isFlagged" SET DEFAULT false,
ALTER COLUMN "isSpam" SET DEFAULT false;

-- AlterTable
ALTER TABLE "SmtpConfig" ADD COLUMN     "password_encrypted" TEXT;

-- DropEnum
DROP TYPE "RecipientType" CASCADE;
