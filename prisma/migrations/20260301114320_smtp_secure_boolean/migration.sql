-- AlterTable: Convert SmtpConfig.secure from String to Boolean
-- Handles existing 'true'/'false' string values
ALTER TABLE "SmtpConfig" ALTER COLUMN "secure" TYPE BOOLEAN USING (LOWER("secure") = 'true');
