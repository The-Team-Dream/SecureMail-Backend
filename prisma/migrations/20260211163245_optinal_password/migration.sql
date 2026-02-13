/*
  Warnings:

  - Made the column `provider` on table `User` required. This step will fail if there are existing NULL values in that column.

*/
-- AlterTable
ALTER TABLE "User" ALTER COLUMN "passwordHash" DROP NOT NULL,
ALTER COLUMN "provider" SET NOT NULL,
ALTER COLUMN "provider" SET DEFAULT 'local';
