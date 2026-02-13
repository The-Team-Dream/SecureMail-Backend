-- AlterTable
ALTER TABLE "User" ADD COLUMN     "oauthAccessToken" TEXT,
ADD COLUMN     "oauthId" TEXT,
ADD COLUMN     "oauthRefreshToken" TEXT;
