# Quickstart: SecureMail-Backend

This guide explains how to get the SecureMail-Backend up and running quickly.

## 1. Using Docker (Recommended)
This is the fastest way to start the entire backend stack including the Database (PostgreSQL) and Redis.

### Steps:
1. Ensure your `.env.docker` is configured correctly (a template is provided in the repo).
2. Run the following command:
   ```bash
   docker compose up -d
   ```
3. Monitor logs to ensure successful startup:
   ```bash
   docker compose logs backend -f
   ```

## 2. Local Development (Standard)
Use this if you want to develop and run the code directly on your machine.

### Prerequisites:
- Node.js (v22+)
- pnpm
- A running PostgreSQL and Redis instance (matching the `.env` settings)

### Steps:
1. Copy the environment variables:
   ```bash
   cp .env.example .env
   ```
2. Install dependencies:
   ```bash
   pnpm install
   ```
3. Generate Prisma Client (essential for types):
   ```bash
   npx prisma generate
   ```
4. Run the development server:
   ```bash
   pnpm run dev
   ```

## Key Configuration
- **Prisma Client**: The client is now part of `@prisma/client`. If you see errors in your editor, always run `npx prisma generate`.
- **Proto Files**: Ensure you have the `contracts/` directory at the root, as it is required for gRPC services.
- **Port**: The default API port is `3000`.
