# SecureMail Backend

NestJS REST API for SecureMail: authentication, mailboxes, email operations, security pipeline, notifications, admin, and OpenAPI (Swagger) documentation.

## Tech stack

- **Runtime:** Node.js 20+
- **Framework:** NestJS 11
- **Database:** PostgreSQL (Prisma)
- **Cache / queues:** Redis (BullMQ, throttling, etc.)
- **API docs:** `@nestjs/swagger` — UI at `/api/docs`, JSON at `/api/docs-json`
- **Internal:** gRPC client to **SecureMail-Ai** (`contracts/ai-agent.proto`)

## Ports

| Environment | Port | Notes |
|-------------|------|--------|
| Local / Docker | `3000` (default) | Override with `PORT` |

## API documentation (Swagger / OpenAPI)

| Resource | URL (local default) |
|----------|---------------------|
| **Swagger UI** | http://localhost:3000/api/docs |
| **OpenAPI JSON** | http://localhost:3000/api/docs-json |

**For frontend & Flutter teams**

1. Download or fetch: `curl -s http://localhost:3000/api/docs-json -o openapi.json`
2. Run your codegen (e.g. openapi-typescript, orval, openapi_generator for Dart).
3. All successful responses use the global wrapper `{ success: true, message, data }`; errors match the documented error schema in Swagger.

## Environment variables (common)

| Variable | Purpose |
|----------|---------|
| `PORT` | HTTP port (default `3000`) |
| `DATABASE_URL` | PostgreSQL connection string |
| `REDIS_HOST` / `REDIS_PORT` | Redis |
| `JWT_SECRET` | **Required** for JWT signing |
| `FRONTEND_URL` | CORS origin (e.g. `http://localhost:3001`) |
| `PUBLIC_API_URL` | Shown as server URL in OpenAPI (optional) |
| `AI_AGENT_GRPC_URL` | AI gRPC address (e.g. `localhost:50051` or `ai:50051`) |
| `MALWARE_GRPC_URL` | Malware gRPC address (e.g. `localhost:50052` or `malware:50052`) |

Copy from your team’s `.env.example` if present; for Docker stack see repo root `.env.docker.example`.

## Run locally (step-by-step)

**Prerequisites:** Node 20+, pnpm, PostgreSQL, Redis, and (for full security features) **SecureMail-Ai** running on gRPC.

1. Install dependencies:
   ```bash
   pnpm install
   ```
2. Ensure repo root contains `contracts/ai-agent.proto` (used at build/runtime).
3. Set `DATABASE_URL`, `JWT_SECRET`, `REDIS_*`, `AI_AGENT_GRPC_URL` in `.env`.
4. Apply migrations:
   ```bash
   pnpm exec prisma migrate deploy
   ```
5. Start dev server:
   ```bash
   pnpm run start:dev
   ```
6. Open **http://localhost:3000/api/docs**

## Run with Docker

Images are built from the **monorepo root** (not from this folder alone):

```bash
cd ..
docker compose up --build backend
```

Or start the full stack: see root [README.md](../README.md).

The backend image runs `prisma migrate deploy` on startup, then `node dist/main.js`.

## API surface (high level)

REST routes are grouped in Swagger by tags, for example:

- `auth` — register, login, 2FA, OAuth callbacks, password reset  
- `user`, `user-settings` — profile and settings  
- `mailboxes`, `Emails` — mailbox connect and email CRUD / send  
- `notifications`, `sessions`, `analytics`  
- `admin/*` — admin-only (JWT + role)  
- `security-test` — dev/test pipeline endpoints (if module enabled)  
- `health` — root `/` liveness

**Authoritative list:** always use **Swagger UI** or **`/api/docs-json`**.

## Troubleshooting

| Issue | What to check |
|-------|----------------|
| `contracts/ai-agent.proto not found` | Run from `SecureMail-Backend` with monorepo `contracts/` present, or use Docker image that copies `contracts/` into `/app/contracts`. |
| Build fails `prebuild` | `scripts/assert-contracts.cjs` must find the shared proto (monorepo or `/app/contracts`). |
| AI timeouts / empty AI report | Is **SecureMail-Ai** up? `AI_AGENT_GRPC_URL` correct? `GROQ_API_KEY` set on AI service? |
| CORS errors from browser | `FRONTEND_URL` must match the web app origin. |
| Prisma errors | `DATABASE_URL`, migrations, Postgres reachable. |

## Scripts

| Command | Purpose |
|---------|---------|
| `pnpm run proto:check` | Verifies shared `ai-agent.proto` exists |
| `pnpm run build` | Production build |
| `pnpm run start:dev` | Watch mode |
| `pnpm run test` | Unit tests |
