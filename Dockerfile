# ════════════════════════════════════════════════════════════════════════════
# SecureMail-Backend — Multi-stage Dockerfile (4 stages)
# Service: NestJS REST API + gRPC client
# Port:    3000
# ════════════════════════════════════════════════════════════════════════════

# ── Stage 1: Install all node_modules ───────────────────────────────────────
FROM node:22-alpine AS deps

# Install pnpm globally
RUN npm install -g pnpm

WORKDIR /app

# Copy lockfiles first for layer caching
COPY package.json pnpm-lock.yaml ./

# Install all dependencies (including devDependencies needed for build)
RUN pnpm install --frozen-lockfile


# ── Stage 2: Build NestJS application ───────────────────────────────────────
FROM node:22-alpine AS builder

RUN npm install -g pnpm

WORKDIR /app

# Copy node_modules from deps stage
COPY --from=deps /app/node_modules ./node_modules

# Copy full source — contracts/ is already inside SecureMail-Backend/contracts/
# nest-cli.json references "contracts/**/*.proto" (relative, patched from "../contracts/")
# so the build will correctly copy .proto files into dist/contracts/
COPY . .

# Generate Prisma client before building (defaults to node_modules/@prisma/client)
RUN pnpm prisma generate && ls -la node_modules/@prisma/client

# Build TypeScript → dist/
RUN pnpm nest build


# ── Stage 4: Production runtime ─────────────────────────────────────────────
FROM node:22-alpine AS runtime

# curl is needed for the /health endpoint healthcheck in docker-compose
RUN apk add --no-cache curl

WORKDIR /app

ENV NODE_ENV=production

# Copy compiled application
COPY --from=builder /app/dist ./dist

# Copy contracts so the runtime proto resolver finds them at cwd/contracts/
COPY --from=builder /app/contracts ./contracts

# Copy production node_modules from builder (contains generated Prisma client)
COPY --from=builder /app/node_modules ./node_modules

# Copy Prisma schema & config (needed for migrations)
COPY prisma/ ./prisma/
COPY prisma.config.ts ./

# Copy package.json (needed for runtime meta)
COPY package.json ./

# Create uploads directory for ServeStaticModule
RUN mkdir -p uploads

# Non-root user
RUN addgroup -S nestgroup && adduser -S -G nestgroup nestuser && \
    chown -R nestuser:nestgroup /app
USER nestuser

EXPOSE 3000

# Run database migration then start the server
CMD sh -c "npx prisma migrate deploy && node dist/main"
