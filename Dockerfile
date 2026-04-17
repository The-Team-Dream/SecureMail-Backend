# ─────────────────────────────────────────────────────────────────
#  SecureMail – Backend  (NestJS + Prisma 7 + pnpm)
#  Standalone: copy SecureMail-Backend/ anywhere and docker build .
# ─────────────────────────────────────────────────────────────────

# ── Stage 1: dependency installer ────────────────────────────────
FROM node:22-alpine AS deps

# pnpm via corepack (fastest – no extra layer)
RUN corepack enable && corepack prepare pnpm@latest --activate

WORKDIR /app

# Copy manifests first – maximises layer-cache hits
COPY package.json pnpm-lock.yaml ./

# Install ALL deps (including devDeps needed for build)
RUN pnpm install --frozen-lockfile

# ── Stage 2: builder ──────────────────────────────────────────────
FROM node:22-alpine AS builder

RUN corepack enable && corepack prepare pnpm@latest --activate

WORKDIR /app

# Bring node_modules from deps stage
COPY --from=deps /app/node_modules ./node_modules

# Copy the full source (excluding what's in .dockerignore)
COPY . .

# Generate Prisma client
# schema.prisma output = "../generated/prisma" is relative to prisma/
# so the client lands at ./generated/prisma inside the service folder
RUN npx prisma generate --schema=prisma/schema.prisma

# Compile TypeScript → dist/
# nest-cli.json copies contracts/**/*.proto → dist/contracts/
RUN pnpm run build

# ── Stage 3: production runner ───────────────────────────────────
FROM node:22-alpine AS runner

RUN corepack enable && corepack prepare pnpm@latest --activate

# Install OpenSSL (required by Prisma) + curl (health-check)
RUN apk add --no-cache openssl curl

# Non-root user for security
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

WORKDIR /app

# Copy only production deps
COPY package.json pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile --prod

# Copy compiled application
COPY --from=builder /app/dist ./dist

# Copy generated Prisma client (built into generated/prisma)
COPY --from=builder /app/generated ./generated

# Copy Prisma schema & migrations (needed for migrate deploy at startup)
COPY --from=builder /app/prisma ./prisma
COPY --from=builder /app/prisma.config.ts ./prisma.config.ts

# Copy proto contracts that nest-cli already placed in dist/contracts
# (already included in the dist copy above – nothing extra needed)

# Nest.js looks for nest-cli.json at startup in some configurations
COPY nest-cli.json ./

RUN chown -R appuser:appgroup /app
USER appuser

EXPOSE 3000

# Health check against the app's own /health endpoint
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
  CMD curl -f http://localhost:3000/health || exit 1

# Run migrations then start the app
CMD ["sh", "-c", "npx prisma migrate deploy --schema=prisma/schema.prisma && node dist/main"]
