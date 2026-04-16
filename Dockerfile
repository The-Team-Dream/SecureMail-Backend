# ─── Stage 1: Dependencies ────────────────────────────────────────
FROM node:20-alpine AS deps

WORKDIR /app

# Enable corepack for pnpm support
RUN corepack enable && corepack prepare pnpm@latest --activate

# OpenSSL required by Prisma
RUN apk add --no-cache openssl

# Context is monorepo root
COPY SecureMail-Backend/package.json SecureMail-Backend/pnpm-lock.yaml ./
RUN pnpm install --no-frozen-lockfile

# ─── Stage 2: Build ───────────────────────────────────────────────
FROM node:20-alpine AS builder

WORKDIR /app

RUN corepack enable && corepack prepare pnpm@latest --activate
RUN apk add --no-cache openssl

COPY --from=deps /app/node_modules ./node_modules
COPY pnpm-workspace.yaml ./
COPY contracts ./contracts
COPY SecureMail-Backend ./SecureMail-Backend

# Run from backend directory to ensure prisma and build scripts find their relative paths
WORKDIR /app/SecureMail-Backend
RUN npx prisma generate
RUN pnpm run build
RUN if [ -d "dist/src" ]; then cp -r dist/src/* dist/ && rm -rf dist/src; fi

# ─── Stage 3: Production ──────────────────────────────────────────
FROM node:20-alpine AS production

WORKDIR /app

RUN corepack enable && corepack prepare pnpm@latest --activate
RUN apk add --no-cache openssl

# Non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser  -S nestjs -u 1001 -G nodejs

# Copy original prisma folder for the schema (do this before install to avoid prisma install warnings)
COPY --chown=nestjs:nodejs --from=builder /app/SecureMail-Backend/prisma ./prisma

# Production dependencies only
COPY --chown=nestjs:nodejs SecureMail-Backend/package.json SecureMail-Backend/pnpm-lock.yaml ./
RUN pnpm install --prod --no-frozen-lockfile

# Copy built app
COPY --chown=nestjs:nodejs --from=builder /app/SecureMail-Backend/dist ./dist

# Ensure the compiled Prisma client is in the expected relative path (../generated from dist/)
COPY --chown=nestjs:nodejs --from=builder /app/SecureMail-Backend/generated /app/generated

# Copy proto-check scripts
COPY --chown=nestjs:nodejs --from=builder /app/SecureMail-Backend/scripts ./scripts

# Copy shared contracts (one level up as expected by scripts)
COPY --chown=nestjs:nodejs --from=builder /app/contracts ../contracts

# Create logs directory with correct permissions
RUN mkdir -p /app/logs && chown nestjs:nodejs /app/logs

USER nestjs

EXPOSE 3000

CMD ["node", "dist/main"]