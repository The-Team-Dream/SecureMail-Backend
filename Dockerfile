# ─── Stage 1: Dependencies ────────────────────────────────────────
FROM node:20-alpine AS deps

WORKDIR /app

# Enable corepack for pnpm support
RUN corepack enable && corepack prepare pnpm@latest --activate

# OpenSSL required by Prisma
RUN apk add --no-cache openssl

# Standalone context
COPY package.json pnpm-lock.yaml ./
RUN pnpm install --no-frozen-lockfile

# ─── Stage 2: Build ───────────────────────────────────────────────
FROM node:20-alpine AS builder

WORKDIR /app

RUN corepack enable && corepack prepare pnpm@latest --activate
RUN apk add --no-cache openssl

COPY --from=deps /app/node_modules ./node_modules

# Copy the standalone project
COPY . .

# Generate prisma client and build app
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
COPY --chown=nestjs:nodejs --from=builder /app/prisma ./prisma

# Production dependencies only
COPY --chown=nestjs:nodejs package.json pnpm-lock.yaml ./
RUN pnpm install --prod --no-frozen-lockfile

# Copy built app
COPY --chown=nestjs:nodejs --from=builder /app/dist ./dist

# Ensure the compiled Prisma client is in the expected relative path
COPY --chown=nestjs:nodejs --from=builder /app/generated ./generated

# Copy proto-check scripts
COPY --chown=nestjs:nodejs --from=builder /app/scripts ./scripts

# Safely copy contracts if they exist locally
COPY --chown=nestjs:nodejs --from=builder /app/contracts* ./contracts/

# Create logs directory with correct permissions
RUN mkdir -p /app/logs && chown nestjs:nodejs /app/logs

USER nestjs

EXPOSE 3000

CMD ["node", "dist/main"]