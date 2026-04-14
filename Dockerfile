# ─── Stage 1: Dependencies ────────────────────────────────────────
FROM node:20-alpine AS deps

WORKDIR /app

# OpenSSL required by Prisma
RUN apk add --no-cache openssl

COPY package*.json ./
RUN npm ci

# ─── Stage 2: Build ───────────────────────────────────────────────
FROM node:20-alpine AS builder

WORKDIR /app

RUN apk add --no-cache openssl

COPY --from=deps /app/node_modules ./node_modules
COPY . .

# Generate Prisma client before building
RUN npx prisma generate

RUN npm run build

# ─── Stage 3: Production ──────────────────────────────────────────
FROM node:20-alpine AS production

WORKDIR /app

RUN apk add --no-cache openssl

# Production dependencies only
COPY package*.json ./
RUN npm ci --only=production && npm cache clean --force

# Copy Prisma schema + generated client
COPY --from=builder /app/prisma        ./prisma
COPY --from=builder /app/generated     ./generated
COPY --from=builder /app/node_modules/.prisma ./node_modules/.prisma

# Copy built app
COPY --from=builder /app/dist ./dist

# Copy proto-check scripts
COPY --from=builder /app/scripts ./scripts

# Non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser  -S nestjs -u 1001 -G nodejs && \
    mkdir -p /app/logs && chown nestjs:nodejs /app/logs

USER nestjs

EXPOSE 3000

CMD ["node", "dist/main"]