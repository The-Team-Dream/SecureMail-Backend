# Build stage
FROM node:22-alpine AS builder

WORKDIR /app

# Install pnpm
RUN npm install -g pnpm

COPY package*.json pnpm-lock.yaml* ./
RUN pnpm install --frozen-lockfile

COPY . .

# Generate Prisma client
RUN pnpm prisma generate

# Build the app
RUN pnpm build

# Production stage
FROM node:22-alpine AS production

WORKDIR /app

RUN npm install -g pnpm

COPY package*.json pnpm-lock.yaml* ./
RUN pnpm install --prod --frozen-lockfile

# Copy built files
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules/.prisma ./node_modules/.prisma
COPY --from=builder /app/generated ./generated
COPY --from=builder /app/prisma ./prisma

# Run migrations then start
CMD ["sh", "-c", "npx prisma migrate deploy && node dist/main"]
