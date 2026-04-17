# STAGE 1: Install all dependencies (including devDependencies for building)
FROM node:22-alpine AS build-deps
RUN apk add --no-cache libc6-compat
WORKDIR /app

# Enable pnpm
ENV PNPM_HOME="/pnpm"
ENV PATH="$PNPM_HOME:$PATH"
RUN corepack enable

# Copy package files
COPY package.json pnpm-lock.yaml ./

# Install all dependencies
RUN pnpm install --frozen-lockfile

# STAGE 2: Build the application
FROM node:22-alpine AS builder
WORKDIR /app

ENV PNPM_HOME="/pnpm"
ENV PATH="$PNPM_HOME:$PATH"
RUN corepack enable

# Copy node_modules from build-deps and source code
COPY --from=build-deps /app/node_modules ./node_modules
COPY . .

# Generate Prisma client and Build NestJS
RUN npx prisma generate
RUN pnpm build

# STAGE 3: Install ONLY production dependencies
FROM node:22-alpine AS runtime-deps
WORKDIR /app

ENV PNPM_HOME="/pnpm"
ENV PATH="$PNPM_HOME:$PATH"
RUN corepack enable

COPY package.json pnpm-lock.yaml ./
# Install only production dependencies
RUN pnpm install --prod --frozen-lockfile

# STAGE 4: Final minimal runtime image
FROM node:22-alpine AS runtime
WORKDIR /app

# Install security updates and libc6-compat for Prisma
RUN apk update && apk upgrade && apk add --no-cache libc6-compat

# Create a non-root user
RUN addgroup --system --gid 1001 nodejs
RUN adduser --system --uid 1001 nestjs

# Copy the compiled application
COPY --from=builder --chown=nestjs:nodejs /app/dist ./dist
# Copy the production node_modules
COPY --from=runtime-deps --chown=nestjs:nodejs /app/node_modules ./node_modules
# Copy the generated Prisma client
COPY --from=builder --chown=nestjs:nodejs /app/generated ./generated
# Copy Prisma schema and migrations for 'migrate deploy'
COPY --from=builder --chown=nestjs:nodejs /app/prisma ./prisma
# Copy package.json and entrypoint
COPY --chown=nestjs:nodejs package.json ./
COPY --chown=nestjs:nodejs docker-entrypoint.sh ./

# Make entrypoint executable
RUN chmod +x docker-entrypoint.sh

USER nestjs

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "fetch('http://localhost:3000/health').then(r => r.status === 200 ? process.exit(0) : process.exit(1)).catch(() => process.exit(1))"

ENTRYPOINT ["./docker-entrypoint.sh"]
CMD ["node", "dist/main"]
