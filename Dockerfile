# Build from monorepo root:
#   docker build -f SecureMail-Backend/Dockerfile -t securemail-backend .

FROM node:20-bookworm-slim AS builder
RUN corepack enable && corepack prepare pnpm@9.15.0 --activate
WORKDIR /app

COPY contracts ./contracts
COPY SecureMail-Backend/package.json SecureMail-Backend/pnpm-lock.yaml ./
COPY SecureMail-Backend/prisma ./prisma
COPY SecureMail-Backend/scripts ./scripts
COPY SecureMail-Backend/tsconfig.json SecureMail-Backend/nest-cli.json ./
COPY SecureMail-Backend/src ./src

RUN pnpm install --frozen-lockfile
RUN pnpm exec prisma generate
ENV NODE_ENV=production
RUN pnpm run build

FROM node:20-bookworm-slim AS runner
RUN corepack enable && corepack prepare pnpm@9.15.0 --activate
RUN apt-get update && apt-get install -y --no-install-recommends openssl ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
ENV NODE_ENV=production

COPY --from=builder /app/dist ./dist
COPY --from=builder /app/generated ./generated
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package.json ./package.json
COPY --from=builder /app/pnpm-lock.yaml ./pnpm-lock.yaml
COPY --from=builder /app/prisma ./prisma
COPY --from=builder /app/contracts ./contracts
COPY SecureMail-Backend/docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh && mkdir -p /app/uploads

EXPOSE 3000
ENTRYPOINT ["/docker-entrypoint.sh"]
