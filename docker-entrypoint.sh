#!/bin/sh
set -e

# Run Prisma migrations to ensure DB is up to date
echo "Running Prisma migrations..."
npx prisma migrate deploy

# Start the application
echo "Starting application..."
exec "$@"
