@echo off

if not exist .env.standalone (
    copy .env.standalone.example .env.standalone
    echo ✅ Created .env.standalone
) else (
    echo ⚠️  .env.standalone already exists
)

if not exist .env.docker (
    copy .env.docker.example .env.docker
    echo ✅ Created .env.docker
) else (
    echo ⚠️  .env.docker already exists
)

if not exist .env (
    copy .env.example .env
    echo ✅ Created .env
) else (
    echo ⚠️  .env already exists
)

echo.
echo 🔐 Fill in your secrets in the .env files before running!
echo.

docker compose up --build -d