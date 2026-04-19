#!/bin/bash

[ ! -f .env.standalone ] && cp .env.standalone.example .env.standalone && echo "✅ Created .env.standalone"
[ ! -f .env.docker ]     && cp .env.docker.example .env.docker         && echo "✅ Created .env.docker"
[ ! -f .env ]            && cp .env.example .env                       && echo "✅ Created .env"

echo ""
echo "⚠️  Fill in your secrets in the .env files before running!"
echo ""

docker compose up --build -d