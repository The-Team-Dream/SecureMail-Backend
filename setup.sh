#!/bin/bash

# ═══════════════════════════════════════════════════════════════
# SecureMail-Backend — Setup & Start Script (Mac/Linux)
# Usage: chmod +x setup.sh && ./setup.sh
# ═══════════════════════════════════════════════════════════════

REPO_URL="https://github.com/The-Team-Dream/SecureMail-Backend"

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║       SecureMail-Backend Setup           ║"
echo "╚══════════════════════════════════════════╝"
echo ""

# ── 1. Check Docker ─────────────────────────────────────────────
if ! docker info > /dev/null 2>&1; then
    echo "❌ Docker is not running. Please start Docker Desktop first."
    exit 1
fi
echo "✅ Docker is running"
echo ""

# ── 2. Create .env.standalone from example ──────────────────────
if [ ! -f .env.standalone ]; then
    cp .env.standalone.example .env.standalone
    echo "✅ Created .env.standalone"
else
    echo "ℹ️  .env.standalone already exists — skipping copy"
fi
echo ""

# ── 3. Ask for DB Password ──────────────────────────────────────
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  DATABASE SETUP"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  Enter a password for PostgreSQL."
echo "  Press Enter to use default: 0000"
echo ""
read -s -p "  PostgreSQL Password: " db_pass
echo ""

# Use default if empty
if [ -z "$db_pass" ]; then
    db_pass="0000"
    echo "  ⚠️  Using default password: 0000"
    echo "      (Not recommended for production)"
else
    echo "  ✅ Password set"
fi
echo ""

# ── 4. Write password into .env.standalone ──────────────────────
sed -i "s/^POSTGRES_PASSWORD=.*/POSTGRES_PASSWORD=${db_pass}/" .env.standalone
sed -i "s|postgresql://postgres:.*@postgres|postgresql://postgres:${db_pass}@postgres|" .env.standalone
sed -i "s/POSTGRES_PASSWORD: \".*\"/POSTGRES_PASSWORD: \"${db_pass}\"/" docker-compose.yml
echo "✅ Password written to .env.standalone"
echo ""

# ── 5. Remind about optional secrets ────────────────────────────
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  ⚠️  OPTIONAL SECRETS — Fill these later"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  The following features won't work until"
echo "  you fill their secrets in .env.standalone:"
echo ""
echo "  📧 Gmail SMTP    → SMTP_PASSWORD"
echo "  🔐 Google OAuth  → GOOGLE_CLIENT_ID"
echo "                     GOOGLE_CLIENT_SECRET"
echo "  ☁️  Cloudinary    → CLOUDINARY_CLOUD_NAME"
echo "                     CLOUDINARY_API_KEY"
echo "                     CLOUDINARY_API_SECRET"
echo "  🛡️  AbuseIPDB     → ABUSEIPDB_API_KEY"
echo "  🔑 JWT           → JWT_SECRET"
echo "  🔒 Encryption    → ENCRYPTION_KEY"
echo ""
echo "  📖 Full guide on how to get each secret:"
echo "     $REPO_URL#readme"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
read -p "  Press Enter to start Docker..." _

# ── 6. Start Docker Compose ─────────────────────────────────────
echo ""
echo "🚀 Starting SecureMail Backend..."
echo ""
docker compose down -v > /dev/null 2>&1
docker compose up --build -d

# ── 7. Wait for backend ─────────────────────────────────────────
echo ""
echo "⏳ Waiting for backend to be ready..."
RETRIES=20
until docker compose logs backend 2>&1 | grep -q "All migrations have been successfully applied"; do
    RETRIES=$((RETRIES - 1))
    if [ $RETRIES -eq 0 ]; then
        echo ""
        echo "❌ Backend failed to start. Check logs with:"
        echo "   docker compose logs backend"
        exit 1
    fi
    sleep 3
    echo "   still waiting..."
done

# ── 8. Done ─────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════╗"
echo "║        ✅ Backend is running!            "
echo "╠══════════════════════════════════════════"
echo "║  API Docs: http://localhost:3000/api/docs/ "
echo "║  Health:   http://localhost:3000/health    "
echo "╠══════════════════════════════════════════"
echo "║  Logs:  docker compose logs -f backend  "
echo "║  Stop:  docker compose down             "
echo "╚══════════════════════════════════════════╝"
echo ""