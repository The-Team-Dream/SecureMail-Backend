# SecureMail-Backend 🛡️

SecureMail-Backend is a high-performance, containerized TypeScript microservice built with NestJS, powering the security and mailbox management infrastructure for SecureMail.

## 🚀 Quick Start

Follow these steps to get the project running on your machine.

### 1. Clone the Repository
```bash
git clone <repository-url>
cd SecureMail-Backend
```

### 2. Configure Environment Variables
Copy the example environment file and adjust values as needed.
```bash
cp .env.example .env
# For Docker specifically
cp .env.example .env.docker
```

---

## 🐳 Option 1: Running with Docker (Recommended)
This method launches the entire stack (PostgreSQL, Redis, and Backend) in isolated containers.

**Prerequisites:** Docker & Docker Compose installed.

**Steps:**
1. Start the stack:
   ```bash
   docker compose up -d
   ```
2. Verify the application is running:
   ```bash
   docker compose logs backend -f
   ```
   *Expected Output: `[NestApplication] Nest application successfully started`*

---

## 🛠️ Option 2: Local Development
Use this for active coding and debugging.

**Prerequisites:** 
- Node.js v22+
- pnpm
- Running PostgreSQL & Redis instances

**Steps:**
1. Install dependencies:
   ```bash
   pnpm install
   ```
2. Generate Prisma Client (crucial for type safety):
   ```bash
   npx prisma generate
   ```
3. Run in development mode:
   ```bash
   pnpm run dev
   ```

---

## 🏗️ Technical Architecture

### Tech Stack
- **Framework**: [NestJS](https://nestjs.com/) (Node.js)
- **Database**: [PostgreSQL](https://www.postgresql.org/)
- **ORM**: [Prisma](https://www.prisma.io/)
- **Caching/Queuing**: [Redis](https://redis.io/)
- **Communication**: gRPC / REST
- **Security**: JWT, TOTP (2FA), Bcrypt

### Key Features
- **Prisma Integration**: Standardized `@prisma/client` implementation for robust database interactions.
- **Multistage Docker Build**: Hardened, production-ready images using Alpine Linux.
- **Security Pipeline**: Multi-layered threat simulation including malware scanning and AI-driven analysis.
- **Automated Deployments**: Integrated entrypoint scripts handling DB migrations automatically.

## 📁 Project Structure
- `src/`: Application source code.
- `prisma/`: Database schema and migrations.
- `contracts/`: gRPC proto definitions.
- `docker-compose.yml`: Infrastructure orchestration.

## ⚠️ Troubleshooting
- **Prisma Errors in Editor**: If you see red imports, run `npx prisma generate` locally.
- **Database Connection**: Ensure your `.env` values match your running database setup.
- **Proto Paths**: The application expects gRPC contracts at `/contracts` relative to the root.

---

Built with ❤️ by the SecureMail Team.
