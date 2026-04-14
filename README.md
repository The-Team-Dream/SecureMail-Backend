# SecureMail Backend

NestJS-powered REST API serving as the central orchestration point for the SecureMail ecosytem.

## ✅ Quick Start

You can run the backend as part of the full stack from the root:
```bash
# From repository root
npm run dev:api
```

Or run it individually:
1. **Infrastructure**: Ensure Postgres and Redis are running.
2. **Setup**:
   ```bash
   npm install
   npx prisma db push
   ```
3. **Execution**:
   ```bash
   npm run dev
   ```

## 🛠️ Configuration

| Variable | Default | Purpose |
|----------|---------|---------|
| `PORT` | `3000` | API port |
| `DATABASE_URL` | - | Postgres connection string |
| `REDIS_HOST` | `localhost` | Redis host |
| `AI_AGENT_GRPC_URL` | `localhost:50051` | Address of AI service |
| `MALWARE_GRPC_URL` | `localhost:50052` | Address of Malware service |

## 📡 API Documentation

Access the interactive **Swagger UI** at:
👉 **http://localhost:3000/api/docs**

---

## 🔗 gRPC Integration
The backend communicates with the AI and Malware microservices via gRPC using shared contracts located in the `/contracts` directory at the project root.

> [!NOTE]
> On startup, the backend logs:
> `✅ Malware Scanner gRPC Service initialized and ready.`
> `✅ AI Agent gRPC Service initialized and ready.`
> These logs confirm the gRPC clients are correctly loaded.
