# Project Contracts (Protobuf)

This directory contains the shared **gRPC** definitions (Protobuf files) used across the SecureMail services. These files serve as the single source of truth for communication between the Backend and various processing engines.

## Files

| File | Primary Owner | Consumers |
|------|---------------|-----------|
| `ai-agent.proto` | **SecureMail-Ai** | Backend (NestJS), AI (Python) |
| `malware.proto` | **SecureMail-Malware** | Backend (NestJS), Malware (Go) |

## Usage

### 1. Backend (NestJS)
The NestJS backend uses `@grpc/proto-loader` to load these files dynamically at runtime (or via generated TS types). Ensure the `contracts/` directory is accessible to the backend container.

### 2. AI Service (Python)
Python files are generated using `grpc_tools.protoc`. See the [SecureMail-Ai/README.md](../SecureMail-Ai/README.md) for regeneration instructions.

### 3. Malware Service (Go)
Go files are generated during the Docker build process in the [SecureMail-Malware/Dockerfile](../SecureMail-Malware/Dockerfile).

## Architecture Note
By centralizing these definitions, we ensure that both the client (Backend) and the servers (AI/Malware) are always in sync regarding request and response schemas.
