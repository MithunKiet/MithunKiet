# Secure API Foundation — .NET 10

A **production-ready** open source backend starter template built with **ASP.NET Core (.NET 10)** using **Clean Architecture**. Includes enterprise-grade JWT authentication with refresh token rotation, device session management, Redis caching, PostgreSQL, Serilog logging, and Docker support.

---

## 📋 Table of Contents

- [Features](#-features)
- [Tech Stack](#-tech-stack)
- [Project Architecture](#-project-architecture)
- [Authentication Flow](#-authentication-flow)
- [Database Schema](#-database-schema)
- [Getting Started](#-getting-started)
  - [Prerequisites](#prerequisites)
  - [Local Setup (without Docker)](#local-setup-without-docker)
  - [Docker Setup](#docker-setup)
- [API Reference](#-api-reference)
- [Configuration](#-configuration)
- [Security Features](#-security-features)

---

## ✨ Features

| Category | Feature |
|---|---|
| **Authentication** | JWT Access Token (15 min), Refresh Token (7 days) |
| **Security** | Refresh Token Rotation, Token Reuse Detection, Account Lockout |
| **Sessions** | Per-device session tracking, Logout, Logout from all devices |
| **Password** | ASP.NET Identity `PasswordHasher` (PBKDF2) |
| **Rate Limiting** | Built-in ASP.NET Core rate limiter (10 req/min on auth endpoints) |
| **Logging** | Structured logging via Serilog (Console + File) |
| **Validation** | Request validation via FluentValidation |
| **API Docs** | Interactive API reference via Scalar |
| **Caching** | Redis-backed cache service |
| **Database** | PostgreSQL via Entity Framework Core |
| **Docker** | Multi-stage Dockerfile + docker-compose |

---

## 🛠 Tech Stack

| Component | Technology |
|---|---|
| Runtime | .NET 10 |
| Framework | ASP.NET Core Web API |
| ORM | Entity Framework Core 10 |
| Database | PostgreSQL 16 |
| Cache | Redis 7 |
| Auth | JWT Bearer + Refresh Tokens |
| Validation | FluentValidation 11 |
| Logging | Serilog 9 |
| API Docs | Scalar + Microsoft.AspNetCore.OpenApi |
| Containers | Docker + Docker Compose |

---

## 🏛 Project Architecture

This project follows **Clean Architecture** principles with clear separation of concerns:

```
src/
├── Domain/                         # Enterprise business rules
│   ├── Common/
│   │   └── BaseEntity.cs           # Shared entity base (Id, CreatedAt, UpdatedAt)
│   ├── Entities/
│   │   ├── User.cs
│   │   ├── UserSession.cs
│   │   └── SecurityLog.cs
│   └── Enums/
│       └── SecurityLogAction.cs
│
├── Application/                    # Application business rules
│   ├── Common/
│   │   └── Result.cs               # Generic result pattern (success/failure)
│   ├── DTOs/
│   │   └── AuthDtos.cs             # Request/response record types
│   ├── Interfaces/
│   │   ├── IAuthService.cs
│   │   ├── ITokenService.cs
│   │   ├── IPasswordService.cs
│   │   ├── ICacheService.cs
│   │   ├── IUserRepository.cs
│   │   ├── IUserSessionRepository.cs
│   │   └── ISecurityLogRepository.cs
│   ├── Services/
│   │   └── AuthService.cs          # Core authentication logic
│   ├── Validators/
│   │   └── AuthValidators.cs       # FluentValidation validators
│   └── DependencyInjection.cs
│
├── Infrastructure/                 # External concerns (DB, Redis, JWT)
│   ├── Database/
│   │   ├── AppDbContext.cs
│   │   └── Configurations/
│   │       └── EntityConfigurations.cs
│   ├── Repositories/
│   │   ├── UserRepository.cs
│   │   ├── UserSessionRepository.cs
│   │   └── SecurityLogRepository.cs
│   ├── Services/
│   │   ├── TokenService.cs         # JWT generation, refresh token, hashing
│   │   ├── PasswordService.cs      # PBKDF2 password hashing
│   │   └── RedisCacheService.cs
│   └── DependencyInjection.cs
│
└── Api/                            # Presentation layer
    ├── Controllers/
    │   └── AuthController.cs
    ├── Middleware/
    │   └── ExceptionMiddleware.cs
    ├── Program.cs
    ├── appsettings.json
    └── appsettings.Development.json
```

### Dependency Flow

```
Api → Application ← Infrastructure
         ↑
       Domain
```

- **Domain** has zero external dependencies.
- **Application** depends only on Domain (no EF Core, no Redis).
- **Infrastructure** implements Application interfaces.
- **Api** wires everything together.

---

## 🔐 Authentication Flow

### Login Flow

```
Client                          API                       Database
  |                              |                            |
  |-- POST /auth/login ---------->|                            |
  |                              |-- GetByEmail() ----------->|
  |                              |<-- User ------------------|
  |                              |-- VerifyPassword()         |
  |                              |-- CreateSession() -------->|
  |                              |-- LogSecurityEvent() ----->|
  |<-- { accessToken,            |                            |
  |       refreshToken,          |                            |
  |       expiresAt }            |                            |
```

### Refresh Token Rotation

```
Client                          API                       Database
  |                              |                            |
  |-- POST /auth/refresh ------->|                            |
  |   { refreshToken }           |-- HashToken()              |
  |                              |-- GetActiveSession() ----->|
  |                              |<-- Session ---------------|
  |                              |-- RevokeOldSession() ----->|
  |                              |-- CreateNewSession() ----->|
  |<-- { newAccessToken,         |                            |
  |       newRefreshToken }      |                            |
```

Key security properties:
- **Token rotation**: every refresh creates a new refresh token and revokes the old one
- **Reuse detection**: if a revoked token is used, no new session is granted
- **SHA-256 hashing**: refresh tokens are stored as hashes, never plaintext

### Account Lockout

After **5 consecutive failed logins**, the account is locked for **15 minutes**. All failed attempts and lockouts are recorded in `SecurityLogs`.

---

## 🗄 Database Schema

### Users
| Column | Type | Notes |
|---|---|---|
| Id | UUID | Primary key |
| Email | VARCHAR(256) | Unique |
| Username | VARCHAR(50) | Unique |
| PasswordHash | VARCHAR(512) | PBKDF2 |
| FirstName | VARCHAR(100) | Optional |
| LastName | VARCHAR(100) | Optional |
| IsActive | BOOL | Default true |
| FailedLoginAttempts | INT | Reset on success |
| LockoutEnd | TIMESTAMP | NULL = not locked |
| CreatedAt | TIMESTAMP | UTC |
| UpdatedAt | TIMESTAMP | UTC, nullable |

### UserSessions
| Column | Type | Notes |
|---|---|---|
| Id | UUID | Primary key |
| UserId | UUID | FK → Users |
| RefreshTokenHash | VARCHAR(512) | SHA-256 hash, indexed |
| DeviceInfo | VARCHAR(256) | |
| IpAddress | VARCHAR(45) | IPv4/IPv6 |
| UserAgent | VARCHAR(512) | |
| ExpiresAt | TIMESTAMP | UTC |
| RevokedAt | TIMESTAMP | UTC, nullable |
| IsActive | BOOL | |
| IsRevoked | BOOL | |

### SecurityLogs
| Column | Type | Notes |
|---|---|---|
| Id | UUID | Primary key |
| UserId | UUID | FK → Users |
| Action | VARCHAR(50) | Enum stored as string |
| IpAddress | VARCHAR(45) | |
| UserAgent | VARCHAR(512) | |
| Details | VARCHAR(1024) | Optional context |
| IsSuccess | BOOL | |
| CreatedAt | TIMESTAMP | UTC |

---

## 🚀 Getting Started

### Prerequisites

- [.NET 10 SDK](https://dotnet.microsoft.com/download/dotnet/10.0)
- [PostgreSQL 16+](https://www.postgresql.org/)
- [Redis 7+](https://redis.io/)
- [Docker + Docker Compose](https://docs.docker.com/get-docker/) *(optional)*

---

### Local Setup (without Docker)

**1. Clone the repository**

```bash
git clone https://github.com/MithunKiet/MithunKiet.git
cd MithunKiet
```

**2. Configure environment**

```bash
cp .env.example .env
# Edit .env with your database and JWT settings
```

Update `src/Api/appsettings.Development.json`:

```json
{
  "ConnectionStrings": {
    "DefaultConnection": "Host=localhost;Port=5432;Database=secure_api_dev;Username=postgres;Password=your_password",
    "Redis": "localhost:6379"
  },
  "Jwt": {
    "SecretKey": "your-very-long-secret-key-at-least-32-characters",
    "Issuer": "SecureApiFoundation",
    "Audience": "SecureApiFoundation"
  }
}
```

**3. Create the database**

```bash
# Install EF Core tools
dotnet tool install --global dotnet-ef

# Run migrations
dotnet ef database update --project src/Infrastructure --startup-project src/Api
```

**4. Run the application**

```bash
cd src/Api
dotnet run
```

API is now available at `https://localhost:7000`  
Interactive API docs at `https://localhost:7000/scalar/v1`

---

### Docker Setup

**1. Configure environment**

```bash
cp .env.example .env
# Set POSTGRES_PASSWORD and JWT_SECRET_KEY
```

**2. Start all services**

```bash
docker compose up -d
```

This starts:
- **API** at `http://localhost:8080`
- **PostgreSQL** at `localhost:5432`
- **Redis** at `localhost:6379`

**3. Apply database migrations**

```bash
docker compose exec api dotnet ef database update \
  --project /app/Infrastructure \
  --startup-project /app
```

**4. View logs**

```bash
docker compose logs -f api
```

---

## 📡 API Reference

### Base URL: `http://localhost:8080`

---

#### `POST /auth/register` — Register a new user

**Request:**
```json
{
  "email": "john@example.com",
  "username": "john_doe",
  "password": "StrongPass@123",
  "firstName": "John",
  "lastName": "Doe"
}
```

**Response** `201 Created`:
```json
{
  "id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "email": "john@example.com",
  "username": "john_doe",
  "firstName": "John",
  "lastName": "Doe"
}
```

---

#### `POST /auth/login` — Authenticate and get tokens

**Request:**
```json
{
  "email": "john@example.com",
  "password": "StrongPass@123",
  "deviceInfo": "Chrome on Windows"
}
```

**Response** `200 OK`:
```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refreshToken": "dGhpcyBpcyBhIHJhbmRvbSByZWZyZXNoIHRva2Vu...",
  "accessTokenExpiry": "2025-01-01T00:15:00Z",
  "refreshTokenExpiry": "2025-01-08T00:00:00Z",
  "user": {
    "id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
    "email": "john@example.com",
    "username": "john_doe"
  }
}
```

---

#### `POST /auth/refresh` — Rotate refresh token

**Request:**
```json
{
  "refreshToken": "dGhpcyBpcyBhIHJhbmRvbSByZWZyZXNoIHRva2Vu..."
}
```

**Response** `200 OK`:
```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refreshToken": "bmV3cmVmcmVzaHRva2VuaGVyZQ==...",
  "accessTokenExpiry": "2025-01-01T00:30:00Z",
  "refreshTokenExpiry": "2025-01-08T00:15:00Z"
}
```

---

#### `POST /auth/logout` — Revoke current session

**Headers:** `Authorization: Bearer <access_token>`

**Request:**
```json
{
  "refreshToken": "dGhpcyBpcyBhIHJhbmRvbSByZWZyZXNoIHRva2Vu..."
}
```

**Response** `204 No Content`

---

#### `POST /auth/logout-all` — Revoke all sessions

**Headers:** `Authorization: Bearer <access_token>`

**Response** `204 No Content`

---

#### `GET /auth/sessions` — List active sessions

**Headers:** `Authorization: Bearer <access_token>`

**Response** `200 OK`:
```json
[
  {
    "id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
    "deviceInfo": "Chrome on Windows",
    "ipAddress": "192.168.1.1",
    "createdAt": "2025-01-01T00:00:00Z",
    "expiresAt": "2025-01-08T00:00:00Z",
    "isActive": true
  }
]
```

---

### Error Responses

| Status | Description |
|---|---|
| `400 Bad Request` | Validation failure |
| `401 Unauthorized` | Invalid credentials / expired token |
| `404 Not Found` | Resource not found |
| `429 Too Many Requests` | Rate limit exceeded |
| `500 Internal Server Error` | Unexpected error |

**Validation error example:**
```json
{
  "errors": [
    { "field": "Email", "message": "A valid email address is required." },
    { "field": "Password", "message": "Password must be at least 8 characters." }
  ]
}
```

---

## ⚙ Configuration

### `appsettings.json` Reference

```json
{
  "Jwt": {
    "SecretKey": "...",                  // Min 32 chars, cryptographically random
    "Issuer": "SecureApiFoundation",
    "Audience": "SecureApiFoundation",
    "AccessTokenExpiryMinutes": "15",    // Default: 15 min
    "RefreshTokenExpiryDays": "7"        // Default: 7 days
  },
  "ConnectionStrings": {
    "DefaultConnection": "...",          // PostgreSQL connection string
    "Redis": "localhost:6379"
  },
  "Cors": {
    "AllowedOrigins": ["http://localhost:3000"]
  }
}
```

### Environment Variables (Docker)

All `appsettings.json` keys can be overridden via environment variables using double-underscore notation:

```
Jwt__SecretKey=your-secret
ConnectionStrings__DefaultConnection=Host=postgres;...
```

---

## 🔒 Security Features

| Feature | Implementation |
|---|---|
| **Password hashing** | ASP.NET Identity `PasswordHasher` (PBKDF2 with SHA-256, 10000 iterations) |
| **Refresh token storage** | Stored as SHA-256 hashes only — never plaintext |
| **Token rotation** | Every refresh call rotates the refresh token |
| **Reuse detection** | Revoked tokens return 401, no new session granted |
| **Account lockout** | 5 failed attempts → 15-minute lockout |
| **Rate limiting** | 10 requests/minute per IP on all auth endpoints |
| **Security audit log** | All auth events (login, logout, failures) recorded in DB |
| **Non-root Docker** | Container runs as unprivileged `appuser` |
| **HTTPS** | Enforced in non-Docker environments |

---

## 📄 License

This project is licensed under the MIT License.
