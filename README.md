# sondhan-auth-service

**Auth & Identity microservice** for the Bloodlink/Sondhan blood donor platform.
Runs on port **8086**. Issues RS256 JWTs; all other services verify against `/auth/.well-known/jwks.json`.

---

## Prerequisites

- Java 21
- Maven 3.9+
- Docker & Docker Compose

---

## Quick start (Docker Compose)

### 1. Generate RSA keys

```bash
# Generate 2048-bit RSA key pair
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem

# Convert to base64 (single line) for environment variables
export JWT_PRIVATE_KEY=$(openssl pkcs8 -topk8 -nocrypt -inform PEM -outform DER -in private.pem | base64 -w0)
export JWT_PUBLIC_KEY=$(openssl rsa -pubin -inform PEM -outform DER -in public.pem | base64 -w0)
```

### 2. Create `.env` file

```env
DB_PASSWORD=your_db_password
REDIS_PASSWORD=your_redis_password
JWT_PRIVATE_KEY=<base64 PKCS8 private key from step 1>
JWT_PUBLIC_KEY=<base64 X.509 public key from step 1>
PII_ENCRYPTION_KEY=your_32_char_encryption_key_here!
TWILIO_ACCOUNT_SID=ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
TWILIO_AUTH_TOKEN=your_twilio_auth_token
TWILIO_FROM_NUMBER=+15005550006
CORS_ORIGIN_1=https://your-frontend.com
```

### 3. Run

```bash
docker compose up -d
```

Service will be available at `http://localhost:8086`.
Swagger UI: `http://localhost:8086/auth/docs`

---

## Local development (without Docker)

### Start dependencies only

```bash
docker compose up postgres redis -d
```

### Run the service

```bash
# Export required environment variables first (see .env example above)
mvn spring-boot:run
```

---

## API Reference

[comment]: <> (| Method | Endpoint | Auth | Description |)

[comment]: <> (|--------|----------|------|-------------|)

[comment]: <> (| POST | `/auth/v1/register` | Public | Register new user, sends OTP |)

[comment]: <> (| POST | `/auth/v1/login` | Public | Login existing user, sends OTP |)

[comment]: <> (| POST | `/auth/v1/verify-otp` | Public | Verify OTP, receive tokens |)

[comment]: <> (| POST | `/auth/v1/refresh` | Public | Rotate refresh token |)

[comment]: <> (| POST | `/auth/v1/logout` | Bearer | Revoke tokens |)

[comment]: <> (| GET  | `/auth/v1/me` | Bearer | Get current user profile |)

[comment]: <> (| GET  | `/auth/.well-known/jwks.json` | Public | RSA public key &#40;JWK Set&#41; |)

Full API docs with request/response schemas: **`/auth/docs`**

---

## Token design

| Token | Format | TTL | Storage |
|-------|--------|-----|---------|
| Access token | RS256 JWT | 15 min | Client-side only |
| Refresh token | Opaque UUID | 30 days | Redis `refresh:{uuid}` |

**Refresh token rotation:** every `/refresh` call deletes the old token and issues a new one atomically. If a previously rotated token is presented, the entire token family is revoked (reuse attack detection).

---

## Security features

- OTP rate limit: max 3 requests per phone per hour
- Failed OTP lockout: 5 failures → 15-minute lockout
- All PII (phone, email) stored encrypted via pgcrypto — never plaintext in `users` table
- JWT deny-list on logout (Redis `deny:{jti}`)
- Append-only audit log (Postgres role has no DELETE)
- CORS restricted to configured origins
- Secrets loaded from environment — never in code

---

## Running tests

```bash
# Unit + integration tests (requires Docker for Testcontainers)
mvn test
```

Tests use real PostgreSQL 16 and Redis 7 containers via Testcontainers.

---

[comment]: <> (## Flyway migrations)

[comment]: <> (Migrations live in `src/main/resources/db/migration/`:)

[comment]: <> (| Version | Description |)

[comment]: <> (|---------|-------------|)

[comment]: <> (| V1 | users, roles, user_roles tables |)

[comment]: <> (| V2 | otp_codes table |)

[comment]: <> (| V3 | pii_tokens table + FK constraints |)

[comment]: <> (| V4 | audit_logs &#40;partitioned, append-only&#41; |)

[comment]: <> (| V5 | Performance indexes |)

[comment]: <> (---)

[comment]: <> (## Package structure)

[comment]: <> (```)

[comment]: <> (com.bloodlink.auth)

[comment]: <> (├── config/       SecurityConfig, RedisConfig, JwtConfig, SwaggerConfig, TwilioConfig)

[comment]: <> (├── controller/   AuthController, JwksController)

[comment]: <> (├── service/      AuthService, TokenService, OtpService, UserService, AuditService)

[comment]: <> (├── repository/   UserRepository, OtpRepository, PiiTokenRepository, RoleRepository, AuditLogRepository)

[comment]: <> (├── domain/       User, Role, OtpCode, PiiToken, AuditLog)

[comment]: <> (├── dto/          AuthDtos &#40;all request/response records&#41;, RefreshTokenData)

[comment]: <> (├── security/     JwtTokenProvider, JwtAuthFilter, CustomUserDetailsService)

[comment]: <> (├── exception/    GlobalExceptionHandler, AuthException, ErrorCode)

[comment]: <> (└── util/         PiiTokenizer, HashUtil, IpExtractor)

[comment]: <> (```)
