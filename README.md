# Enterprise-Grade Monolithic IAM System

A modern, highly modular, production-ready Identity and Access Management (IAM) platform built with **Spring Boot 3.3.3**, **Spring Security 6**, and **Nimbus JOSE + JWT**. It provides comprehensive support for both human user identities and non-human machine-to-machine (M2M) entities under a unified architecture.

---

## Architecture & Modular Design

The system is organized into decoupled Maven modules to enforce clean separation of concerns and maintainable domain boundaries:

```
iam-system/
├── iam-common/       # Shared domain models, standard API responses, and base exceptions
├── iam-crypto/       # Cryptography, RSA key lifecycle management, and public JWKS endpoint
├── iam-directory/    # JPA entities and repositories (Users, Service Principals, Auth Codes, Revoked Tokens)
├── iam-authn/        # Authentication engine (Human login, OAuth2 Authorization Code + PKCE, M2M Client Credentials)
├── iam-authz/        # Authorization engine (JWT verification, token introspection, and token revocation)
└── iam-gateway/      # Main application assembly, database seeding, and runtime bootstrap
```

---

## Core Capabilities & Features

### 1. Cryptography & Key Management (`iam-crypto`)
* **Asymmetric Signing**: Automatically generates secure RSA-2048 key pairs on startup via `KeyManagementService`.
* **JWKS Endpoint**: Publishes public JSON Web Key Sets dynamically at `/.well-known/jwks.json` to allow downstream microservices to verify JWS signatures locally.

### 2. User & Entity Directory (`iam-directory`)
* **Relational Storage**: Backed by Spring Data JPA and H2 (easily configurable for PostgreSQL, MySQL, etc.).
* **Core Models**:
  * `UserEntity`: Manages human user profiles, credentials, and active statuses.
  * `ServicePrincipalEntity`: Manages machine identities, secrets, and allowed scopes.
  * `AuthorizationCodeEntity`: Manages short-lived, single-use auth codes.
  * `RevokedTokenEntity`: Tracks blocklisted tokens for immediate session termination.

### 3. Authentication Engine (`iam-authn`)
* **Human Direct Login**: Password hashing via BCrypt (`/auth/login`) returning cryptographically signed RS256 JWT access tokens.
* **OAuth 2.0 Authorization Code Flow with PKCE**:
  * `/oauth2/authorize`: Validates clients, redirect URIs, and code challenges (`S256`).
  * `/oauth2/token`: Exchanges single-use authorization codes securely using PKCE code verifiers.
* **Machine-to-Machine (M2M) Client Credentials Flow**:
  * `/oauth2/token` (`grant_type=client_credentials`): Validates client secrets and issues scoped access tokens for backend microservices and service accounts.

### 4. Authorization & Security (`iam-authz`)
* **Token Introspection**: `/authz/introspect` securely validates JWS signatures against local public keys and inspects active claims, expiration times, and revocation status.
* **Token Revocation**: `/authz/revoke` instantly registers tokens into the revocation blocklist store to prevent usage after logout or compromise.

---

## Getting Started

### Prerequisites
* **Java 21** or higher
* **Maven 3.8+**

### Building the Project
Clone the repository and compile all modules using Maven:
```bash
mvn clean install
```

### Running the Application
Run the main Spring Boot application from the gateway module:
```bash
mvn spring-boot:run -pl iam-gateway
```

The application will start on port `8080`.

---

## Default Seed Data

On startup, the system automatically seeds default test records for immediate evaluation:

* **Human User**: 
  * Username: `testuser`
  * Password: `password123`
* **Service Principal (M2M)**: 
  * Client ID: `test-service-client`
  * Client Secret: `secret123`
  * Allowed Scopes: `payments:read payments:write`

---

## API Endpoints Reference

| Endpoint | Method | Description |
| :--- | :---: | :--- |
| `/.well-known/jwks.json` | `GET` | Retrieve public JSON Web Key Set for JWT verification |
| `/auth/login` | `POST` | Authenticate human user with username/password |
| `/oauth2/authorize` | `GET` | Initiate OAuth 2.0 authorization code flow with PKCE |
| `/oauth2/token` | `POST` | Exchange auth code (PKCE) or client credentials for a JWT |
| `/authz/introspect` | `POST` | Validate and inspect active token claims |
| `/authz/revoke` | `POST` | Revoke/blocklist an active token |
| `/h2-console` | `GET` | H2 Database Web Console (`jdbc:h2:mem:iamdb`) |
