# AuthForge

A JWT + refresh-token authentication service built from scratch in **Node.js, Express, and MySQL** — as a hands-on project to deeply understand how modern auth systems work under the hood.

## Why this project

Most tutorials wrap authentication in a library and move on. AuthForge intentionally avoids that — every piece (token signing, rotation, theft detection, rate limiting) is implemented manually to build real understanding of the mechanics, not just usage of an abstraction.

## Features

- **Signup / Login** with bcrypt password hashing (12 rounds)
- **Short-lived JWT access tokens** (15 min), returned in the response body
- **Long-lived refresh tokens**, stored in an `httpOnly` cookie
- **Refresh token rotation** — every refresh issues a new token and invalidates the old one
- **Theft detection** — reuse of a rotated (dead) refresh token revokes the entire session family
- **Rate limiting** on login (max 5 attempts / 15 min / IP)
- **Protected routes** via JWT-verifying middleware

## Tech stack

| Layer | Choice |
|---|---|
| Runtime | Node.js + Express |
| Database | MySQL 8.0 |
| Auth | JWT (`jsonwebtoken`) + `bcrypt` + `httpOnly` cookies |
| Rate limiting | `express-rate-limit` |

## Project structure
auth-service/
├── server.js # entry point
├── db/ # MySQL pool, schema, and query functions
├── controllers/ # route business logic
├── routes/ # Express route definitions
├── middleware/ # auth guard + rate limiter
└── utils/ # token helpers, input validators
## API endpoints

| Method | Route | Description |
|---|---|---|
| POST | `/api/auth/signup` | Create a new user (bcrypt hash, 12 rounds) |
| POST | `/api/auth/login` | Returns access token in JSON, refresh token in httpOnly cookie |
| POST | `/api/auth/refresh` | Rotates the refresh token |
| POST | `/api/auth/logout` | Invalidates the current refresh token |
| GET | `/api/me` | Protected route, returns current user data |

## Setup

1. Clone the repo and install dependencies:
```bash
   npm install
```
2. Create a MySQL database:
```sql
   CREATE DATABASE authforge;
```
3. Run the schema:
```bash
   mysql -u root -p authforge < db/schema.sql
```
4. Copy `.env.example` to `.env` and fill in your values:
DATABASE_URL=mysql://root:yourpassword@localhost:3306/authforge
ACCESS_TOKEN_SECRET=your_generated_secret
ACCESS_TOKEN_EXPIRY=15m
REFRESH_TOKEN_EXPIRY_DAYS=7
PORT=3000
5. Start the server:
```bash
   node server.js
```

## Status

🚧 Actively being built — see commit history for progress.
