# AgentPay

**Venmo for AI Agents** — A peer-to-peer payment platform where AI agents and humans transact seamlessly on Solana.

AgentPay enables AI agents to send, receive, and request USDC payments through a simple API, while humans maintain full control through a polished web dashboard. Bank account details are encrypted at rest (AES-256-CBC) and never exposed to agents.

## Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌──────────────┐
│  Human Frontend │────▶│  Express API    │────▶│  Solana      │
│  (React + Vite) │     │  (TypeScript)   │     │  (Devnet)    │
└─────────────────┘     │                 │     │  USDC SPL    │
                        │  JWT + API Key  │     └──────────────┘
┌─────────────────┐     │  Dual Auth      │     ┌──────────────┐
│  Agent SDK      │────▶│                 │────▶│  SQLite      │
│  (REST API)     │     │  WebSocket +    │     │  (Prisma)    │
└─────────────────┘     │  Webhooks       │     └──────────────┘
                        └─────────────────┘
```

## Features

- **Dual Authentication** — JWT for humans, API keys (`agentpay_` prefix) for agents
- **Solana USDC Transfers** — On-chain SPL token transfers with auto ATA creation
- **Spending Controls** — Per-transaction and daily limits for agents
- **Bank Encryption** — Full account/routing numbers encrypted with AES-256-CBC, separate key derivation from wallet keys
- **Real-time Notifications** — WebSocket events + HMAC-signed webhook callbacks
- **Friend System** — Send/accept/decline friend requests, send money by @username
- **Email Verification** — 6-digit codes via Resend API, bcrypt-hashed in DB
- **Password Reset** — Forgot password flow with rate-limited code generation
- **Demo Mode** — Dev-only endpoints for testing transfers without blockchain

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | React 18, Vite, Tailwind CSS v4, TypeScript |
| Backend | Express 4, TypeScript, Prisma ORM |
| Database | SQLite (dev), PostgreSQL-ready |
| Blockchain | Solana Web3.js, SPL Token |
| Auth | JWT (humans), SHA-256 hashed API keys (agents) |
| Email | Resend API |
| Security | AES-256-CBC encryption, bcrypt, helmet, rate limiting |
| Real-time | WebSocket (ws), HMAC-SHA256 webhooks |

## Quick Start

### Prerequisites
- Node.js 18+
- npm

### Backend
```bash
cd backend
cp .env.example .env
npm install
npx prisma db push
npx ts-node src/index.ts
```
Backend runs on `http://localhost:3001`

### Frontend
```bash
cd frontend
npm install
npm run dev
```
Frontend runs on `http://localhost:5173`

## API Endpoints

### Auth
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/register/human` | Register human account + Solana wallet |
| POST | `/api/auth/register/agent` | Register agent + API key |
| POST | `/api/auth/login` | Login (returns JWT) |
| POST | `/api/auth/verify-email` | Verify 6-digit email code |
| POST | `/api/auth/forgot-password` | Request password reset code |
| POST | `/api/auth/reset-password` | Reset password with code |

### Transfers
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/transfers/send` | Send USDC (by userId, @username, or wallet address) |
| POST | `/api/transfers/request` | Request payment from another user |
| POST | `/api/transfers/withdraw` | Withdraw to external Solana wallet |

### Wallets & Transactions
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/wallets/me` | Get balance (USDC + SOL) |
| POST | `/api/wallets/airdrop` | Devnet SOL airdrop |
| GET | `/api/transactions` | Paginated transaction history |

### Social
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/friends` | List accepted friends |
| POST | `/api/friends` | Send friend request |
| POST | `/api/friends/:id/accept` | Accept friend request |
| GET | `/api/users/search/query` | Search users by @name |

### Banking
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/banks` | Connect bank (encrypted at rest) |
| GET | `/api/banks` | List banks (last 4 digits only) |

## Security Model

1. **Agent Isolation** — Agents authenticate via API keys and can only access wallet/transfer endpoints. They never see bank account details, emails, or password hashes.
2. **Bank Encryption** — Account and routing numbers are AES-256-CBC encrypted with a separate key derivation (different salt from Solana wallet encryption) for defense in depth.
3. **Wallet Security** — Solana private keys are AES-256-CBC encrypted at rest. Keys are decrypted only at the moment of transaction signing.
4. **Input Validation** — Zod schemas on every endpoint. Express-async-errors catches all thrown errors.
5. **Rate Limiting** — 60 requests/minute per IP via rate-limiter-flexible.

## Built By

This project was built entirely by AI agents as part of the [Colosseum Agent Hackathon](https://colosseum.com/agent-hackathon):
- **LuxCode** (Claude Opus 4.6) — Backend architecture, API design, security, Solana integration
- **LuxClaw** (Kimi K2.5) — Frontend UI, visual QA, component design

No human-written code. Humans provided design direction and testing feedback.

## License

MIT
