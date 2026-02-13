# AgentPay

**Venmo for AI Agents** — A peer-to-peer USDC payment platform on Solana where AI agents transact autonomously while humans maintain full financial control.

## Live Demo

- **Frontend:** https://luxbot01.github.io/agentpay/
- **Backend API:** https://agentpay-backend.onrender.com
- **Agent API Docs:** [SKILL.md](./SKILL.md)

## Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌──────────────┐
│  Human Frontend │────▶│  Express API    │────▶│  Solana      │
│  (React + Vite) │     │  (TypeScript)   │     │  (Devnet)    │
└─────────────────┘     │                 │     │  USDC SPL    │
                        │  JWT + API Key  │     └──────────────┘
┌─────────────────┐     │  Dual Auth      │     ┌──────────────┐
│  AI Agents      │────▶│                 │────▶│  PostgreSQL  │
│  (REST API)     │     │  WebSocket +    │     │  (Prisma)    │
└─────────────────┘     │  Webhooks       │     └──────────────┘
                        └─────────────────┘
```

## Features

- **Dual Authentication** — JWT + TOTP 2FA for humans, SHA-256 hashed API keys for agents
- **Agent Pairing** — Human-initiated one-time tokens link agents to owner accounts with preset spending limits
- **Solana USDC Transfers** — On-chain SPL token transfers with automatic ATA creation
- **Payment Requests** — Request money from other users with accept/dismiss flow
- **Spending Controls** — Per-transaction and daily limits enforced server-side
- **Bank Encryption** — Full account/routing numbers AES-256-CBC encrypted, separate key derivation from wallet keys
- **Agent Isolation** — `requireHuman` middleware blocks agents from deposit, withdrawal, bank, and settings endpoints
- **Real-time Notifications** — WebSocket events + HMAC-signed webhook callbacks
- **Friend System** — Send/accept/decline friend requests, send money by @username
- **Demo Mode** — Dev-only endpoints for testing transfers without blockchain

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | React 18, Vite, Tailwind CSS v4, TypeScript |
| Backend | Express 4, TypeScript, Prisma ORM |
| Database | PostgreSQL (production), SQLite (dev) |
| Blockchain | Solana Web3.js, SPL Token |
| Auth | JWT + TOTP 2FA (humans), SHA-256 hashed API keys (agents) |
| Security | AES-256-CBC encryption, bcrypt, helmet, rate limiting |
| Real-time | WebSocket (ws), HMAC-SHA256 webhooks |
| Deployment | GitHub Pages (frontend), Render (backend) |

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
npx tsx src/index.ts
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

### Auth & Agent Pairing
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/register/human` | Register human account + Solana wallet |
| POST | `/api/auth/login` | Login (returns JWT or requires TOTP) |
| POST | `/api/auth/totp/setup` | Generate QR code for 2FA setup |
| POST | `/api/auth/totp/verify` | Verify TOTP code (setup or login) |
| POST | `/api/auth/agents/pairing-token` | Generate one-time agent pairing token (human only) |
| POST | `/api/auth/register/agent` | Register agent with pairing token |
| GET | `/api/auth/agents` | List linked agents (human only) |
| DELETE | `/api/auth/agents/:id` | Revoke agent access (human only) |

### Transfers
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/transfers/send` | Send USDC (by userId, @username, or wallet address) |
| POST | `/api/transfers/request` | Request payment from another user |
| GET | `/api/transfers/requests/incoming` | List incoming payment requests |
| POST | `/api/transfers/requests/:id/accept` | Accept and pay a request |
| POST | `/api/transfers/requests/:id/dismiss` | Dismiss a request |
| POST | `/api/transfers/withdraw` | Withdraw to external Solana wallet (human only) |

### Wallets & Transactions
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/wallets/me` | Get balance (USDC + SOL) |
| POST | `/api/wallets/deposit` | Demo deposit (human only) |
| POST | `/api/wallets/airdrop` | Devnet SOL airdrop (human only) |
| GET | `/api/transactions` | Paginated transaction history |

### Social
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/friends` | List accepted friends |
| POST | `/api/friends` | Send friend request |
| POST | `/api/friends/:id/accept` | Accept friend request |
| GET | `/api/users/search/query` | Search users by @name |

### Banking (Human Only)
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/banks` | Connect bank (encrypted at rest) |
| GET | `/api/banks` | List banks (last 4 digits only) |

## Security Model

1. **Agent Pairing** — Agents cannot self-register. Humans generate one-time pairing tokens (15-min expiry) that link agents to their account with preset spending limits.
2. **TOTP 2FA** — Human accounts use Google Authenticator for two-factor authentication. No password reset exists — the authenticator IS the second factor.
3. **Agent Isolation** — `requireHuman` middleware blocks agents from deposit, withdrawal, bank account, and settings endpoints at the routing layer.
4. **Bank Encryption** — Account and routing numbers are AES-256-CBC encrypted with a separate key derivation (different salt from Solana wallet encryption) for defense in depth.
5. **Wallet Security** — Solana private keys are AES-256-CBC encrypted at rest. Keys are decrypted only at the moment of transaction signing.
6. **Input Validation** — Zod schemas on every endpoint. Express-async-errors catches all thrown errors.
7. **Rate Limiting** — 60 requests/minute per IP via rate-limiter-flexible.

## Built By

This project was built entirely by AI agents as part of the [Colosseum Agent Hackathon](https://colosseum.com/agent-hackathon):
- **LuxCode** (Claude Opus 4.6) — Backend architecture, API design, security, Solana integration
- **LuxClaw** (Kimi K2.5) — Frontend UI, visual QA, component design, deployment

No human-written code. Humans provided design direction and testing feedback.

## License

MIT
