# AgentPay API — Agent Skill Reference

> **Base URL:** `http://localhost:3001/api`
> **Auth:** Bearer token (API key from registration)

---

## Quick Start

Agents must be paired with a human account before they can register. The human generates a one-time pairing token from their dashboard, then gives it to the agent.

```bash
# 1. Register your agent (requires pairing token from human owner)
curl -X POST http://localhost:3001/api/auth/register/agent \
  -H "Content-Type: application/json" \
  -d '{"pairingToken": "abc123...", "displayName": "my-agent"}'

# Response: { "user": {...}, "apiKey": "agentpay_abc123..." }
# SAVE THIS KEY — it cannot be retrieved later.

# 2. Check your balance
curl http://localhost:3001/api/wallets/me \
  -H "Authorization: Bearer agentpay_abc123..."

# 3. Send money to another user
curl -X POST http://localhost:3001/api/transfers/send \
  -H "Authorization: Bearer agentpay_abc123..." \
  -H "Content-Type: application/json" \
  -d '{"toUsername": "alice", "amount": 5.00, "memo": "Payment for API usage"}'
```

---

## Authentication

All requests require a Bearer token in the `Authorization` header:

```
Authorization: Bearer agentpay_<your-api-key>
```

API keys are generated at registration and can be rotated (see below). The old key is invalidated immediately on rotation.

### Agent Pairing Flow

Agents cannot self-register. A human must initiate the pairing:

1. Human calls `POST /auth/agents/pairing-token` (requires human JWT auth)
2. Human gives the returned token to the agent
3. Agent calls `POST /auth/register/agent` with the pairing token
4. Agent is linked to the human account with spending limits set by the human
5. Human can list agents (`GET /auth/agents`) and revoke access (`DELETE /auth/agents/:id`)

---

## Endpoints

### Generate Pairing Token (Human Only)

```
POST /auth/agents/pairing-token
```

Requires human JWT auth. Creates a one-time pairing token for agent registration.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `agentName` | string | No | Pre-set @username for the agent |
| `dailyLimit` | number | No | Max USDC spend per day |
| `txLimit` | number | No | Max USDC per transaction |

**Response (201):**
```json
{
  "pairingToken": "a1b2c3...",
  "expiresAt": "2026-02-13T01:15:00.000Z",
  "message": "Give this token to your AI agent. It expires in 15 minutes."
}
```

### Register Agent

```
POST /auth/register/agent
```

No auth required, but requires a valid pairing token from a human account.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `pairingToken` | string | Yes | One-time token from human owner |
| `displayName` | string | No | Unique @username (uses token's agentName if omitted) |

```bash
curl -X POST http://localhost:3001/api/auth/register/agent \
  -H "Content-Type: application/json" \
  -d '{"pairingToken": "a1b2c3...", "displayName": "my-agent"}'
```

**Response (201):**
```json
{
  "user": {
    "id": "uuid",
    "type": "AGENT",
    "displayName": "my-agent",
    "walletAddress": "So1ana...",
    "parentUserId": "human-uuid"
  },
  "apiKey": "agentpay_abc123...",
  "warning": "Save this API key now. It cannot be retrieved later."
}
```

### List My Agents (Human Only)

```
GET /auth/agents
```

Returns all agents linked to the authenticated human.

### Revoke Agent (Human Only)

```
DELETE /auth/agents/:agentId
```

Invalidates the agent's API key. The agent can no longer authenticate.

---

### Check Balance

```
GET /wallets/me
```

Returns your Solana wallet balance.

```bash
curl http://localhost:3001/api/wallets/me \
  -H "Authorization: Bearer agentpay_abc123..."
```

**Response (200):**
```json
{
  "publicKey": "So1ana...",
  "usdcBalance": 42.50,
  "solBalance": 0.5,
  "isActive": true
}
```

---

### Send Money

```
POST /transfers/send
```

Send USDC to another user. Specify the recipient by **one** of: `toUserId`, `toUsername`, or `toWalletAddress`.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `toUserId` | string (UUID) | One of three | Recipient user ID |
| `toUsername` | string | One of three | Recipient @username |
| `toWalletAddress` | string | One of three | Solana wallet address |
| `amount` | number | Yes | USDC amount (max 1,000,000) |
| `memo` | string | No | Note (max 500 chars) |
| `metadata` | object | No | Custom key-value data |

```bash
# Send by @username
curl -X POST http://localhost:3001/api/transfers/send \
  -H "Authorization: Bearer agentpay_abc123..." \
  -H "Content-Type: application/json" \
  -d '{"toUsername": "alice", "amount": 10.00, "memo": "Thanks!"}'

# Send by user ID
curl -X POST http://localhost:3001/api/transfers/send \
  -H "Authorization: Bearer agentpay_abc123..." \
  -H "Content-Type: application/json" \
  -d '{"toUserId": "uuid-here", "amount": 5.00}'

# Send by wallet address
curl -X POST http://localhost:3001/api/transfers/send \
  -H "Authorization: Bearer agentpay_abc123..." \
  -H "Content-Type: application/json" \
  -d '{"toWalletAddress": "So1anaAddress...", "amount": 25.00}'
```

**Response (201):**
```json
{
  "transaction": {
    "id": "uuid",
    "type": "TRANSFER",
    "status": "CONFIRMED",
    "amount": 10.00,
    "fee": 0,
    "fromWallet": "So1ana...",
    "toWallet": "So1ana...",
    "solanaSignature": "5K7x...",
    "memo": "Thanks!",
    "createdAt": "2026-02-12T...",
    "confirmedAt": "2026-02-12T..."
  }
}
```

---

### Request Payment

```
POST /transfers/request
```

Request money from another user. Creates a pending transaction.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `fromUserId` | string (UUID) | Yes | User to request from |
| `amount` | number | Yes | USDC amount (max 1,000,000) |
| `memo` | string | No | Note (max 500 chars) |

```bash
curl -X POST http://localhost:3001/api/transfers/request \
  -H "Authorization: Bearer agentpay_abc123..." \
  -H "Content-Type: application/json" \
  -d '{"fromUserId": "uuid-here", "amount": 15.00, "memo": "Invoice #42"}'
```

**Response (201):**
```json
{
  "request": {
    "id": "uuid",
    "amount": 15.00,
    "from": { "id": "uuid", "displayName": "bob" },
    "memo": "Invoice #42",
    "status": "PENDING",
    "createdAt": "2026-02-12T..."
  }
}
```

---

### Transaction History

```
GET /transactions
```

Returns paginated transaction history.

| Query Param | Type | Default | Description |
|-------------|------|---------|-------------|
| `page` | int | 1 | Page number |
| `limit` | int | 20 | Results per page (max 100) |
| `type` | string | all | Filter: `DEPOSIT`, `WITHDRAW`, `TRANSFER` |
| `status` | string | all | Filter: `PENDING`, `CONFIRMED`, `FAILED`, `CANCELLED` |
| `direction` | string | all | Filter: `sent`, `received`, `all` |

```bash
curl "http://localhost:3001/api/transactions?limit=5&direction=sent" \
  -H "Authorization: Bearer agentpay_abc123..."
```

**Response (200):**
```json
{
  "transactions": [
    {
      "id": "uuid",
      "type": "TRANSFER",
      "status": "CONFIRMED",
      "amount": 10.00,
      "sender": { "id": "uuid", "displayName": "my-agent", "type": "AGENT" },
      "receiver": { "id": "uuid", "displayName": "alice", "type": "HUMAN" },
      "direction": "sent",
      "memo": "Thanks!",
      "createdAt": "2026-02-12T..."
    }
  ],
  "pagination": { "page": 1, "limit": 5, "total": 12, "totalPages": 3 }
}
```

---

### Get Single Transaction

```
GET /transactions/:id
```

```bash
curl http://localhost:3001/api/transactions/uuid-here \
  -H "Authorization: Bearer agentpay_abc123..."
```

---

### Search Users

```
GET /users/search/query
```

| Query Param | Type | Required | Description |
|-------------|------|----------|-------------|
| `q` | string | Yes | Search term (1-100 chars) |
| `type` | string | No | Filter: `HUMAN` or `AGENT` |
| `limit` | int | No | Max results (default 10, max 50) |

```bash
curl "http://localhost:3001/api/users/search/query?q=alice&type=HUMAN" \
  -H "Authorization: Bearer agentpay_abc123..."
```

**Response (200):**
```json
{
  "users": [
    {
      "id": "uuid",
      "displayName": "alice",
      "type": "HUMAN",
      "walletAddress": "So1ana..."
    }
  ]
}
```

---

### Lookup User by ID

```
GET /users/:id
```

Returns public info about any user.

```bash
curl http://localhost:3001/api/users/uuid-here \
  -H "Authorization: Bearer agentpay_abc123..."
```

---

### Rotate API Key

```
POST /auth/rotate-key
```

Generates a new API key. The old key is immediately invalidated.

```bash
curl -X POST http://localhost:3001/api/auth/rotate-key \
  -H "Authorization: Bearer agentpay_abc123..."
```

**Response (200):**
```json
{
  "apiKey": "agentpay_new_key_here...",
  "warning": "Save this API key now. The old key is now invalid."
}
```

---

## What Agents CAN Do

- Register an account (no email required)
- Send USDC to any user (by @username, user ID, or wallet address)
- Request payment from any user
- Check their own balance
- View their transaction history
- Search for other users
- Rotate their API key
- Set spending limits at registration

## What Agents CANNOT Do

- Deposit funds (human dashboard only, requires 2FA)
- Withdraw to external wallets (human dashboard only, requires 2FA)
- Connect or manage bank accounts (human only)
- Change profile settings (display name, limits)
- Access any banking information
- Airdrop devnet SOL (human only)

---

## Spending Limits

Agents can have two types of limits (set at registration):

- **`txLimit`** — Maximum USDC per single transaction. Transfers exceeding this are rejected with `TX_LIMIT_EXCEEDED`.
- **`dailyLimit`** — Maximum total USDC sent per calendar day. Rejected with `DAILY_LIMIT_EXCEEDED` when exceeded.

Both are optional. If not set, there is no limit.

---

## Error Codes

All errors return JSON: `{ "error": "message", "code": "CODE" }`

| Code | HTTP | Description |
|------|------|-------------|
| `VALIDATION_ERROR` | 400 | Invalid input (check field formats) |
| `INSUFFICIENT_BALANCE` | 400 | Not enough USDC |
| `SELF_TRANSFER` | 400 | Cannot send money to yourself |
| `INVALID_CREDENTIALS` | 401 | Wrong API key |
| `UNAUTHORIZED` | 401 | Missing or expired token |
| `HUMAN_ONLY` | 403 | Endpoint restricted to human users |
| `TX_LIMIT_EXCEEDED` | 403 | Amount exceeds per-transaction limit |
| `DAILY_LIMIT_EXCEEDED` | 403 | Daily spending limit reached |
| `USER_NOT_FOUND` | 404 | User or @username not found |
| `WALLET_NOT_FOUND` | 404 | Wallet not found |
| `RECEIVER_NOT_FOUND` | 404 | Recipient not found |
| `DUPLICATE_NAME` | 409 | Username already taken |
| `TRANSFER_FAILED` | 500 | On-chain transfer failed |

---

## WebSocket (Real-time Events)

Connect to receive transaction notifications:

```
ws://localhost:3001/ws?token=agentpay_abc123...
```

Events are JSON messages:

```json
{
  "event": "transaction.confirmed",
  "data": {
    "transactionId": "uuid",
    "amount": 10.00,
    "direction": "received"
  }
}
```

Event types: `transaction.confirmed`, `transaction.failed`, `transaction.pending`

---

## Webhooks

Register a URL to receive HTTP POST callbacks for events.

```bash
# Create webhook
curl -X POST http://localhost:3001/api/webhooks \
  -H "Authorization: Bearer agentpay_abc123..." \
  -H "Content-Type: application/json" \
  -d '{"url": "https://your-server.com/webhook", "events": ["transaction.confirmed"]}'

# Response includes HMAC secret for signature verification
```

Webhook payloads are signed with HMAC-SHA256. Verify using the `X-AgentPay-Signature` header.

---

## Python Example

```python
import requests

BASE = "http://localhost:3001/api"
API_KEY = "agentpay_your_key_here"
HEADERS = {
    "Authorization": f"Bearer {API_KEY}",
    "Content-Type": "application/json"
}

# Check balance
balance = requests.get(f"{BASE}/wallets/me", headers=HEADERS).json()
print(f"Balance: {balance['usdcBalance']} USDC")

# Send payment
tx = requests.post(f"{BASE}/transfers/send", headers=HEADERS, json={
    "toUsername": "alice",
    "amount": 5.00,
    "memo": "Payment for services"
}).json()
print(f"Sent! TX: {tx['transaction']['id']}")

# Check history
history = requests.get(f"{BASE}/transactions?limit=5", headers=HEADERS).json()
for tx in history["transactions"]:
    print(f"  {tx['direction']}: {tx['amount']} USDC - {tx['memo']}")
```
