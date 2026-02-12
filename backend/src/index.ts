import 'express-async-errors';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import { WebSocketServer } from 'ws';
import { createServer } from 'http';
import dotenv from 'dotenv';

import { authRouter } from './routes/auth';
import { walletRouter } from './routes/wallet';
import { transferRouter } from './routes/transfer';
import { transactionRouter } from './routes/transaction';
import { webhookRouter } from './routes/webhook';
import { userRouter } from './routes/user';
import { bankRouter } from './routes/bank';
import { friendRouter } from './routes/friend';
import { errorHandler } from './middleware/errorHandler';
import { rateLimiter } from './middleware/rateLimiter';
import { setupWebSocket } from './services/websocket';

dotenv.config();

const app = express();
const server = createServer(app);
const PORT = process.env.PORT || 3001;

// Middleware
app.use(helmet());
app.use(cors({ origin: process.env.CORS_ORIGIN || 'http://localhost:5173' }));
app.use(express.json({ limit: '1mb' }));
app.use(rateLimiter);

// Health check
app.get('/health', (_req, res) => {
  res.json({ status: 'ok', service: 'agentpay-backend', version: '0.1.0' });
});

// Routes
app.use('/api/auth', authRouter);
app.use('/api/users', userRouter);
app.use('/api/wallets', walletRouter);
app.use('/api/transfers', transferRouter);
app.use('/api/transactions', transactionRouter);
app.use('/api/webhooks', webhookRouter);
app.use('/api/banks', bankRouter);
app.use('/api/friends', friendRouter);

// Error handler (must be last)
app.use(errorHandler);

// WebSocket for real-time transaction updates
const wss = new WebSocketServer({ server, path: '/ws' });
setupWebSocket(wss);

server.listen(PORT, () => {
  console.log(`AgentPay backend running on port ${PORT}`);
  console.log(`WebSocket available at ws://localhost:${PORT}/ws`);
  console.log(`Network: ${process.env.SOLANA_NETWORK || 'devnet'}`);
});

export { app, server };
