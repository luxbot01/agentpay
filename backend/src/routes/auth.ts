import 'express-async-errors';
import { Router, Request, Response } from 'express';
import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { z } from 'zod';
import { authenticate, generateApiKey, hashApiKey, requireHuman } from '../middleware/auth';
import { generateKeypair, encryptPrivateKey } from '../services/solana';
import { AppError } from '../middleware/errorHandler';
import { generateTotpSecret, verifyTotpToken, encryptSecret } from '../services/totp';

const prisma = new PrismaClient();
export const authRouter = Router();

// === HUMAN REGISTRATION ===
const registerHumanSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
  displayName: z.string().min(1).max(50),
});

authRouter.post('/register/human', async (req: Request, res: Response) => {
  const parsed = registerHumanSchema.safeParse(req.body);
  if (!parsed.success) {
    throw new AppError('Invalid input: ' + parsed.error.issues[0].message, 400, 'VALIDATION_ERROR');
  }

  const { email, password } = parsed.data;
  const displayName = parsed.data.displayName.replace(/^@/, '').trim();

  const existing = await prisma.user.findUnique({ where: { email } });
  if (existing) throw new AppError('Email already registered', 409, 'DUPLICATE_EMAIL');

  const nameTaken = await prisma.user.findUnique({ where: { displayName } });
  if (nameTaken) throw new AppError('That username is already taken', 409, 'DUPLICATE_NAME');

  const passwordHash = await bcrypt.hash(password, 12);
  const keypair = generateKeypair();
  const encryptedSecret = encryptPrivateKey(keypair.secretKey);

  const user = await prisma.user.create({
    data: {
      type: 'HUMAN',
      email,
      passwordHash,
      displayName,
      wallet: {
        create: {
          publicKey: keypair.publicKey.toBase58(),
          encryptedSecret,
        },
      },
    },
    include: { wallet: true },
  });

  const token = jwt.sign(
    { userId: user.id, type: 'HUMAN' },
    process.env.JWT_SECRET || 'change-me',
    { expiresIn: 86400 }
  );

  res.status(201).json({
    user: {
      id: user.id,
      type: user.type,
      email: user.email,
      displayName: user.displayName,
      walletAddress: user.wallet?.publicKey,
    },
    token,
    requiresTotpSetup: true,
  });
});

// === GENERATE AGENT PAIRING TOKEN (human only) ===
const createPairingSchema = z.object({
  agentName: z.string().min(1).max(50).optional(),
  dailyLimit: z.number().positive().optional(),
  txLimit: z.number().positive().optional(),
});

authRouter.post('/agents/pairing-token', authenticate, requireHuman, async (req: Request, res: Response) => {
  const parsed = createPairingSchema.safeParse(req.body);
  if (!parsed.success) {
    throw new AppError('Invalid input: ' + parsed.error.issues[0].message, 400, 'VALIDATION_ERROR');
  }

  const { agentName, dailyLimit, txLimit } = parsed.data;
  const token = crypto.randomBytes(32).toString('hex');

  const pairingToken = await prisma.pairingToken.create({
    data: {
      token,
      userId: req.user!.userId,
      agentName: agentName?.replace(/^@/, '').trim(),
      dailyLimit,
      txLimit,
      expiresAt: new Date(Date.now() + 15 * 60 * 1000), // 15 minutes
    },
  });

  res.status(201).json({
    pairingToken: token,
    expiresAt: pairingToken.expiresAt,
    message: 'Give this token to your AI agent. It expires in 15 minutes and can only be used once.',
  });
});

// === LIST MY AGENTS (human only) ===
authRouter.get('/agents', authenticate, requireHuman, async (req: Request, res: Response) => {
  const agents = await prisma.user.findMany({
    where: { parentUserId: req.user!.userId, type: 'AGENT' },
    include: { wallet: true },
    orderBy: { createdAt: 'desc' },
  });

  res.json({
    agents: agents.map((a) => ({
      id: a.id,
      displayName: a.displayName,
      walletAddress: a.wallet?.publicKey,
      dailyLimit: a.dailyLimit,
      txLimit: a.txLimit,
      createdAt: a.createdAt,
    })),
  });
});

// === REVOKE AGENT (human only) ===
authRouter.delete('/agents/:agentId', authenticate, requireHuman, async (req: Request, res: Response) => {
  const agentId = String(req.params.agentId);

  const agent = await prisma.user.findUnique({ where: { id: agentId } });
  if (!agent || agent.parentUserId !== req.user!.userId) {
    throw new AppError('Agent not found or not owned by you', 404, 'NOT_FOUND');
  }

  // Invalidate the agent's API key
  await prisma.user.update({
    where: { id: agentId },
    data: { apiKey: null, apiKeyHash: null },
  });

  res.json({ message: `Agent @${agent.displayName} has been revoked.` });
});

// === AGENT REGISTRATION (requires pairing token) ===
const registerAgentSchema = z.object({
  pairingToken: z.string().min(1),
  displayName: z.string().min(1).max(50).optional(),
});

authRouter.post('/register/agent', async (req: Request, res: Response) => {
  const parsed = registerAgentSchema.safeParse(req.body);
  if (!parsed.success) {
    throw new AppError('Invalid input: ' + parsed.error.issues[0].message, 400, 'VALIDATION_ERROR');
  }

  const { pairingToken } = parsed.data;

  // Validate pairing token
  const tokenRecord = await prisma.pairingToken.findUnique({ where: { token: pairingToken } });
  if (!tokenRecord) throw new AppError('Invalid pairing token', 401, 'INVALID_TOKEN');
  if (tokenRecord.used) throw new AppError('Pairing token already used', 401, 'TOKEN_USED');
  if (tokenRecord.expiresAt < new Date()) throw new AppError('Pairing token expired', 401, 'TOKEN_EXPIRED');

  // Use agent name from token or from request body
  const displayName = (parsed.data.displayName || tokenRecord.agentName || `agent-${Date.now()}`).replace(/^@/, '').trim();

  const nameTaken = await prisma.user.findUnique({ where: { displayName } });
  if (nameTaken) throw new AppError('That username is already taken', 409, 'DUPLICATE_NAME');

  const apiKey = generateApiKey();
  const apiKeyHash = hashApiKey(apiKey);
  const keypair = generateKeypair();
  const encryptedSecret = encryptPrivateKey(keypair.secretKey);

  // Mark token as used and create agent in one transaction
  const [, user] = await prisma.$transaction([
    prisma.pairingToken.update({
      where: { id: tokenRecord.id },
      data: { used: true },
    }),
    prisma.user.create({
      data: {
        type: 'AGENT',
        displayName,
        apiKey: apiKey.slice(0, 12) + '...',
        apiKeyHash,
        parentUserId: tokenRecord.userId, // link to human owner
        dailyLimit: tokenRecord.dailyLimit,
        txLimit: tokenRecord.txLimit,
        wallet: {
          create: {
            publicKey: keypair.publicKey.toBase58(),
            encryptedSecret,
          },
        },
      },
      include: { wallet: true },
    }),
  ]);

  res.status(201).json({
    user: {
      id: user.id,
      type: user.type,
      displayName: user.displayName,
      walletAddress: user.wallet?.publicKey,
      parentUserId: tokenRecord.userId,
    },
    apiKey,
    warning: 'Save this API key now. It cannot be retrieved later.',
  });
});

// === HUMAN LOGIN ===
const loginSchema = z.object({
  email: z.string().email(),
  password: z.string(),
});

authRouter.post('/login', async (req: Request, res: Response) => {
  const parsed = loginSchema.safeParse(req.body);
  if (!parsed.success) {
    throw new AppError('Invalid input', 400, 'VALIDATION_ERROR');
  }

  const { email, password } = parsed.data;

  const user = await prisma.user.findUnique({
    where: { email },
    include: { wallet: true },
  });

  if (!user || !user.passwordHash) {
    throw new AppError('Invalid credentials', 401, 'INVALID_CREDENTIALS');
  }

  const valid = await bcrypt.compare(password, user.passwordHash);
  if (!valid) {
    throw new AppError('Invalid credentials', 401, 'INVALID_CREDENTIALS');
  }

  if (!user.totpEnabled) {
    // First login or 2FA not set up yet — issue token for setup only
    const token = jwt.sign(
      { userId: user.id, type: 'HUMAN' },
      process.env.JWT_SECRET || 'change-me',
      { expiresIn: 86400 }
    );

    return res.json({
      requiresTotpSetup: true,
      token,
      user: {
        id: user.id,
        type: user.type,
        email: user.email,
        displayName: user.displayName,
        walletAddress: user.wallet?.publicKey,
      },
    });
  }

  // 2FA enabled — issue short-lived temp token, require TOTP code
  const tempToken = jwt.sign(
    { userId: user.id, type: 'HUMAN', temp2fa: true },
    process.env.JWT_SECRET || 'change-me',
    { expiresIn: 300 } // 5 minutes
  );

  res.json({ requiresTotpCode: true, tempToken });
});

// === TOTP SETUP (generate QR code) ===
authRouter.post('/totp/setup', authenticate, async (req: Request, res: Response) => {
  const userId = req.user!.userId;

  const user = await prisma.user.findUnique({ where: { id: userId } });
  if (!user || !user.email) throw new AppError('User not found', 404, 'NOT_FOUND');

  if (user.totpEnabled) {
    throw new AppError('2FA is already enabled', 400, 'TOTP_ALREADY_ENABLED');
  }

  const { secret, qrCodeDataUrl } = await generateTotpSecret(user.email);

  // Store encrypted secret (not enabled yet — user must verify first)
  const encrypted = encryptSecret(secret);
  await prisma.user.update({
    where: { id: userId },
    data: { totpSecret: encrypted, totpEnabled: false },
  });

  res.json({
    qrCodeDataUrl,
    secret, // text secret for manual entry
    message: 'Scan this QR code with Google Authenticator, then verify with a code',
  });
});

// === TOTP VERIFY (both setup confirmation and login verification) ===
const totpVerifySchema = z.object({
  code: z.string().length(6).regex(/^\d{6}$/),
  tempToken: z.string().optional(),
});

authRouter.post('/totp/verify', async (req: Request, res: Response) => {
  const parsed = totpVerifySchema.safeParse(req.body);
  if (!parsed.success) {
    throw new AppError('Invalid code format', 400, 'VALIDATION_ERROR');
  }

  const { code, tempToken } = parsed.data;

  let userId: string;
  let isSetupFlow = false;

  if (tempToken) {
    // Login flow — verify the temp token
    try {
      const decoded = jwt.verify(tempToken, process.env.JWT_SECRET || 'change-me') as any;
      if (!decoded.temp2fa) throw new Error('Not a 2FA token');
      userId = decoded.userId;
    } catch {
      throw new AppError('Token expired or invalid — please log in again', 401, 'INVALID_TOKEN');
    }
  } else {
    // Setup flow — use regular auth header
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith('Bearer ')) {
      throw new AppError('Missing authorization', 401, 'UNAUTHORIZED');
    }
    const token = authHeader.replace('Bearer ', '');
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET || 'change-me') as any;
      userId = decoded.userId;
      isSetupFlow = true;
    } catch {
      throw new AppError('Invalid token', 401, 'INVALID_TOKEN');
    }
  }

  const user = await prisma.user.findUnique({
    where: { id: userId },
    include: { wallet: true },
  });

  if (!user || !user.totpSecret) {
    throw new AppError('2FA not configured — please set up first', 400, 'TOTP_NOT_CONFIGURED');
  }

  const isValid = verifyTotpToken(user.totpSecret, code);
  if (!isValid) {
    throw new AppError('Invalid or expired code', 400, 'INVALID_TOTP');
  }

  // If setup flow, enable TOTP
  if (isSetupFlow && !user.totpEnabled) {
    await prisma.user.update({
      where: { id: userId },
      data: { totpEnabled: true },
    });
  }

  // Issue full session token
  const fullToken = jwt.sign(
    { userId: user.id, type: 'HUMAN' },
    process.env.JWT_SECRET || 'change-me',
    { expiresIn: 86400 }
  );

  res.json({
    token: fullToken,
    user: {
      id: user.id,
      type: user.type,
      email: user.email,
      displayName: user.displayName,
      totpEnabled: true,
      walletAddress: user.wallet?.publicKey,
    },
    message: isSetupFlow ? '2FA setup complete' : 'Login successful',
  });
});

// === ROTATE AGENT API KEY ===
authRouter.post('/rotate-key', authenticate, async (req: Request, res: Response) => {
  if (!req.user || req.user.type !== 'AGENT') {
    throw new AppError('Only agents can rotate API keys', 403, 'FORBIDDEN');
  }

  const newApiKey = generateApiKey();
  const newHash = hashApiKey(newApiKey);

  await prisma.user.update({
    where: { id: req.user.userId },
    data: {
      apiKey: newApiKey.slice(0, 12) + '...',
      apiKeyHash: newHash,
    },
  });

  res.json({
    apiKey: newApiKey,
    warning: 'Save this API key now. The old key is now invalid.',
  });
});
