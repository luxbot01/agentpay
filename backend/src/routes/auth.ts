import { Router, Request, Response } from 'express';
import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { z } from 'zod';
import { authenticate, generateApiKey, hashApiKey } from '../middleware/auth';
import { generateKeypair, encryptPrivateKey } from '../services/solana';
import { AppError } from '../middleware/errorHandler';
import { sendVerificationEmail, sendPasswordResetEmail, generateCode } from '../services/email';

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

  // Check existing email
  const existing = await prisma.user.findUnique({ where: { email } });
  if (existing) throw new AppError('Email already registered', 409, 'DUPLICATE_EMAIL');

  // Check unique display name
  const nameTaken = await prisma.user.findUnique({ where: { displayName } });
  if (nameTaken) throw new AppError('That username is already taken', 409, 'DUPLICATE_NAME');

  // Hash password
  const passwordHash = await bcrypt.hash(password, 12);

  // Generate Solana wallet
  const keypair = generateKeypair();
  const encryptedSecret = encryptPrivateKey(keypair.secretKey);

  // Create user + wallet in transaction
  const user = await prisma.user.create({
    data: {
      type: 'HUMAN',
      email,
      passwordHash,
      displayName,
      emailVerified: false,
      wallet: {
        create: {
          publicKey: keypair.publicKey.toBase58(),
          encryptedSecret,
        },
      },
    },
    include: { wallet: true },
  });

  // Generate verification code
  const code = generateCode();
  const codeHash = await bcrypt.hash(code, 10);

  await prisma.verificationCode.create({
    data: {
      userId: user.id,
      code: codeHash,
      type: 'EMAIL_VERIFY',
      expiresAt: new Date(Date.now() + 15 * 60 * 1000), // 15 minutes
    },
  });

  // Send verification email (don't block registration on email failure)
  try {
    await sendVerificationEmail(email, code);
  } catch (err) {
    console.error('Failed to send verification email:', err);
  }

  // Generate JWT
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
      emailVerified: false,
      walletAddress: user.wallet?.publicKey,
    },
    token,
    ...(process.env.NODE_ENV !== 'production' ? { devCode: code } : {}),
  });
});

// === VERIFY EMAIL ===
const verifyEmailSchema = z.object({
  code: z.string().length(6).regex(/^\d{6}$/),
});

authRouter.post('/verify-email', authenticate, async (req: Request, res: Response) => {
  const parsed = verifyEmailSchema.safeParse(req.body);
  if (!parsed.success) {
    throw new AppError('Invalid code format', 400, 'VALIDATION_ERROR');
  }

  const userId = req.user!.userId;
  const { code } = parsed.data;

  // Find unused, unexpired verification codes for this user
  const codes = await prisma.verificationCode.findMany({
    where: {
      userId,
      type: 'EMAIL_VERIFY',
      used: false,
      expiresAt: { gt: new Date() },
    },
    orderBy: { createdAt: 'desc' },
    take: 5,
  });

  // Check each code (bcrypt comparison)
  let matched = false;
  for (const stored of codes) {
    if (await bcrypt.compare(code, stored.code)) {
      matched = true;
      await prisma.verificationCode.update({
        where: { id: stored.id },
        data: { used: true },
      });
      break;
    }
  }

  if (!matched) {
    throw new AppError('Invalid or expired verification code', 400, 'INVALID_CODE');
  }

  await prisma.user.update({
    where: { id: userId },
    data: { emailVerified: true },
  });

  res.json({ message: 'Email verified successfully', emailVerified: true });
});

// === RESEND VERIFICATION CODE ===
authRouter.post('/resend-verification', authenticate, async (req: Request, res: Response) => {
  const userId = req.user!.userId;

  const user = await prisma.user.findUnique({ where: { id: userId } });
  if (!user || !user.email) throw new AppError('User not found', 404, 'NOT_FOUND');
  if (user.emailVerified) throw new AppError('Email already verified', 400, 'ALREADY_VERIFIED');

  // Rate limit: max 1 code per 60 seconds
  const recent = await prisma.verificationCode.findFirst({
    where: {
      userId,
      type: 'EMAIL_VERIFY',
      createdAt: { gt: new Date(Date.now() - 60 * 1000) },
    },
  });
  if (recent) throw new AppError('Please wait 60 seconds before requesting a new code', 429, 'RATE_LIMITED');

  const code = generateCode();
  const codeHash = await bcrypt.hash(code, 10);

  await prisma.verificationCode.create({
    data: {
      userId,
      code: codeHash,
      type: 'EMAIL_VERIFY',
      expiresAt: new Date(Date.now() + 15 * 60 * 1000),
    },
  });

  try {
    await sendVerificationEmail(user.email, code);
  } catch (err) {
    console.error('Failed to resend verification email:', err);
  }

  res.json({
    message: 'Verification code sent',
    ...(process.env.NODE_ENV !== 'production' ? { devCode: code } : {}),
  });
});

// === FORGOT PASSWORD ===
const forgotPasswordSchema = z.object({
  email: z.string().email(),
});

authRouter.post('/forgot-password', async (req: Request, res: Response) => {
  const parsed = forgotPasswordSchema.safeParse(req.body);
  if (!parsed.success) {
    throw new AppError('Invalid email', 400, 'VALIDATION_ERROR');
  }

  const { email } = parsed.data;

  // Always return success (don't leak whether email exists)
  const user = await prisma.user.findUnique({ where: { email } });

  if (user) {
    // Rate limit: max 1 code per 60 seconds
    const recent = await prisma.verificationCode.findFirst({
      where: {
        userId: user.id,
        type: 'PASSWORD_RESET',
        createdAt: { gt: new Date(Date.now() - 60 * 1000) },
      },
    });

    if (!recent) {
      const code = generateCode();
      const codeHash = await bcrypt.hash(code, 10);

      await prisma.verificationCode.create({
        data: {
          userId: user.id,
          code: codeHash,
          type: 'PASSWORD_RESET',
          expiresAt: new Date(Date.now() + 15 * 60 * 1000),
        },
      });

      try {
        await sendPasswordResetEmail(email, code);
      } catch (err) {
        console.error('Failed to send password reset email:', err);
      }

      // In dev mode, return the code directly
      if (process.env.NODE_ENV !== 'production') {
        return res.json({ message: 'Reset code sent', devCode: code });
      }
    }
  }

  // Always return success to prevent email enumeration
  res.json({ message: 'If an account exists with that email, a reset code has been sent' });
});


// === RESET PASSWORD ===
const resetPasswordSchema = z.object({
  email: z.string().email(),
  code: z.string().length(6).regex(/^\d{6}$/),
  newPassword: z.string().min(8),
});

authRouter.post('/reset-password', async (req: Request, res: Response) => {
  const parsed = resetPasswordSchema.safeParse(req.body);
  if (!parsed.success) {
    throw new AppError('Invalid input', 400, 'VALIDATION_ERROR');
  }

  const { email, code, newPassword } = parsed.data;

  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) throw new AppError('Invalid code', 400, 'INVALID_CODE');

  // Find unused, unexpired reset codes for this user
  const codes = await prisma.verificationCode.findMany({
    where: {
      userId: user.id,
      type: 'PASSWORD_RESET',
      used: false,
      expiresAt: { gt: new Date() },
    },
    orderBy: { createdAt: 'desc' },
    take: 5,
  });

  let matched = false;
  for (const stored of codes) {
    if (await bcrypt.compare(code, stored.code)) {
      matched = true;
      await prisma.verificationCode.update({
        where: { id: stored.id },
        data: { used: true },
      });
      break;
    }
  }

  if (!matched) {
    throw new AppError('Invalid or expired reset code', 400, 'INVALID_CODE');
  }

  const passwordHash = await bcrypt.hash(newPassword, 12);
  await prisma.user.update({
    where: { id: user.id },
    data: { passwordHash },
  });

  res.json({ message: 'Password reset successfully' });
});

// === AGENT REGISTRATION ===
const registerAgentSchema = z.object({
  displayName: z.string().min(1).max(50),
  dailyLimit: z.number().positive().optional(),
  txLimit: z.number().positive().optional(),
});

authRouter.post('/register/agent', async (req: Request, res: Response) => {
  const parsed = registerAgentSchema.safeParse(req.body);
  if (!parsed.success) {
    throw new AppError('Invalid input: ' + parsed.error.issues[0].message, 400, 'VALIDATION_ERROR');
  }

  const { dailyLimit, txLimit } = parsed.data;
  const displayName = parsed.data.displayName.replace(/^@/, '').trim();

  // Check unique display name
  const nameTaken = await prisma.user.findUnique({ where: { displayName } });
  if (nameTaken) throw new AppError('That username is already taken', 409, 'DUPLICATE_NAME');

  // Generate API key and wallet
  const apiKey = generateApiKey();
  const apiKeyHash = hashApiKey(apiKey);
  const keypair = generateKeypair();
  const encryptedSecret = encryptPrivateKey(keypair.secretKey);

  const user = await prisma.user.create({
    data: {
      type: 'AGENT',
      displayName,
      emailVerified: true, // Agents don't need email verification
      apiKey: apiKey.slice(0, 12) + '...', // store truncated for display only
      apiKeyHash,
      dailyLimit,
      txLimit,
      wallet: {
        create: {
          publicKey: keypair.publicKey.toBase58(),
          encryptedSecret,
        },
      },
    },
    include: { wallet: true },
  });

  // Return full API key ONCE (user must save it)
  res.status(201).json({
    user: {
      id: user.id,
      type: user.type,
      displayName: user.displayName,
      walletAddress: user.wallet?.publicKey,
    },
    apiKey, // ONLY returned once at creation
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

  const token = jwt.sign(
    { userId: user.id, type: 'HUMAN' },
    process.env.JWT_SECRET || 'change-me',
    { expiresIn: 86400 }
  );

  res.json({
    user: {
      id: user.id,
      type: user.type,
      email: user.email,
      displayName: user.displayName,
      emailVerified: user.emailVerified,
      walletAddress: user.wallet?.publicKey,
    },
    token,
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
