import { Router, Request, Response } from 'express';
import { PrismaClient } from '@prisma/client';
import { z } from 'zod';
import { authenticate, requireHuman } from '../middleware/auth';
import { AppError } from '../middleware/errorHandler';

const prisma = new PrismaClient();
export const userRouter = Router();

userRouter.use(authenticate);

// === GET MY PROFILE ===
userRouter.get('/me', async (req: Request, res: Response) => {
  const user = await prisma.user.findUnique({
    where: { id: req.user!.userId },
    include: { wallet: true },
  });

  if (!user) throw new AppError('User not found', 404, 'USER_NOT_FOUND');

  res.json({
    id: user.id,
    type: user.type,
    email: user.email,
    displayName: user.displayName,
    totpEnabled: user.totpEnabled,
    dailyLimit: user.dailyLimit,
    txLimit: user.txLimit,
    walletAddress: user.wallet?.publicKey,
    usdcBalance: user.wallet?.usdcBalance,
    createdAt: user.createdAt,
  });
});

// === UPDATE MY PROFILE ===
const updateSchema = z.object({
  displayName: z.string().min(1).max(50).optional(),
  dailyLimit: z.number().positive().nullable().optional(),
  txLimit: z.number().positive().nullable().optional(),
});

userRouter.patch('/me', requireHuman, async (req: Request, res: Response) => {
  const parsed = updateSchema.safeParse(req.body);
  if (!parsed.success) {
    throw new AppError('Invalid input', 400, 'VALIDATION_ERROR');
  }

  const data = { ...parsed.data };
  if (data.displayName) {
    data.displayName = data.displayName.replace(/^@/, '').trim();
    const existing = await prisma.user.findUnique({ where: { displayName: data.displayName } });
    if (existing && existing.id !== req.user!.userId) {
      throw new AppError('That username is already taken', 409, 'DUPLICATE_NAME');
    }
  }

  const user = await prisma.user.update({
    where: { id: req.user!.userId },
    data,
  });

  res.json({
    id: user.id,
    displayName: user.displayName,
    dailyLimit: user.dailyLimit,
    txLimit: user.txLimit,
  });
});

// === LOOKUP USER BY ID (public info) ===
userRouter.get('/:id', async (req: Request, res: Response) => {
  const id = String(req.params.id);
  const user = await prisma.user.findUnique({
    where: { id },
    include: { wallet: { select: { publicKey: true, usdcBalance: true } } },
  });

  if (!user) throw new AppError('User not found', 404, 'USER_NOT_FOUND');

  res.json({
    id: user.id,
    type: user.type,
    displayName: user.displayName,
    walletAddress: user.wallet?.publicKey,
  });
});

// === SEARCH USERS ===
const searchSchema = z.object({
  q: z.string().min(1).max(100),
  type: z.enum(['HUMAN', 'AGENT']).optional(),
  limit: z.coerce.number().int().min(1).max(50).default(10),
});

userRouter.get('/search/query', async (req: Request, res: Response) => {
  const parsed = searchSchema.safeParse(req.query);
  if (!parsed.success) {
    throw new AppError('Invalid query', 400, 'VALIDATION_ERROR');
  }

  const { type: userType, limit } = parsed.data;
  const q = parsed.data.q.replace(/^@/, '').trim();

  const users = await prisma.user.findMany({
    where: {
      displayName: { contains: q },
      ...(userType ? { type: userType } : {}),
    },
    take: limit,
    select: {
      id: true,
      displayName: true,
      type: true,
      wallet: { select: { publicKey: true } },
    },
  });

  res.json({
    users: users.map(u => ({
      id: u.id,
      displayName: u.displayName,
      type: u.type,
      walletAddress: u.wallet?.publicKey,
    })),
  });
});
