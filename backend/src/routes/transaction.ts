import { Router, Request, Response } from 'express';
import { PrismaClient } from '@prisma/client';
import { z } from 'zod';
import { authenticate } from '../middleware/auth';
import { AppError } from '../middleware/errorHandler';

const prisma = new PrismaClient();
export const transactionRouter = Router();

transactionRouter.use(authenticate);

// === LIST MY TRANSACTIONS ===
const listSchema = z.object({
  page: z.coerce.number().int().positive().default(1),
  limit: z.coerce.number().int().min(1).max(100).default(20),
  type: z.enum(['DEPOSIT', 'WITHDRAW', 'TRANSFER']).optional(),
  status: z.enum(['PENDING', 'CONFIRMED', 'FAILED', 'CANCELLED']).optional(),
  direction: z.enum(['sent', 'received', 'all']).default('all'),
});

transactionRouter.get('/', async (req: Request, res: Response) => {
  const parsed = listSchema.safeParse(req.query);
  if (!parsed.success) {
    throw new AppError('Invalid query params', 400, 'VALIDATION_ERROR');
  }

  const { page, limit, type, status, direction } = parsed.data;
  const userId = req.user!.userId;
  const skip = (page - 1) * limit;

  // Build where clause
  const where: any = {};
  if (type) where.type = type;
  if (status) where.status = status;

  if (direction === 'sent') {
    where.senderId = userId;
  } else if (direction === 'received') {
    where.receiverId = userId;
  } else {
    where.OR = [{ senderId: userId }, { receiverId: userId }];
  }

  const [transactions, total] = await Promise.all([
    prisma.transaction.findMany({
      where,
      orderBy: { createdAt: 'desc' },
      skip,
      take: limit,
      include: {
        sender: { select: { id: true, displayName: true, type: true } },
        receiver: { select: { id: true, displayName: true, type: true } },
      },
    }),
    prisma.transaction.count({ where }),
  ]);

  res.json({
    transactions: transactions.map((tx) => ({
      id: tx.id,
      type: tx.type,
      status: tx.status,
      amount: tx.amount,
      fee: tx.fee,
      fromWallet: tx.fromWallet,
      toWallet: tx.toWallet,
      solanaSignature: tx.solanaSignature,
      memo: tx.memo,
      metadata: tx.metadata,
      sender: tx.sender,
      receiver: tx.receiver,
      direction: tx.senderId === userId ? 'sent' : 'received',
      createdAt: tx.createdAt,
      confirmedAt: tx.confirmedAt,
    })),
    pagination: {
      page,
      limit,
      total,
      totalPages: Math.ceil(total / limit),
    },
  });
});

// === GET SINGLE TRANSACTION ===
transactionRouter.get('/:id', async (req: Request, res: Response) => {
  const userId = req.user!.userId;
  const txId = String(req.params.id);

  const tx = await prisma.transaction.findUnique({
    where: { id: txId },
    include: {
      sender: { select: { id: true, displayName: true, type: true } },
      receiver: { select: { id: true, displayName: true, type: true } },
    },
  });

  if (!tx) throw new AppError('Transaction not found', 404, 'TX_NOT_FOUND');

  if (tx.senderId !== userId && tx.receiverId !== userId) {
    throw new AppError('Not authorized to view this transaction', 403, 'FORBIDDEN');
  }

  res.json({
    id: tx.id,
    type: tx.type,
    status: tx.status,
    amount: tx.amount,
    fee: tx.fee,
    fromWallet: tx.fromWallet,
    toWallet: tx.toWallet,
    solanaSignature: tx.solanaSignature,
    memo: tx.memo,
    metadata: tx.metadata,
    sender: tx.sender,
    receiver: tx.receiver,
    direction: tx.senderId === userId ? 'sent' : 'received',
    createdAt: tx.createdAt,
    confirmedAt: tx.confirmedAt,
  });
});
