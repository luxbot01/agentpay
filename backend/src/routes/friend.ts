import { Router, Request, Response } from 'express';
import { PrismaClient } from '@prisma/client';
import { z } from 'zod';
import { authenticate } from '../middleware/auth';
import { AppError } from '../middleware/errorHandler';

const prisma = new PrismaClient();
export const friendRouter = Router();

friendRouter.use(authenticate);

// === LIST ACCEPTED FRIENDS ===
friendRouter.get('/', async (req: Request, res: Response) => {
  const userId = req.user!.userId;

  // Friends where I sent the request (accepted)
  const sent = await prisma.friendship.findMany({
    where: { userId, status: 'ACCEPTED' },
    include: {
      friend: {
        select: { id: true, displayName: true, type: true, wallet: { select: { publicKey: true } } },
      },
    },
  });

  // Friends where they sent the request to me (accepted)
  const received = await prisma.friendship.findMany({
    where: { friendId: userId, status: 'ACCEPTED' },
    include: {
      user: {
        select: { id: true, displayName: true, type: true, wallet: { select: { publicKey: true } } },
      },
    },
  });

  const friends = [
    ...sent.map(f => ({
      id: f.friend.id,
      displayName: f.friend.displayName,
      type: f.friend.type,
      walletAddress: f.friend.wallet?.publicKey,
      addedAt: f.createdAt,
    })),
    ...received.map(f => ({
      id: f.user.id,
      displayName: f.user.displayName,
      type: f.user.type,
      walletAddress: f.user.wallet?.publicKey,
      addedAt: f.createdAt,
    })),
  ];

  res.json({ friends });
});

// === LIST PENDING INCOMING REQUESTS ===
friendRouter.get('/requests', async (req: Request, res: Response) => {
  const userId = req.user!.userId;

  const incoming = await prisma.friendship.findMany({
    where: { friendId: userId, status: 'PENDING' },
    include: {
      user: {
        select: { id: true, displayName: true, type: true, wallet: { select: { publicKey: true } } },
      },
    },
    orderBy: { createdAt: 'desc' },
  });

  res.json({
    requests: incoming.map(f => ({
      id: f.id,
      from: {
        id: f.user.id,
        displayName: f.user.displayName,
        type: f.user.type,
        walletAddress: f.user.wallet?.publicKey,
      },
      createdAt: f.createdAt,
    })),
  });
});

// === SEND FRIEND REQUEST ===
const addFriendSchema = z.object({
  friendId: z.string().uuid(),
});

friendRouter.post('/', async (req: Request, res: Response) => {
  const parsed = addFriendSchema.safeParse(req.body);
  if (!parsed.success) {
    throw new AppError('Invalid friend ID', 400, 'VALIDATION_ERROR');
  }

  const userId = req.user!.userId;
  const { friendId } = parsed.data;

  if (friendId === userId) {
    throw new AppError('Cannot add yourself as a friend', 400, 'SELF_FRIEND');
  }

  const friendUser = await prisma.user.findUnique({
    where: { id: friendId },
    select: { id: true, displayName: true, type: true },
  });
  if (!friendUser) throw new AppError('User not found', 404, 'USER_NOT_FOUND');

  // Check for existing request in either direction
  const existing = await prisma.friendship.findFirst({
    where: {
      OR: [
        { userId, friendId },
        { userId: friendId, friendId: userId },
      ],
    },
  });

  if (existing) {
    if (existing.status === 'ACCEPTED') {
      throw new AppError('Already friends', 409, 'ALREADY_FRIENDS');
    }
    throw new AppError('Friend request already pending', 409, 'ALREADY_PENDING');
  }

  await prisma.friendship.create({
    data: { userId, friendId, status: 'PENDING' },
  });

  res.status(201).json({ message: 'Friend request sent', status: 'PENDING' });
});

// === ACCEPT FRIEND REQUEST ===
friendRouter.post('/:requestId/accept', async (req: Request, res: Response) => {
  const userId = req.user!.userId;
  const requestId = String(req.params.requestId);

  const request = await prisma.friendship.findUnique({ where: { id: requestId } });

  if (!request || request.friendId !== userId || request.status !== 'PENDING') {
    throw new AppError('Friend request not found', 404, 'NOT_FOUND');
  }

  await prisma.friendship.update({
    where: { id: requestId },
    data: { status: 'ACCEPTED' },
  });

  res.json({ message: 'Friend request accepted' });
});

// === DECLINE FRIEND REQUEST ===
friendRouter.post('/:requestId/decline', async (req: Request, res: Response) => {
  const userId = req.user!.userId;
  const requestId = String(req.params.requestId);

  const request = await prisma.friendship.findUnique({ where: { id: requestId } });

  if (!request || request.friendId !== userId || request.status !== 'PENDING') {
    throw new AppError('Friend request not found', 404, 'NOT_FOUND');
  }

  await prisma.friendship.delete({ where: { id: requestId } });

  res.json({ message: 'Friend request declined' });
});

// === REMOVE FRIEND ===
friendRouter.delete('/:friendId', async (req: Request, res: Response) => {
  const userId = req.user!.userId;
  const friendId = String(req.params.friendId);

  // Find friendship in either direction
  const friendship = await prisma.friendship.findFirst({
    where: {
      OR: [
        { userId, friendId, status: 'ACCEPTED' },
        { userId: friendId, friendId: userId, status: 'ACCEPTED' },
      ],
    },
  });

  if (!friendship) throw new AppError('Friendship not found', 404, 'NOT_FOUND');

  await prisma.friendship.delete({ where: { id: friendship.id } });

  res.json({ message: 'Friend removed' });
});
