import { Router, Request, Response } from 'express';
import { PrismaClient } from '@prisma/client';
import { z } from 'zod';
import crypto from 'crypto';
import { authenticate } from '../middleware/auth';
import { AppError } from '../middleware/errorHandler';

const prisma = new PrismaClient();
export const webhookRouter = Router();

webhookRouter.use(authenticate);

const VALID_EVENTS = [
  'transaction.confirmed',
  'transaction.failed',
  'transaction.pending',
  'balance.updated',
];

// === CREATE WEBHOOK ===
const createSchema = z.object({
  url: z.string().url(),
  events: z.array(z.enum(['transaction.confirmed', 'transaction.failed', 'transaction.pending', 'balance.updated'])).min(1),
});

webhookRouter.post('/', async (req: Request, res: Response) => {
  const parsed = createSchema.safeParse(req.body);
  if (!parsed.success) {
    throw new AppError('Invalid input', 400, 'VALIDATION_ERROR');
  }

  const secret = crypto.randomBytes(32).toString('hex');

  const webhook = await prisma.webhook.create({
    data: {
      userId: req.user!.userId,
      url: parsed.data.url,
      events: JSON.stringify(parsed.data.events),
      secret,
    },
  });

  res.status(201).json({
    id: webhook.id,
    url: webhook.url,
    events: JSON.parse(webhook.events),
    secret, // Only returned once at creation
    warning: 'Save this secret now. It cannot be retrieved later.',
  });
});

// === LIST MY WEBHOOKS ===
webhookRouter.get('/', async (req: Request, res: Response) => {
  const webhooks = await prisma.webhook.findMany({
    where: { userId: req.user!.userId },
    select: {
      id: true,
      url: true,
      events: true,
      isActive: true,
      createdAt: true,
    },
  });

  res.json({ webhooks });
});

// === DELETE WEBHOOK ===
webhookRouter.delete('/:id', async (req: Request, res: Response) => {
  const id = String(req.params.id);
  const webhook = await prisma.webhook.findUnique({ where: { id } });

  if (!webhook) throw new AppError('Webhook not found', 404, 'WEBHOOK_NOT_FOUND');
  if (webhook.userId !== req.user!.userId) throw new AppError('Not authorized', 403, 'FORBIDDEN');

  await prisma.webhook.delete({ where: { id } });
  res.json({ message: 'Webhook deleted' });
});

// === TOGGLE WEBHOOK ===
webhookRouter.patch('/:id/toggle', async (req: Request, res: Response) => {
  const id = String(req.params.id);
  const webhook = await prisma.webhook.findUnique({ where: { id } });

  if (!webhook) throw new AppError('Webhook not found', 404, 'WEBHOOK_NOT_FOUND');
  if (webhook.userId !== req.user!.userId) throw new AppError('Not authorized', 403, 'FORBIDDEN');

  const updated = await prisma.webhook.update({
    where: { id },
    data: { isActive: !webhook.isActive },
  });

  res.json({ id: updated.id, isActive: updated.isActive });
});
