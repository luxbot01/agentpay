import { Router, Request, Response } from 'express';
import { PrismaClient } from '@prisma/client';
import { z } from 'zod';
import { authenticate, requireHuman } from '../middleware/auth';
import { AppError } from '../middleware/errorHandler';
import { encryptBankField, getLast4 } from '../services/bankCrypto';

const prisma = new PrismaClient();
export const bankRouter = Router();

bankRouter.use(authenticate);
bankRouter.use(requireHuman); // All bank operations are human-only

// === CONNECT BANK ACCOUNT ===
const connectSchema = z.object({
  bankName: z.string().min(1).max(100),
  accountType: z.enum(['CHECKING', 'SAVINGS']),
  accountNumber: z.string().min(4).max(17).regex(/^\d+$/, 'Account number must be digits only'),
  routingNumber: z.string().length(9).regex(/^\d{9}$/, 'Routing number must be exactly 9 digits'),
  isDefault: z.boolean().optional(),
});

bankRouter.post('/', async (req: Request, res: Response) => {
  const parsed = connectSchema.safeParse(req.body);
  if (!parsed.success) {
    throw new AppError(parsed.error.issues[0].message, 400, 'VALIDATION_ERROR');
  }

  const userId = req.user!.userId;
  const { bankName, accountType, accountNumber, routingNumber, isDefault } = parsed.data;

  // Encrypt full numbers - they never leave the server unencrypted
  const encryptedAccountNumber = encryptBankField(accountNumber);
  const encryptedRoutingNumber = encryptBankField(routingNumber);

  // Derive last 4 for display purposes only
  const accountLast4 = getLast4(accountNumber);
  const routingLast4 = getLast4(routingNumber);

  // If setting as default, unset other defaults first
  if (isDefault) {
    await prisma.bankAccount.updateMany({
      where: { userId, isDefault: true },
      data: { isDefault: false },
    });
  }

  // If this is the first bank account, make it default
  const existingCount = await prisma.bankAccount.count({ where: { userId } });
  const shouldBeDefault = isDefault || existingCount === 0;

  const bank = await prisma.bankAccount.create({
    data: {
      userId,
      bankName,
      accountType,
      encryptedAccountNumber,
      encryptedRoutingNumber,
      accountLast4,
      routingLast4,
      isDefault: shouldBeDefault,
    },
  });

  // NEVER return encrypted fields - only last 4
  res.status(201).json({
    bankAccount: {
      id: bank.id,
      bankName: bank.bankName,
      accountType: bank.accountType,
      accountLast4: bank.accountLast4,
      routingLast4: bank.routingLast4,
      isDefault: bank.isDefault,
      createdAt: bank.createdAt,
    },
  });
});

// === LIST MY BANK ACCOUNTS ===
bankRouter.get('/', async (req: Request, res: Response) => {
  const banks = await prisma.bankAccount.findMany({
    where: { userId: req.user!.userId, isActive: true },
    orderBy: { createdAt: 'desc' },
  });

  // NEVER return encrypted fields - only last 4
  res.json({
    bankAccounts: banks.map(b => ({
      id: b.id,
      bankName: b.bankName,
      accountType: b.accountType,
      accountLast4: b.accountLast4,
      routingLast4: b.routingLast4,
      isDefault: b.isDefault,
      createdAt: b.createdAt,
    })),
  });
});

// === DELETE BANK ACCOUNT ===
bankRouter.delete('/:id', async (req: Request, res: Response) => {
  const id = String(req.params.id);
  const userId = req.user!.userId;

  const bank = await prisma.bankAccount.findFirst({
    where: { id, userId },
  });

  if (!bank) throw new AppError('Bank account not found', 404, 'NOT_FOUND');

  await prisma.bankAccount.update({
    where: { id },
    data: { isActive: false },
  });

  res.json({ message: 'Bank account removed' });
});

// === SET DEFAULT BANK ACCOUNT ===
bankRouter.patch('/:id/default', async (req: Request, res: Response) => {
  const id = String(req.params.id);
  const userId = req.user!.userId;

  const bank = await prisma.bankAccount.findFirst({
    where: { id, userId, isActive: true },
  });

  if (!bank) throw new AppError('Bank account not found', 404, 'NOT_FOUND');

  // Unset all defaults
  await prisma.bankAccount.updateMany({
    where: { userId, isDefault: true },
    data: { isDefault: false },
  });

  // Set this one as default
  await prisma.bankAccount.update({
    where: { id },
    data: { isDefault: true },
  });

  res.json({ message: 'Default bank account updated' });
});
