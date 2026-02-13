import { Router, Request, Response } from 'express';
import { PrismaClient } from '@prisma/client';
import { z } from 'zod';
import { authenticate, requireHuman } from '../middleware/auth';
import { getUsdcBalance, getSolBalance, requestAirdrop } from '../services/solana';
import { notifyUser } from '../services/websocket';
import { AppError } from '../middleware/errorHandler';

const prisma = new PrismaClient();
export const walletRouter = Router();

walletRouter.use(authenticate);

// === GET MY WALLET ===
walletRouter.get('/me', async (req: Request, res: Response) => {
  const wallet = await prisma.wallet.findUnique({
    where: { userId: req.user!.userId },
  });

  if (!wallet) throw new AppError('Wallet not found', 404, 'WALLET_NOT_FOUND');

  // Get on-chain balance, but use cached if higher (demo deposits are off-chain)
  let usdcBalance: number;
  try {
    const onChainBalance = await getUsdcBalance(wallet.publicKey);
    usdcBalance = Math.max(onChainBalance, wallet.usdcBalance);
  } catch {
    usdcBalance = wallet.usdcBalance;
  }
  const solBalance = await getSolBalance(wallet.publicKey).catch(() => 0);

  await prisma.wallet.update({
    where: { id: wallet.id },
    data: { usdcBalance },
  });

  res.json({
    publicKey: wallet.publicKey,
    usdcBalance,
    solBalance,
    isActive: wallet.isActive,
  });
});

// === GET WALLET BY USER ID (public info only) ===
walletRouter.get('/user/:userId', async (req: Request, res: Response) => {
  const userId = String(req.params.userId);
  const wallet = await prisma.wallet.findUnique({
    where: { userId },
    include: { user: { select: { displayName: true, type: true } } },
  });

  if (!wallet) throw new AppError('Wallet not found', 404, 'WALLET_NOT_FOUND');

  res.json({
    publicKey: wallet.publicKey,
    usdcBalance: wallet.usdcBalance,
    owner: wallet.user.displayName,
    ownerType: wallet.user.type,
  });
});

// === LOOKUP WALLET BY SOLANA ADDRESS ===
walletRouter.get('/address/:address', async (req: Request, res: Response) => {
  const address = String(req.params.address);
  const wallet = await prisma.wallet.findUnique({
    where: { publicKey: address },
    include: { user: { select: { id: true, displayName: true, type: true } } },
  });

  if (!wallet) throw new AppError('Address not registered', 404, 'ADDRESS_NOT_FOUND');

  res.json({
    userId: wallet.user.id,
    publicKey: wallet.publicKey,
    owner: wallet.user.displayName,
    ownerType: wallet.user.type,
  });
});

// === DEPOSIT (demo faucet - adds test USDC) ===
const depositSchema = z.object({
  amount: z.number().positive().max(10000).default(10),
});

walletRouter.post('/deposit', requireHuman, async (req: Request, res: Response) => {
  const parsed = depositSchema.safeParse(req.body);
  const amount = parsed.success ? parsed.data.amount : 10;
  const userId = req.user!.userId;

  const wallet = await prisma.wallet.findUnique({ where: { userId } });
  if (!wallet) throw new AppError('Wallet not found', 404, 'WALLET_NOT_FOUND');

  // Create deposit transaction record
  const tx = await prisma.transaction.create({
    data: {
      type: 'DEPOSIT',
      status: 'CONFIRMED',
      receiverId: userId,
      amount,
      fee: 0,
      toWallet: wallet.publicKey,
      memo: `Demo deposit of ${amount} USDC`,
      confirmedAt: new Date(),
    },
  });

  // Update cached balance
  const newBalance = wallet.usdcBalance + amount;
  await prisma.wallet.update({
    where: { userId },
    data: { usdcBalance: newBalance },
  });

  notifyUser(userId, 'transaction.confirmed', {
    transactionId: tx.id,
    amount,
    type: 'deposit',
  });

  res.status(201).json({
    transaction: {
      id: tx.id,
      type: tx.type,
      status: tx.status,
      amount: tx.amount,
      createdAt: tx.createdAt,
    },
    newBalance,
  });
});

// === DEVNET AIRDROP (testing only) ===
walletRouter.post('/airdrop', requireHuman, async (req: Request, res: Response) => {
  if (process.env.SOLANA_NETWORK !== 'devnet') {
    throw new AppError('Airdrop only available on devnet', 403, 'NOT_DEVNET');
  }

  const wallet = await prisma.wallet.findUnique({
    where: { userId: req.user!.userId },
  });

  if (!wallet) throw new AppError('Wallet not found', 404, 'WALLET_NOT_FOUND');

  const signature = await requestAirdrop(wallet.publicKey, 1);

  res.json({
    message: 'Airdrop of 1 SOL requested (for tx fees)',
    signature,
    walletAddress: wallet.publicKey,
  });
});
