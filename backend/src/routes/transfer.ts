import { Router, Request, Response } from 'express';
import { PrismaClient } from '@prisma/client';
import { z } from 'zod';
import { authenticate, requireHuman } from '../middleware/auth';
import { transferUsdc, getUsdcBalance } from '../services/solana';
import { notifyUser } from '../services/websocket';
import { dispatchWebhook } from '../services/webhook';
import { AppError } from '../middleware/errorHandler';

const prisma = new PrismaClient();
export const transferRouter = Router();

transferRouter.use(authenticate);

// === REQUEST PAYMENT ===
const requestSchema = z.object({
  fromUserId: z.string().uuid().optional(),
  fromUsername: z.string().max(50).optional(),
  amount: z.number().positive().max(1000000),
  memo: z.string().max(500).optional(),
}).refine(
  (data) => data.fromUserId || data.fromUsername,
  { message: 'Either fromUserId or fromUsername is required' }
);

transferRouter.post('/request', async (req: Request, res: Response) => {
  const parsed = requestSchema.safeParse(req.body);
  if (!parsed.success) {
    throw new AppError(parsed.error.issues[0].message, 400, 'VALIDATION_ERROR');
  }

  const { fromUserId, fromUsername, amount, memo } = parsed.data;
  const requesterId = req.user!.userId;

  // Resolve username to userId if provided
  let resolvedFromUserId = fromUserId;
  if (!resolvedFromUserId && fromUsername) {
    const name = fromUsername.replace(/^@/, '').trim();
    const found = await prisma.user.findUnique({ where: { displayName: name } });
    if (!found) throw new AppError(`User @${name} not found`, 404, 'USER_NOT_FOUND');
    resolvedFromUserId = found.id;
  }

  if (resolvedFromUserId === requesterId) {
    throw new AppError('Cannot request money from yourself', 400, 'SELF_REQUEST');
  }

  // Verify both users exist
  const [requester, target] = await Promise.all([
    prisma.user.findUnique({ where: { id: requesterId }, include: { wallet: true } }),
    prisma.user.findUnique({ where: { id: resolvedFromUserId! }, include: { wallet: true } }),
  ]);

  if (!requester?.wallet) throw new AppError('Your wallet not found', 404, 'WALLET_NOT_FOUND');
  if (!target?.wallet) throw new AppError('Target user not found', 404, 'USER_NOT_FOUND');

  // Create pending request transaction
  const tx = await prisma.transaction.create({
    data: {
      type: 'TRANSFER',
      status: 'PENDING',
      senderId: resolvedFromUserId!,  // who will pay
      receiverId: requesterId,         // who requested
      amount,
      fee: 0,
      fromWallet: target.wallet.publicKey,
      toWallet: requester.wallet.publicKey,
      memo: memo || `Payment request from @${requester.displayName}`,
      metadata: { isRequest: true, requestedBy: requesterId },
    },
  });

  // Notify target user
  notifyUser(resolvedFromUserId!, 'transaction.pending', {
    transactionId: tx.id,
    amount,
    requestedBy: requester.displayName,
    type: 'payment_request',
  });

  res.status(201).json({
    request: {
      id: tx.id,
      amount: tx.amount,
      from: { id: target.id, displayName: target.displayName },
      memo: tx.memo,
      status: tx.status,
      createdAt: tx.createdAt,
    },
  });
});

// === INCOMING PAYMENT REQUESTS ===
transferRouter.get('/requests/incoming', async (req: Request, res: Response) => {
  const userId = req.user!.userId;

  // Find PENDING transactions where current user is the sender (payer) and it's a request
  const pendingRequests = await prisma.transaction.findMany({
    where: {
      senderId: userId,
      status: 'PENDING',
      type: 'TRANSFER',
    },
    include: {
      receiver: { select: { id: true, displayName: true } },
    },
    orderBy: { createdAt: 'desc' },
  });

  // Filter for requests (metadata contains isRequest: true)
  const requests = pendingRequests.filter((tx) => {
    const meta = tx.metadata as Record<string, unknown> | null;
    return meta && meta.isRequest === true;
  });

  res.json({
    requests: requests.map((tx) => ({
      id: tx.id,
      amount: tx.amount,
      requestedBy: tx.receiver,
      memo: tx.memo,
      createdAt: tx.createdAt,
    })),
  });
});

// === ACCEPT PAYMENT REQUEST ===
transferRouter.post('/requests/:id/accept', async (req: Request, res: Response) => {
  const txId = String(req.params.id);
  const userId = req.user!.userId;

  const tx = await prisma.transaction.findUnique({ where: { id: txId } });

  if (!tx) throw new AppError('Request not found', 404, 'NOT_FOUND');
  if (tx.status !== 'PENDING') throw new AppError('Request is no longer pending', 400, 'NOT_PENDING');

  const meta = tx.metadata as Record<string, unknown> | null;
  if (!meta || meta.isRequest !== true) {
    throw new AppError('Transaction is not a payment request', 400, 'NOT_A_REQUEST');
  }

  if (tx.senderId !== userId) {
    throw new AppError('Only the requested payer can accept this request', 403, 'FORBIDDEN');
  }

  // Fetch sender wallet to check balance
  const senderWallet = await prisma.wallet.findUnique({ where: { userId: tx.senderId! } });
  const receiverWallet = await prisma.wallet.findUnique({ where: { userId: tx.receiverId! } });

  if (!senderWallet || !receiverWallet) {
    throw new AppError('Wallet not found', 404, 'WALLET_NOT_FOUND');
  }

  if (senderWallet.usdcBalance < tx.amount) {
    throw new AppError(
      `Insufficient balance: ${senderWallet.usdcBalance} USDC available`,
      400,
      'INSUFFICIENT_BALANCE'
    );
  }

  // Execute the payment: move cached balances + confirm transaction
  await prisma.$transaction([
    prisma.wallet.update({
      where: { userId: tx.senderId! },
      data: { usdcBalance: { decrement: tx.amount } },
    }),
    prisma.wallet.update({
      where: { userId: tx.receiverId! },
      data: { usdcBalance: { increment: tx.amount } },
    }),
    prisma.transaction.update({
      where: { id: txId },
      data: {
        status: 'CONFIRMED',
        solanaSignature: `request_accepted_${Date.now()}`,
        confirmedAt: new Date(),
      },
    }),
  ]);

  // Notify both parties
  notifyUser(tx.senderId!, 'transaction.confirmed', {
    transactionId: tx.id,
    amount: tx.amount,
    direction: 'sent',
    type: 'request_accepted',
  });
  notifyUser(tx.receiverId!, 'transaction.confirmed', {
    transactionId: tx.id,
    amount: tx.amount,
    direction: 'received',
    type: 'request_accepted',
  });

  res.json({ message: 'Payment request accepted', transactionId: tx.id });
});

// === DISMISS PAYMENT REQUEST ===
transferRouter.post('/requests/:id/dismiss', async (req: Request, res: Response) => {
  const txId = String(req.params.id);
  const userId = req.user!.userId;

  const tx = await prisma.transaction.findUnique({ where: { id: txId } });

  if (!tx) throw new AppError('Request not found', 404, 'NOT_FOUND');
  if (tx.status !== 'PENDING') throw new AppError('Request is no longer pending', 400, 'NOT_PENDING');

  const meta = tx.metadata as Record<string, unknown> | null;
  if (!meta || meta.isRequest !== true) {
    throw new AppError('Transaction is not a payment request', 400, 'NOT_A_REQUEST');
  }

  if (tx.senderId !== userId) {
    throw new AppError('Only the requested payer can dismiss this request', 403, 'FORBIDDEN');
  }

  await prisma.transaction.update({
    where: { id: txId },
    data: { status: 'CANCELLED' },
  });

  // Notify the requester that their request was dismissed
  if (tx.receiverId) {
    notifyUser(tx.receiverId, 'transaction.failed', {
      transactionId: tx.id,
      type: 'request_dismissed',
    });
  }

  res.json({ message: 'Payment request dismissed', transactionId: tx.id });
});

// === WITHDRAW TO EXTERNAL WALLET ===
const withdrawSchema = z.object({
  toWalletAddress: z.string().min(32).max(44),
  amount: z.number().positive().max(1000000),
  memo: z.string().max(500).optional(),
});

transferRouter.post('/withdraw', requireHuman, async (req: Request, res: Response) => {
  const parsed = withdrawSchema.safeParse(req.body);
  if (!parsed.success) {
    throw new AppError(parsed.error.issues[0].message, 400, 'VALIDATION_ERROR');
  }

  const { toWalletAddress, amount, memo } = parsed.data;
  const userId = req.user!.userId;

  const user = await prisma.user.findUnique({
    where: { id: userId },
    include: { wallet: true },
  });
  if (!user?.wallet) throw new AppError('Wallet not found', 404, 'WALLET_NOT_FOUND');

  // Check spending limits
  if (user.txLimit && amount > user.txLimit) {
    throw new AppError(`Amount exceeds per-transaction limit of ${user.txLimit} USDC`, 403, 'TX_LIMIT_EXCEEDED');
  }

  // Check balance
  const balance = await getUsdcBalance(user.wallet.publicKey);
  if (balance < amount) {
    throw new AppError(`Insufficient balance: ${balance} USDC available`, 400, 'INSUFFICIENT_BALANCE');
  }

  // Create pending withdrawal
  const tx = await prisma.transaction.create({
    data: {
      type: 'WITHDRAW',
      status: 'PENDING',
      senderId: userId,
      amount,
      fee: 0,
      fromWallet: user.wallet.publicKey,
      toWallet: toWalletAddress,
      memo,
    },
  });

  try {
    const signature = await transferUsdc(user.wallet.encryptedSecret, toWalletAddress, amount);

    const confirmedTx = await prisma.transaction.update({
      where: { id: tx.id },
      data: { status: 'CONFIRMED', solanaSignature: signature, confirmedAt: new Date() },
    });

    // Update cached balance
    const newBalance = await getUsdcBalance(user.wallet.publicKey);
    await prisma.wallet.update({ where: { userId }, data: { usdcBalance: newBalance } });

    notifyUser(userId, 'transaction.confirmed', {
      transactionId: confirmedTx.id,
      amount,
      type: 'withdrawal',
    });

    res.status(201).json({
      transaction: {
        id: confirmedTx.id,
        type: confirmedTx.type,
        status: confirmedTx.status,
        amount: confirmedTx.amount,
        toWallet: confirmedTx.toWallet,
        solanaSignature: confirmedTx.solanaSignature,
        createdAt: confirmedTx.createdAt,
        confirmedAt: confirmedTx.confirmedAt,
      },
    });
  } catch (err) {
    await prisma.transaction.update({ where: { id: tx.id }, data: { status: 'FAILED' } });
    throw new AppError(
      'Withdrawal failed: ' + (err instanceof Error ? err.message : 'Unknown error'),
      500,
      'WITHDRAW_FAILED'
    );
  }
});

// === SEND USDC ===
const transferSchema = z.object({
  toUserId: z.string().uuid().optional(),
  toUsername: z.string().max(50).optional(),
  toWalletAddress: z.string().optional(),
  amount: z.number().positive().max(1000000),
  memo: z.string().max(500).optional(),
  metadata: z.record(z.unknown()).optional(),
}).refine(
  (data) => data.toUserId || data.toWalletAddress || data.toUsername,
  { message: 'Either toUserId, toUsername, or toWalletAddress is required' }
);

transferRouter.post('/send', async (req: Request, res: Response) => {
  const parsed = transferSchema.safeParse(req.body);
  if (!parsed.success) {
    throw new AppError(parsed.error.issues[0].message, 400, 'VALIDATION_ERROR');
  }

  const { toUserId, toUsername, toWalletAddress, amount, memo, metadata } = parsed.data;
  const senderId = req.user!.userId;

  // Resolve username to userId if provided
  let resolvedToUserId = toUserId;
  if (!resolvedToUserId && toUsername) {
    const name = toUsername.replace(/^@/, '').trim();
    const found = await prisma.user.findUnique({ where: { displayName: name } });
    if (!found) throw new AppError(`User @${name} not found`, 404, 'USER_NOT_FOUND');
    resolvedToUserId = found.id;
  }

  // Get sender wallet
  const senderUser = await prisma.user.findUnique({
    where: { id: senderId },
    include: { wallet: true },
  });
  if (!senderUser?.wallet) throw new AppError('Sender wallet not found', 404, 'WALLET_NOT_FOUND');

  // Check spending limits
  if (senderUser.txLimit && amount > senderUser.txLimit) {
    throw new AppError(
      `Amount exceeds per-transaction limit of ${senderUser.txLimit} USDC`,
      403,
      'TX_LIMIT_EXCEEDED'
    );
  }

  if (senderUser.dailyLimit) {
    const dayStart = new Date();
    dayStart.setHours(0, 0, 0, 0);
    const dailyTotal = await prisma.transaction.aggregate({
      where: {
        senderId,
        type: 'TRANSFER',
        status: 'CONFIRMED',
        createdAt: { gte: dayStart },
      },
      _sum: { amount: true },
    });
    if ((dailyTotal._sum.amount || 0) + amount > senderUser.dailyLimit) {
      throw new AppError('Daily spending limit exceeded', 403, 'DAILY_LIMIT_EXCEEDED');
    }
  }

  // Resolve receiver
  let receiverWalletAddress: string;
  let receiverId: string | null = null;

  if (resolvedToUserId) {
    const receiver = await prisma.user.findUnique({
      where: { id: resolvedToUserId },
      include: { wallet: true },
    });
    if (!receiver?.wallet) throw new AppError('Receiver not found', 404, 'RECEIVER_NOT_FOUND');
    receiverWalletAddress = receiver.wallet.publicKey;
    receiverId = receiver.id;
  } else {
    receiverWalletAddress = toWalletAddress!;
    // Try to find internal user by wallet address
    const wallet = await prisma.wallet.findUnique({ where: { publicKey: toWalletAddress! } });
    if (wallet) receiverId = wallet.userId;
  }

  // Check balance
  const balance = await getUsdcBalance(senderUser.wallet.publicKey);
  if (balance < amount) {
    throw new AppError(
      `Insufficient balance: ${balance} USDC available, ${amount} USDC requested`,
      400,
      'INSUFFICIENT_BALANCE'
    );
  }

  // Create pending transaction
  const tx = await prisma.transaction.create({
    data: {
      type: 'TRANSFER',
      status: 'PENDING',
      senderId,
      receiverId,
      amount,
      fee: 0, // no platform fee for MVP
      fromWallet: senderUser.wallet.publicKey,
      toWallet: receiverWalletAddress,
      memo,
      metadata: metadata ? JSON.parse(JSON.stringify(metadata)) : undefined,
    },
  });

  // Execute on-chain transfer
  try {
    const signature = await transferUsdc(
      senderUser.wallet.encryptedSecret,
      receiverWalletAddress,
      amount
    );

    // Update transaction as confirmed
    const confirmedTx = await prisma.transaction.update({
      where: { id: tx.id },
      data: {
        status: 'CONFIRMED',
        solanaSignature: signature,
        confirmedAt: new Date(),
      },
    });

    // Update cached balances
    const newSenderBalance = await getUsdcBalance(senderUser.wallet.publicKey);
    await prisma.wallet.update({
      where: { userId: senderId },
      data: { usdcBalance: newSenderBalance },
    });

    if (receiverId) {
      const receiverWallet = await prisma.wallet.findUnique({ where: { userId: receiverId } });
      if (receiverWallet) {
        const newReceiverBalance = await getUsdcBalance(receiverWallet.publicKey);
        await prisma.wallet.update({
          where: { userId: receiverId },
          data: { usdcBalance: newReceiverBalance },
        });
      }
    }

    // Notify via WebSocket
    notifyUser(senderId, 'transaction.confirmed', {
      transactionId: confirmedTx.id,
      amount,
      direction: 'sent',
    });
    if (receiverId) {
      notifyUser(receiverId, 'transaction.confirmed', {
        transactionId: confirmedTx.id,
        amount,
        direction: 'received',
      });
    }

    // Dispatch webhooks
    dispatchWebhook(senderId, 'transaction.confirmed', {
      transactionId: confirmedTx.id,
      type: 'TRANSFER',
      amount,
      direction: 'sent',
    });
    if (receiverId) {
      dispatchWebhook(receiverId, 'transaction.confirmed', {
        transactionId: confirmedTx.id,
        type: 'TRANSFER',
        amount,
        direction: 'received',
      });
    }

    res.status(201).json({
      transaction: {
        id: confirmedTx.id,
        type: confirmedTx.type,
        status: confirmedTx.status,
        amount: confirmedTx.amount,
        fee: confirmedTx.fee,
        fromWallet: confirmedTx.fromWallet,
        toWallet: confirmedTx.toWallet,
        solanaSignature: confirmedTx.solanaSignature,
        memo: confirmedTx.memo,
        createdAt: confirmedTx.createdAt,
        confirmedAt: confirmedTx.confirmedAt,
      },
    });
  } catch (err) {
    // Mark transaction as failed
    await prisma.transaction.update({
      where: { id: tx.id },
      data: { status: 'FAILED' },
    });

    notifyUser(senderId, 'transaction.failed', { transactionId: tx.id });
    if (receiverId) {
      dispatchWebhook(receiverId, 'transaction.failed', { transactionId: tx.id });
    }

    throw new AppError(
      'Transfer failed on-chain: ' + (err instanceof Error ? err.message : 'Unknown error'),
      500,
      'TRANSFER_FAILED'
    );
  }
});

// === DEMO SEND (cached balance transfer, no blockchain) ===
{
  const demoSendSchema = z.object({
    toUserId: z.string().uuid().optional(),
    toUsername: z.string().max(50).optional(),
    amount: z.number().positive().max(1000000),
    memo: z.string().max(500).optional(),
  }).refine(
    (data) => data.toUserId || data.toUsername,
    { message: 'Either toUserId or toUsername is required' }
  );

  transferRouter.post('/demo-send', async (req: Request, res: Response) => {
    const parsed = demoSendSchema.safeParse(req.body);
    if (!parsed.success) {
      throw new AppError(parsed.error.issues[0].message, 400, 'VALIDATION_ERROR');
    }

    const { toUserId, toUsername, amount, memo } = parsed.data;
    const authUserId = req.user!.userId;

    // If caller is an agent, use parent's account for the transaction
    const callerUser = await prisma.user.findUnique({ where: { id: authUserId } });
    if (!callerUser) throw new AppError('User not found', 404, 'USER_NOT_FOUND');

    const isAgent = callerUser.type === 'AGENT';
    const effectiveSenderId = isAgent && callerUser.parentUserId
      ? callerUser.parentUserId
      : authUserId;

    // Resolve recipient
    let recipientId = toUserId;
    if (!recipientId && toUsername) {
      const name = toUsername.replace(/^@/, '').trim();
      const found = await prisma.user.findUnique({ where: { displayName: name } });
      if (!found) throw new AppError(`User @${name} not found`, 404, 'USER_NOT_FOUND');
      recipientId = found.id;
    }

    if (recipientId === effectiveSenderId) {
      throw new AppError('Cannot send money to yourself', 400, 'SELF_TRANSFER');
    }

    // Get both wallets (using parent's wallet for agents)
    const [senderWallet, receiverWallet] = await Promise.all([
      prisma.wallet.findUnique({ where: { userId: effectiveSenderId } }),
      prisma.wallet.findUnique({ where: { userId: recipientId! } }),
    ]);

    if (!senderWallet) throw new AppError('Your wallet not found', 404, 'WALLET_NOT_FOUND');
    if (!receiverWallet) throw new AppError('Recipient wallet not found', 404, 'RECEIVER_NOT_FOUND');

    // Check cached balance (parent's balance for agents)
    if (senderWallet.usdcBalance < amount) {
      throw new AppError(
        `Insufficient balance: ${senderWallet.usdcBalance} USDC available`,
        400,
        'INSUFFICIENT_BALANCE'
      );
    }

    // Check agent's spending limits (not parent's)
    if (callerUser.txLimit && amount > callerUser.txLimit) {
      throw new AppError(`Amount exceeds per-transaction limit of ${callerUser.txLimit} USDC`, 403, 'TX_LIMIT_EXCEEDED');
    }

    if (callerUser.dailyLimit) {
      const dayStart = new Date();
      dayStart.setHours(0, 0, 0, 0);
      const dailyTotal = await prisma.transaction.aggregate({
        where: {
          senderId: effectiveSenderId,
          type: 'TRANSFER',
          status: 'CONFIRMED',
          createdAt: { gte: dayStart },
          metadata: { path: ['initiatedByAgent'], equals: callerUser.displayName },
        },
        _sum: { amount: true },
      });
      if ((dailyTotal._sum.amount || 0) + amount > callerUser.dailyLimit) {
        throw new AppError('Daily spending limit exceeded', 403, 'DAILY_LIMIT_EXCEEDED');
      }
    }

    // Build metadata (track which agent initiated the transaction)
    const txMetadata = isAgent
      ? { initiatedByAgent: callerUser.displayName, agentId: authUserId }
      : undefined;

    // Move cached balances + create transaction record in a single operation
    const [, , tx] = await prisma.$transaction([
      prisma.wallet.update({
        where: { userId: effectiveSenderId },
        data: { usdcBalance: { decrement: amount } },
      }),
      prisma.wallet.update({
        where: { userId: recipientId! },
        data: { usdcBalance: { increment: amount } },
      }),
      prisma.transaction.create({
        data: {
          type: 'TRANSFER',
          status: 'CONFIRMED',
          senderId: effectiveSenderId,
          receiverId: recipientId,
          amount,
          fee: 0,
          fromWallet: senderWallet.publicKey,
          toWallet: receiverWallet.publicKey,
          memo: isAgent ? (memo || `Sent by @${callerUser.displayName}`) : memo,
          metadata: txMetadata ? JSON.parse(JSON.stringify(txMetadata)) : undefined,
          solanaSignature: `demo_${Date.now()}`,
          confirmedAt: new Date(),
        },
      }),
    ]);

    // Notify both parties (notify the parent, not the agent)
    notifyUser(effectiveSenderId, 'transaction.confirmed', { transactionId: tx.id, amount, direction: 'sent' });
    notifyUser(recipientId!, 'transaction.confirmed', { transactionId: tx.id, amount, direction: 'received' });

    res.status(201).json({
      transaction: {
        id: tx.id,
        type: tx.type,
        status: tx.status,
        amount: tx.amount,
        toWallet: tx.toWallet,
        memo: tx.memo,
        createdAt: tx.createdAt,
        confirmedAt: tx.confirmedAt,
        demo: true,
        ...(isAgent && { initiatedBy: callerUser.displayName }),
      },
    });
  });
}
