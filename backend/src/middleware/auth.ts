import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { PrismaClient } from '@prisma/client';
import crypto from 'crypto';

const prisma = new PrismaClient();

export interface AuthPayload {
  userId: string;
  type: 'HUMAN' | 'AGENT';
}

declare global {
  namespace Express {
    interface Request {
      user?: AuthPayload;
    }
  }
}

// Hash API key for secure lookup
export function hashApiKey(key: string): string {
  return crypto.createHash('sha256').update(key).digest('hex');
}

// Generate a new API key
export function generateApiKey(): string {
  const prefix = process.env.API_KEY_PREFIX || 'agentpay_';
  const random = crypto.randomBytes(32).toString('hex');
  return `${prefix}${random}`;
}

// Authenticate via JWT (humans) or API key (agents)
export async function authenticate(req: Request, res: Response, next: NextFunction): Promise<void> {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    res.status(401).json({ error: 'Missing authorization header' });
    return;
  }

  // API Key auth: "Bearer agentpay_..."
  if (authHeader.startsWith('Bearer agentpay_') || authHeader.startsWith('Bearer ' + (process.env.API_KEY_PREFIX || 'agentpay_'))) {
    const apiKey = authHeader.replace('Bearer ', '');
    const keyHash = hashApiKey(apiKey);

    const user = await prisma.user.findFirst({ where: { apiKeyHash: keyHash } });
    if (!user) {
      res.status(401).json({ error: 'Invalid API key' });
      return;
    }

    req.user = { userId: user.id, type: user.type as 'HUMAN' | 'AGENT' };
    next();
    return;
  }

  // JWT auth: "Bearer eyJ..."
  if (authHeader.startsWith('Bearer ')) {
    const token = authHeader.replace('Bearer ', '');
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET || 'change-me') as AuthPayload;
      req.user = decoded;
      next();
    } catch {
      res.status(401).json({ error: 'Invalid or expired token' });
    }
    return;
  }

  res.status(401).json({ error: 'Invalid authorization format' });
}

// Require specific user type
export function requireType(type: 'HUMAN' | 'AGENT') {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!req.user) {
      res.status(401).json({ error: 'Not authenticated' });
      return;
    }
    if (req.user.type !== type) {
      res.status(403).json({ error: `This endpoint requires ${type} authentication` });
      return;
    }
    next();
  };
}
