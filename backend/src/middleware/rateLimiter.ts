import { Request, Response, NextFunction } from 'express';
import { RateLimiterMemory } from 'rate-limiter-flexible';

const limiter = new RateLimiterMemory({
  points: parseInt(process.env.RATE_LIMIT_POINTS || '60'),
  duration: parseInt(process.env.RATE_LIMIT_DURATION || '60'),
});

export async function rateLimiter(req: Request, res: Response, next: NextFunction): Promise<void> {
  try {
    const key = req.ip || 'unknown';
    await limiter.consume(key);
    next();
  } catch {
    res.status(429).json({ error: 'Too many requests', code: 'RATE_LIMITED' });
  }
}
