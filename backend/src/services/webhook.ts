import { PrismaClient } from '@prisma/client';
import crypto from 'crypto';

const prisma = new PrismaClient();

// Sign webhook payload with HMAC
function signPayload(payload: string, secret: string): string {
  return crypto.createHmac('sha256', secret).update(payload).digest('hex');
}

// Dispatch webhook events to all registered listeners
export async function dispatchWebhook(
  userId: string,
  event: string,
  data: Record<string, unknown>
): Promise<void> {
  const allWebhooks = await prisma.webhook.findMany({
    where: {
      userId,
      isActive: true,
    },
  });

  // Filter webhooks that subscribe to this event (events stored as JSON string)
  const webhooks = allWebhooks.filter(wh => {
    const events: string[] = JSON.parse(wh.events);
    return events.includes(event);
  });

  const payload = JSON.stringify({ event, data, timestamp: new Date().toISOString() });

  for (const webhook of webhooks) {
    const signature = signPayload(payload, webhook.secret);

    try {
      await fetch(webhook.url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-AgentPay-Signature': signature,
          'X-AgentPay-Event': event,
        },
        body: payload,
        signal: AbortSignal.timeout(10000),
      });
    } catch (err) {
      console.error(`Webhook delivery failed for ${webhook.id}:`, err);
    }
  }
}
