import { WebSocketServer, WebSocket } from 'ws';
import jwt from 'jsonwebtoken';
import { AuthPayload } from '../middleware/auth';

interface AuthenticatedWs extends WebSocket {
  userId?: string;
  isAlive?: boolean;
}

const clients = new Map<string, Set<AuthenticatedWs>>();

export function setupWebSocket(wss: WebSocketServer): void {
  // Heartbeat interval
  const heartbeat = setInterval(() => {
    wss.clients.forEach((ws) => {
      const authWs = ws as AuthenticatedWs;
      if (!authWs.isAlive) {
        authWs.terminate();
        return;
      }
      authWs.isAlive = false;
      authWs.ping();
    });
  }, 30000);

  wss.on('close', () => clearInterval(heartbeat));

  wss.on('connection', (ws: AuthenticatedWs, req) => {
    ws.isAlive = true;
    ws.on('pong', () => { ws.isAlive = true; });

    // Authenticate via query param: ?token=<jwt_or_apikey>
    const url = new URL(req.url || '', `http://${req.headers.host}`);
    const token = url.searchParams.get('token');

    if (!token) {
      ws.close(4001, 'Missing auth token');
      return;
    }

    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET || 'change-me') as AuthPayload;
      ws.userId = decoded.userId;

      // Track client
      if (!clients.has(decoded.userId)) {
        clients.set(decoded.userId, new Set());
      }
      clients.get(decoded.userId)!.add(ws);

      ws.send(JSON.stringify({ type: 'connected', userId: decoded.userId }));

      ws.on('close', () => {
        const userClients = clients.get(decoded.userId);
        if (userClients) {
          userClients.delete(ws);
          if (userClients.size === 0) clients.delete(decoded.userId);
        }
      });
    } catch {
      ws.close(4002, 'Invalid auth token');
    }
  });
}

// Notify a user of a transaction event
export function notifyUser(userId: string, event: string, data: Record<string, unknown>): void {
  const userClients = clients.get(userId);
  if (!userClients) return;

  const message = JSON.stringify({ type: event, data, timestamp: new Date().toISOString() });
  userClients.forEach((ws) => {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(message);
    }
  });
}
