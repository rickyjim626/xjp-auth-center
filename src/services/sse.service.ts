import { FastifyReply } from 'fastify';
import { logger } from '../utils/logger.js';

interface SSEClient {
  loginId: string;
  reply: FastifyReply;
  heartbeat?: NodeJS.Timeout;
}

export class SSEService {
  private static instance: SSEService;
  private clients: Map<string, SSEClient> = new Map();

  private constructor() {}

  static getInstance(): SSEService {
    if (!SSEService.instance) {
      SSEService.instance = new SSEService();
    }
    return SSEService.instance;
  }

  addClient(loginId: string, reply: FastifyReply): void {
    // Remove existing client if any
    this.removeClient(loginId);

    // Set up SSE headers
    reply.raw.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
      'X-Accel-Buffering': 'no', // Disable Nginx buffering
    });

    // Send initial event
    this.sendEvent(reply, 'connected', { status: 'PENDING' });

    // Set up heartbeat
    const heartbeat = setInterval(() => {
      try {
        reply.raw.write(':heartbeat\n\n');
      } catch (error) {
        logger.debug({ loginId }, 'SSE heartbeat failed, removing client');
        this.removeClient(loginId);
      }
    }, 30000); // 30 seconds

    // Store client
    this.clients.set(loginId, { loginId, reply, heartbeat });

    // Handle client disconnect
    reply.raw.on('close', () => {
      logger.debug({ loginId }, 'SSE client disconnected');
      this.removeClient(loginId);
    });

    logger.info({ loginId }, 'SSE client connected');
  }

  removeClient(loginId: string): void {
    const client = this.clients.get(loginId);
    if (client) {
      if (client.heartbeat) {
        clearInterval(client.heartbeat);
      }
      this.clients.delete(loginId);
      logger.debug({ loginId }, 'SSE client removed');
    }
  }

  sendToClient(loginId: string, event: string, data: any): boolean {
    const client = this.clients.get(loginId);
    if (!client) {
      return false;
    }

    try {
      this.sendEvent(client.reply, event, data);
      return true;
    } catch (error) {
      logger.error({ loginId, error }, 'Failed to send SSE event');
      this.removeClient(loginId);
      return false;
    }
  }

  private sendEvent(reply: FastifyReply, event: string, data: any): void {
    const message = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
    reply.raw.write(message);
  }

  broadcastLoginStatus(loginId: string, status: string, result?: any): void {
    const data = { status, ...result };
    
    if (this.sendToClient(loginId, status.toLowerCase(), data)) {
      logger.info({ loginId, status }, 'Broadcasted login status via SSE');
    } else {
      logger.debug({ loginId, status }, 'No SSE client found for login status update');
    }

    // Clean up client after success/fail
    if (status === 'SUCCESS' || status === 'FAIL' || status === 'TIMEOUT') {
      setTimeout(() => this.removeClient(loginId), 5000);
    }
  }

  getActiveClients(): number {
    return this.clients.size;
  }
}

export const sseService = SSEService.getInstance();