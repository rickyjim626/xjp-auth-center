import { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { wechatServiceTCB } from '../services/wechat.service.tcb.js';
import { sseService } from '../services/sse.service.js';
import { logger } from '../utils/logger.js';

const qrSchema = z.object({
  client_id: z.string().optional(),
  redirect_uri: z.string().url().optional(),
});

const callbackSchema = z.object({
  code: z.string(),
  state: z.string(),
});

const loginStreamSchema = z.object({
  loginId: z.string(),
});

export async function authRoutesTCB(fastify: FastifyInstance) {
  // Generate WeChat QR code
  fastify.post('/auth/wechat/qr', async (request, reply) => {
    try {
      const body = request.body ? qrSchema.parse(request.body) : {};
      
      const result = await wechatServiceTCB.generateQRCode(
        body.client_id,
        body.redirect_uri
      );

      return reply.send(result);
    } catch (error) {
      logger.error(error, 'Failed to generate QR code');
      return reply.code(500).send({
        error: 'internal_server_error',
        message: 'Failed to generate QR code',
      });
    }
  });

  // WeChat OAuth callback
  fastify.get('/auth/wechat/callback', async (request, reply) => {
    try {
      const query = callbackSchema.parse(request.query);
      
      const result = await wechatServiceTCB.handleCallback(query.code, query.state);

      // Notify SSE clients
      sseService.broadcastLoginStatus(query.state, 'SUCCESS', {
        authCode: result.authCode,
        redirectUri: '/auth/success',
      });

      // Redirect to success page or return JSON
      const acceptHeader = request.headers.accept || '';
      if (acceptHeader.includes('application/json')) {
        return reply.send({
          success: true,
          authCode: result.authCode,
        });
      } else {
        // Redirect to frontend success page
        return reply.redirect(`/auth/success?code=${result.authCode}`);
      }
    } catch (error) {
      logger.error(error, 'WeChat callback failed');
      
      const state = (request.query as any).state;
      if (state) {
        sseService.broadcastLoginStatus(state, 'FAIL', {
          error: 'authentication_failed',
        });
      }

      return reply.code(400).send({
        error: 'authentication_failed',
        message: 'WeChat authentication failed',
      });
    }
  });

  // SSE login status stream
  fastify.get('/auth/login-stream', async (request, reply) => {
    try {
      const query = loginStreamSchema.parse(request.query);
      
      sseService.addClient(query.loginId, reply);

      // Keep connection open
      request.socket.on('close', () => {
        sseService.removeClient(query.loginId);
      });
      
      // Keep the response open for SSE
      return;
    } catch (error) {
      logger.error(error, 'SSE stream setup failed');
      return reply.code(400).send({
        error: 'invalid_request',
        message: 'Invalid login ID',
      });
    }
  });

  // Login ticket status check (polling alternative)
  fastify.get('/auth/login-status/:loginId', async (request, reply) => {
    const { loginId } = request.params as { loginId: string };
    
    try {
      // With stateless design, we don't track login tickets
      // Just return a generic response
      return reply.send({
        status: 'PENDING',
        message: 'Login status tracking not available in stateless mode'
      });
    } catch (error) {
      logger.error(error, 'Failed to get login status');
      return reply.code(500).send({
        error: 'internal_server_error',
        message: 'Failed to get login status',
      });
    }
  });
}