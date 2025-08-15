import Fastify from 'fastify';
import cors from '@fastify/cors';
import cookie from '@fastify/cookie';
import rateLimit from '@fastify/rate-limit';
import { getConfig } from './config/auth-config.js';
import { logger } from './utils/logger.js';
import { jwtServiceTCB } from './services/jwt.service.tcb.js';
import { authRoutesTCB } from './routes/auth.routes.tcb.js';
import { oauthRoutesTCB } from './routes/oauth.routes.tcb.js';
import { oidcRoutes } from './routes/oidc.routes.js';
import { wechatRoutes } from './routes/wechat.routes.js';
import { usersRoutesTCB } from './routes/users.routes.tcb.js';
import { TCBDatabase } from './db/tcb-client.js';
import { secretStoreClient } from './services/secret-store.client.js';

export async function createApp() {
  const config = await getConfig();
  
  const fastify = Fastify({
    logger: logger as any,
    trustProxy: true,
    requestIdHeader: 'x-request-id',
    requestIdLogLabel: 'reqId',
  });

  // Register plugins
  await fastify.register(cors, {
    origin: (origin, cb) => {
      if (!origin) return cb(null, true);
      
      const allowedOrigins = config.security.corsOrigin;
      const allowed = allowedOrigins.some(pattern => {
        if (pattern.includes('*')) {
          const regex = new RegExp(pattern.replace('*', '.*'));
          return regex.test(origin);
        }
        return pattern === origin;
      });
      
      cb(null, allowed);
    },
    credentials: true,
  });

  await fastify.register(cookie, {
    secret: config.jwt.issuer,
    parseOptions: {
      httpOnly: true,
      secure: config.env === 'production',
      sameSite: 'lax',
    },
  });

  await fastify.register(rateLimit, {
    global: true,
    max: config.security.rateLimitMax,
    timeWindow: config.security.rateLimitWindow,
    cache: 10000,
    keyGenerator: (request) => {
      return request.headers['x-forwarded-for'] as string || 
             request.socket.remoteAddress || 
             'unknown';
    },
    errorResponseBuilder: () => {
      return {
        error: 'rate_limit_exceeded',
        message: 'Too many requests, please try again later',
      };
    },
  });

  // Health check endpoints
  fastify.get('/health/live', async (request, reply) => {
    // Simple liveness check - app is running
    return reply.send('OK');
  });

  fastify.get('/health/ready', async (request, reply) => {
    // Readiness check - app is ready to serve traffic
    // Don't check external dependencies to avoid cascading failures
    return reply.send({ 
      ok: true,
      timestamp: new Date().toISOString(),
      environment: config.env,
      issuer: config.jwt.issuer,
    });
  });

  // Backward compatibility
  fastify.get('/health', async (request, reply) => {
    return reply.redirect('/health/ready');
  });

  fastify.get('/ready', async (request, reply) => {
    return reply.redirect('/health/ready');
  });

  // Register routes
  await fastify.register(authRoutesTCB);
  await fastify.register(oauthRoutesTCB);
  await fastify.register(oidcRoutes);
  await fastify.register(wechatRoutes);
  await fastify.register(usersRoutesTCB);

  // Error handler
  fastify.setErrorHandler((error, request, reply) => {
    logger.error({ error, request: request.raw }, 'Request error');
    
    if (error.validation) {
      return reply.code(400).send({
        error: 'validation_error',
        message: 'Invalid request parameters',
        details: error.validation,
      });
    }
    
    if (error.statusCode) {
      return reply.code(error.statusCode).send({
        error: error.code || 'error',
        message: error.message,
      });
    }
    
    return reply.code(500).send({
      error: 'internal_server_error',
      message: 'An unexpected error occurred',
    });
  });

  // Graceful shutdown
  const gracefulShutdown = async () => {
    logger.info('Shutting down gracefully...');
    
    try {
      await fastify.close();
      const tcbDb = TCBDatabase.getInstance();
      await tcbDb.close();
      logger.info('Server shut down successfully');
      process.exit(0);
    } catch (error) {
      logger.error(error, 'Error during shutdown');
      process.exit(1);
    }
  };

  process.on('SIGTERM', gracefulShutdown);
  process.on('SIGINT', gracefulShutdown);

  return fastify;
}