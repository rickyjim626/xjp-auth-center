import Fastify, { FastifyInstance } from 'fastify';
import { getConfig } from './config/auth-config.js';
import { logger } from './utils/logger.js';

// Import routes
import { authRoutes } from './routes/auth.routes.js';
import { oauthRoutes } from './routes/oauth.routes.js';
import { usersRoutes } from './routes/users.routes.js';
import { healthRoutes } from './routes/health.routes.js';

export async function createApp(): Promise<FastifyInstance> {
  const config = await getConfig();
  
  const app = Fastify({
    logger: false, // Use our custom logger instead
    bodyLimit: 1048576, // 1MB
    maxParamLength: 1000,
  });

  // CORS setup
  await app.register(import('@fastify/cors'), {
    origin: config.security.corsOrigin,
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'Accept'],
  });

  // Cookie support
  await app.register(import('@fastify/cookie'), {
    secret: config.cookie.secret,
    parseOptions: {
      secure: config.cookie.secure,
      sameSite: config.cookie.sameSite,
      httpOnly: true,
      maxAge: config.cookie.sessionExpires,
    },
  });

  // Rate limiting
  await app.register(import('@fastify/rate-limit'), {
    max: config.security.rateLimitMax,
    timeWindow: config.security.rateLimitWindow,
    errorResponseBuilder: () => ({
      error: 'rate_limit_exceeded',
      message: 'Too many requests',
    }),
  });

  // Request logging middleware
  app.addHook('onRequest', async (request, reply) => {
    logger.info({
      method: request.method,
      url: request.url,
      userAgent: request.headers['user-agent'],
      ip: request.ip,
    }, 'Request received');
  });

  // Response logging middleware
  app.addHook('onSend', async (request, reply, payload) => {
    logger.info({
      method: request.method,
      url: request.url,
      statusCode: reply.statusCode,
      responseTime: reply.getResponseTime(),
    }, 'Request completed');
  });

  // Error handler
  app.setErrorHandler(async (error, request, reply) => {
    logger.error({
      error: error.message,
      stack: error.stack,
      method: request.method,
      url: request.url,
    }, 'Request error');

    const statusCode = error.statusCode || 500;
    const response = {
      error: error.name || 'internal_server_error',
      message: statusCode >= 500 ? 'Internal server error' : error.message,
    };

    return reply.status(statusCode).send(response);
  });

  // Register routes
  await app.register(healthRoutes);
  await app.register(authRoutes);
  await app.register(oauthRoutes);
  await app.register(usersRoutes);

  // 404 handler
  app.setNotFoundHandler(async (request, reply) => {
    logger.warn({
      method: request.method,
      url: request.url,
    }, 'Route not found');

    return reply.status(404).send({
      error: 'not_found',
      message: 'Route not found',
    });
  });

  return app;
}