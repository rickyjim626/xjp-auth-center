import { FastifyPluginAsync } from 'fastify';
import { getDatabaseAdapter } from '../infra/database.js';
import { getRedisManager } from '../infra/redis.js';
import { logger } from '../utils/logger.js';

export const healthRoutes: FastifyPluginAsync = async (fastify) => {
  // Liveness probe - basic health check
  fastify.get('/health/live', async (request, reply) => {
    return reply.send({
      status: 'ok',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
    });
  });

  // Readiness probe - check all dependencies
  fastify.get('/health/ready', async (request, reply) => {
    const checks: Record<string, any> = {
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
    };

    let allHealthy = true;

    // Check database
    try {
      const db = getDatabaseAdapter();
      const dbHealthy = await db.healthCheck();
      checks.database = {
        status: dbHealthy ? 'healthy' : 'unhealthy',
        provider: 'unknown', // Can be enhanced to show actual provider
      };
      if (!dbHealthy) allHealthy = false;
    } catch (error) {
      checks.database = {
        status: 'error',
        error: (error as Error).message,
      };
      allHealthy = false;
    }

    // Check Redis (if enabled)
    try {
      const redis = getRedisManager();
      const redisHealthy = await redis.ping();
      checks.redis = {
        status: redisHealthy ? 'healthy' : 'unhealthy',
      };
      if (!redisHealthy) allHealthy = false;
    } catch (error) {
      checks.redis = {
        status: 'disabled_or_error',
        error: (error as Error).message,
      };
      // Redis is optional, so don't mark as unhealthy
    }

    const statusCode = allHealthy ? 200 : 503;
    const status = allHealthy ? 'healthy' : 'unhealthy';

    if (!allHealthy) {
      logger.warn({ checks }, 'Health check failed');
    }

    return reply.status(statusCode).send({
      status,
      checks,
    });
  });

  // Legacy health check endpoint
  fastify.get('/health', async (request, reply) => {
    return reply.redirect(301, '/health/ready');
  });
};