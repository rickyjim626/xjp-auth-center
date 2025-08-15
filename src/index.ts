import { createApp } from './app.js';
import { getConfig } from './config/auth-config.js';
import { logger } from './utils/logger.js';
import { initializeDatabaseAdapter, closeDatabaseAdapter } from './infra/database.js';
import { createRedisManager } from './infra/redis.js';
import { RepositoryFactory } from './repos/index.js';
// Migration handled separately via npm run migrate

async function start() {
  try {
    // Load configuration
    logger.info('Loading configuration...');
    const config = await getConfig();
    
    logger.info({
      env: config.env,
      dbProvider: config.database.provider,
      redisEnabled: config.redis.enabled,
      issuer: config.jwt.issuer,
    }, 'Configuration loaded');

    // Initialize database adapter
    logger.info('Initializing database...');
    const dbAdapter = await initializeDatabaseAdapter({
      provider: config.database.provider,
      url: config.database.url,
      tcb: config.database.provider === 'tcb' ? {
        envId: config.tcb.envId,
        secretId: config.tcb.secretId,
        secretKey: config.tcb.secretKey,
        sessionToken: config.tcb.sessionToken,
      } : undefined,
    });

    // Note: Migrations should be run separately with `npm run migrate`
    // This avoids including script files in the main source tree

    // Initialize Redis manager
    const redisManager = createRedisManager(config.redis.url, config.redis.enabled);
    if (config.redis.enabled) {
      await redisManager.connect();
      const redisHealthy = await redisManager.ping();
      logger.info({ redisHealthy }, 'Redis connection status');
    }

    // Initialize repositories
    RepositoryFactory.initialize(dbAdapter);
    logger.info('Repository layer initialized');

    // Test database connection
    const dbHealthy = await dbAdapter.healthCheck();
    if (!dbHealthy) {
      throw new Error('Database health check failed');
    }
    logger.info('Database connection verified');

    // Create and start server
    const app = await createApp();
    
    await app.listen({
      port: config.server.port,
      host: config.server.host,
    });

    logger.info({
      port: config.server.port,
      host: config.server.host,
      env: config.env,
      dbProvider: config.database.provider,
    }, 'Auth Center started successfully');

    // Log important endpoints
    logger.info('Available endpoints:');
    logger.info('  POST   /auth/wechat/qr        - Generate WeChat QR code');
    logger.info('  GET    /auth/wechat/callback  - WeChat OAuth callback');
    logger.info('  GET    /auth/login-stream     - SSE login status stream');
    logger.info('  POST   /oauth2/token          - Exchange code/refresh for tokens');
    logger.info('  GET    /.well-known/jwks.json - Public keys for verification');
    logger.info('  GET    /v1/users/me           - Get current user');
    logger.info('  GET    /v1/sessions           - List user sessions');
    logger.info('  GET    /health/ready          - Health check');

  } catch (error) {
    logger.fatal(error, 'Failed to start Auth Center');
    process.exit(1);
  }
}

// Handle graceful shutdown
async function shutdown() {
  logger.info('Shutting down Auth Center...');
  
  try {
    const redisManager = createRedisManager();
    await redisManager.disconnect();
    await closeDatabaseAdapter();
    logger.info('Cleanup completed');
    process.exit(0);
  } catch (error) {
    logger.error(error, 'Error during shutdown');
    process.exit(1);
  }
}

// Handle uncaught errors
process.on('uncaughtException', (error) => {
  logger.fatal(error, 'Uncaught exception');
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  logger.fatal({ reason, promise }, 'Unhandled rejection');
  process.exit(1);
});

// Handle graceful shutdown signals
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);

// Start the server
start();