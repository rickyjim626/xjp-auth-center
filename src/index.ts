import { createApp } from './app.js';
import { config } from './config/index.js';
import { logger } from './utils/logger.js';
import { jwtService } from './services/jwt.service.js';
import { db } from './db/client.js';

async function start() {
  try {
    // Test database connection
    const dbHealthy = await db.healthCheck();
    if (!dbHealthy) {
      throw new Error('Database connection failed');
    }
    logger.info('Database connected successfully');

    // Initialize JWT service
    await jwtService.initialize();
    logger.info('JWT service initialized');

    // Create and start server
    const app = await createApp();
    
    await app.listen({
      port: config.server.port,
      host: config.server.host,
    });

    logger.info(
      { 
        port: config.server.port, 
        host: config.server.host,
        env: config.env,
      },
      'Auth Center started successfully'
    );

    // Log important endpoints
    logger.info('Available endpoints:');
    logger.info('  POST   /auth/wechat/qr        - Generate WeChat QR code');
    logger.info('  GET    /auth/wechat/callback  - WeChat OAuth callback');
    logger.info('  GET    /auth/login-stream     - SSE login status stream');
    logger.info('  POST   /oauth/token           - Exchange code/refresh for tokens');
    logger.info('  GET    /.well-known/jwks.json - Public keys for verification');
    logger.info('  GET    /v1/users/me           - Get current user');
    logger.info('  GET    /v1/sessions           - List user sessions');
    logger.info('  GET    /health                - Health check');

  } catch (error) {
    logger.fatal(error, 'Failed to start Auth Center');
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

// Start the server
start();