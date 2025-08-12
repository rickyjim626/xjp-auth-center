import { createApp } from './app.tcb.js';
import { getConfig } from './config/auth-config.js';
import { logger } from './utils/logger.js';
import { jwtServiceTCB } from './services/jwt.service.tcb.js';
import { TCBDatabase } from './db/tcb-client.js';
import { secretStoreClient } from './services/secret-store.client.js';

async function start() {
  try {
    // Load configuration from Secret Store or environment
    logger.info('Loading configuration...');
    const config = await getConfig();
    
    logger.info(
      { 
        env: config.env,
        tcbEnvId: config.tcb.envId,
        issuer: config.jwt.issuer,
      },
      'Configuration loaded'
    );

    // Test Secret Store connection if configured
    if (config.secretStore.apiKey) {
      const secretStoreHealth = await secretStoreClient.healthCheck();
      logger.info({ secretStoreHealth }, 'Secret Store connection status');
    }

    // Initialize TCB Database
    logger.info('Initializing TCB database...');
    const tcbDb = await TCBDatabase.initialize({
      envId: config.tcb.envId,
      secretId: config.tcb.secretId,
      secretKey: config.tcb.secretKey,
      sessionToken: config.tcb.sessionToken,
    });

    // Test database connection
    const dbHealthy = await tcbDb.healthCheck();
    if (!dbHealthy) {
      throw new Error('TCB database connection failed');
    }
    logger.info('TCB database connected successfully');

    // Initialize JWT service
    await jwtServiceTCB.initialize();
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
      'Auth Center (TCB) started successfully'
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