import { readFile } from 'fs/promises';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { db } from './client.js';
import { logger } from '../utils/logger.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

async function migrate() {
  try {
    logger.info('Starting database migration...');
    
    // Read schema file
    const schemaPath = join(__dirname, 'schema.sql');
    const schema = await readFile(schemaPath, 'utf-8');
    
    // Execute schema
    await db.query(schema);
    
    // Insert default data
    await insertDefaults();
    
    logger.info('Database migration completed successfully');
    process.exit(0);
  } catch (error) {
    logger.error(error, 'Database migration failed');
    process.exit(1);
  }
}

async function insertDefaults() {
  // Insert default clients
  await db.query(`
    INSERT INTO clients (id, name, redirect_uris, first_party, allowed_scopes)
    VALUES 
      ('xjp-web', 'XiaoJin Pro Web', ARRAY['https://xiaojinpro.com/callback', 'https://*.xiaojinpro.com/callback'], true, ARRAY['openid', 'profile', 'email']),
      ('xjp-cli', 'XiaoJin Pro CLI', ARRAY['http://localhost:8989/callback', 'xjp://callback'], true, ARRAY['openid', 'profile', 'offline_access'])
    ON CONFLICT (id) DO NOTHING
  `);

  // Insert default roles
  await db.query(`
    INSERT INTO roles (name, description, permissions)
    VALUES 
      ('admin', 'System Administrator', '["users:*", "sessions:*", "audit:*"]'::jsonb),
      ('user', 'Standard User', '["profile:read", "profile:write", "sessions:read"]'::jsonb)
    ON CONFLICT (name) DO NOTHING
  `);

  logger.info('Default data inserted');
}

// Run migration if executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  migrate();
}