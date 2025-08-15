#!/usr/bin/env node

/**
 * Database migration script
 * 用于初始化 MySQL 数据库 Schema
 */

import { readFileSync } from 'fs';
import { join } from 'path';
import { MySQLAdapter } from '../src/db/MySQLAdapter.js';
import { logger } from '../src/utils/logger.js';
import { getConfig } from '../src/config/auth-config.js';

async function migrate() {
  try {
    logger.info('Starting database migration...');
    
    const config = await getConfig();
    
    if (config.database.provider !== 'mysql') {
      logger.info('Database provider is not MySQL, skipping migration');
      return;
    }
    
    if (!config.database.url) {
      throw new Error('Database URL is required for migration');
    }
    
    // 创建数据库连接
    const db = new MySQLAdapter(config.database.url);
    
    // 读取 Schema 文件
    const schemaPath = join(process.cwd(), 'scripts/mysql-schema.sql');
    const schemaSql = readFileSync(schemaPath, 'utf-8');
    
    // 分割 SQL 语句 (简单按分号分割)
    const statements = schemaSql
      .split(';')
      .map(stmt => stmt.trim())
      .filter(stmt => stmt.length > 0 && !stmt.startsWith('--'));
    
    logger.info(`Executing ${statements.length} SQL statements...`);
    
    // 执行每个 SQL 语句
    for (const statement of statements) {
      if (statement.toUpperCase().includes('DELIMITER')) {
        // 跳过存储过程分隔符语句 (需要特殊处理)
        continue;
      }
      
      try {
        await db.query(statement);
        logger.debug(`Executed: ${statement.substring(0, 50)}...`);
      } catch (error) {
        logger.error({ error, statement: statement.substring(0, 100) }, 'Failed to execute statement');
        throw error;
      }
    }
    
    // 验证关键表是否创建成功
    const tables = ['users', 'oauth_clients', 'auth_codes', 'tokens', 'jwks', 'identities'];
    for (const table of tables) {
      const result = await db.query(`SHOW TABLES LIKE ?`, [table]);
      if (result.rows.length === 0) {
        throw new Error(`Table ${table} was not created`);
      }
    }
    
    logger.info('Database migration completed successfully');
    
    await db.close();
    
  } catch (error) {
    logger.error({ error }, 'Database migration failed');
    process.exit(1);
  }
}

// 如果直接运行此脚本
if (import.meta.url === `file://${process.argv[1]}`) {
  migrate();
}

export { migrate };