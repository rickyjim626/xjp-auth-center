import { DatabaseAdapter, DatabaseConfig } from '../db/DatabaseAdapter.js';
import { MySQLAdapter } from '../db/MySQLAdapter.js';
import { TcbAdapter } from '../db/TcbAdapter.js';
import { TCBDatabase } from '../db/tcb-client.js';
import { logger } from '../utils/logger.js';

/**
 * 数据库适配器工厂
 * 根据配置创建对应的数据库适配器
 */
export async function createDatabaseAdapter(config: DatabaseConfig): Promise<DatabaseAdapter> {
  logger.info({ provider: config.provider }, 'Creating database adapter');

  switch (config.provider) {
    case 'mysql':
      if (!config.url) {
        throw new Error('MySQL connection URL is required');
      }
      return new MySQLAdapter(config.url);

    case 'tcb':
      if (!config.tcb) {
        throw new Error('TCB configuration is required');
      }
      
      const tcbDb = await TCBDatabase.initialize({
        envId: config.tcb.envId,
        secretId: config.tcb.secretId,
        secretKey: config.tcb.secretKey,
        sessionToken: config.tcb.sessionToken,
      });
      
      return new TcbAdapter(tcbDb);

    default:
      throw new Error(`Unsupported database provider: ${config.provider}`);
  }
}

// 全局数据库适配器实例
let databaseAdapter: DatabaseAdapter;

export async function initializeDatabaseAdapter(config: DatabaseConfig): Promise<DatabaseAdapter> {
  if (!databaseAdapter) {
    databaseAdapter = await createDatabaseAdapter(config);
    
    // 健康检查
    const isHealthy = await databaseAdapter.healthCheck();
    if (!isHealthy) {
      throw new Error('Database health check failed');
    }
    
    logger.info('Database adapter initialized successfully');
  }
  
  return databaseAdapter;
}

export function getDatabaseAdapter(): DatabaseAdapter {
  if (!databaseAdapter) {
    throw new Error('Database adapter not initialized. Call initializeDatabaseAdapter() first.');
  }
  return databaseAdapter;
}

export async function closeDatabaseAdapter(): Promise<void> {
  if (databaseAdapter) {
    await databaseAdapter.close();
    logger.info('Database adapter closed');
  }
}