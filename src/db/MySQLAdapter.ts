import mysql from 'mysql2/promise';
import { DatabaseAdapter, Tx } from './DatabaseAdapter.js';
import { logger } from '../utils/logger.js';

export class MySQLAdapter implements DatabaseAdapter {
  private pool: mysql.Pool;

  constructor(connectionString: string, maxConnections = 20) {
    this.pool = mysql.createPool({
      uri: connectionString,
      connectionLimit: maxConnections,
      charset: 'utf8mb4',
    });
    
    logger.info('MySQL connection pool created');
  }

  async query<T = any>(sql: string, params?: any[]): Promise<{ rows: T[] }> {
    try {
      const [rows] = await this.pool.execute(sql, params);
      return { rows: rows as T[] };
    } catch (error) {
      logger.error({ sql, params, error }, 'MySQL query failed');
      throw error;
    }
  }

  async queryOne<T = any>(sql: string, params?: any[]): Promise<T | null> {
    const result = await this.query<T>(sql, params);
    return result.rows[0] || null;
  }

  async tx<T>(fn: (t: Tx) => Promise<T>): Promise<T> {
    const connection = await this.pool.getConnection();
    
    try {
      await connection.beginTransaction();
      
      const tx: Tx = {
        query: async <U>(sql: string, params?: any[]) => {
          const [rows] = await connection.execute(sql, params);
          return { rows: rows as U[] };
        },
        queryOne: async <U>(sql: string, params?: any[]) => {
          const result = await tx.query<U>(sql, params);
          return result.rows[0] || null;
        }
      };

      const result = await fn(tx);
      await connection.commit();
      return result;
    } catch (error) {
      await connection.rollback();
      logger.error({ error }, 'MySQL transaction failed');
      throw error;
    } finally {
      connection.release();
    }
  }

  async healthCheck(): Promise<boolean> {
    try {
      await this.query('SELECT 1 as healthy');
      return true;
    } catch (error) {
      logger.error({ error }, 'MySQL health check failed');
      return false;
    }
  }

  async close(): Promise<void> {
    await this.pool.end();
    logger.info('MySQL connection pool closed');
  }
}