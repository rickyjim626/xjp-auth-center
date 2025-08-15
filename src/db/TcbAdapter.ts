import { DatabaseAdapter, Tx } from './DatabaseAdapter.js';
import { TCBDatabase, findOne, findMany, insertOne, updateOne, deleteOne } from './tcb-client.js';
import { logger } from '../utils/logger.js';

/**
 * TCB 适配器 - 将现有 TCB 操作封装为统一接口
 * 这是过渡期间的兼容层，保持现有 TCB 代码可用
 */
export class TcbAdapter implements DatabaseAdapter {
  private tcbDb: TCBDatabase;

  constructor(tcbDb: TCBDatabase) {
    this.tcbDb = tcbDb;
  }

  async query<T = any>(collection: string, filter?: any, options?: any): Promise<{ rows: T[] }> {
    try {
      if (filter) {
        const results = await findMany<T>(collection, filter, options);
        return { rows: results };
      } else {
        // 类似 SELECT * FROM collection 的操作
        const results = await findMany<T>(collection, {}, options);
        return { rows: results };
      }
    } catch (error) {
      logger.error({ collection, filter, error }, 'TCB query failed');
      throw error;
    }
  }

  async queryOne<T = any>(collection: string, filter: any): Promise<T | null> {
    try {
      return await findOne<T>(collection, filter);
    } catch (error) {
      logger.error({ collection, filter, error }, 'TCB queryOne failed');
      throw error;
    }
  }

  async tx<T>(fn: (t: Tx) => Promise<T>): Promise<T> {
    // TCB 事务模拟
    const transaction = await this.tcbDb.startTransaction();
    
    try {
      const tx: Tx = {
        query: async <U>(collection: string, filter?: any, options?: any) => {
          // 在事务中执行查询 (TCB 事务 API)
          const results = await transaction.collection(collection).where(filter || {}).get();
          return { rows: (results.data || []) as U[] };
        },
        queryOne: async <U>(collection: string, filter: any) => {
          const result = await tx.query<U>(collection, filter);
          return result.rows[0] || null;
        }
      };

      const result = await fn(tx);
      await transaction.commit();
      return result;
    } catch (error) {
      await transaction.rollback();
      logger.error({ error }, 'TCB transaction failed');
      throw error;
    }
  }

  async healthCheck(): Promise<boolean> {
    return await this.tcbDb.healthCheck();
  }

  async close(): Promise<void> {
    await this.tcbDb.close();
  }

  // TCB 特有的便捷方法，向后兼容
  async findOne<T>(collection: string, filter: any): Promise<T | null> {
    return findOne<T>(collection, filter);
  }

  async findMany<T>(collection: string, filter: any, options?: any): Promise<T[]> {
    return findMany<T>(collection, filter, options);
  }

  async insertOne(collection: string, data: any): Promise<string> {
    return insertOne(collection, data);
  }

  async updateOne(collection: string, filter: any, data: any): Promise<boolean> {
    return updateOne(collection, filter, data);
  }

  async deleteOne(collection: string, filter: any): Promise<boolean> {
    return deleteOne(collection, filter);
  }
}