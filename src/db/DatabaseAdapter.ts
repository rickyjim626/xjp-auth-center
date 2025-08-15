/**
 * 数据库适配器接口 - 统一 TCB 和 MySQL 的数据访问
 */

export interface Tx {
  query<T = any>(sql: string, params?: any[]): Promise<{ rows: T[] }>;
  queryOne<T = any>(sql: string, params?: any[]): Promise<T | null>;
}

export interface DatabaseAdapter {
  query<T = any>(sql: string, params?: any[]): Promise<{ rows: T[] }>;
  queryOne<T = any>(sql: string, params?: any[]): Promise<T | null>;
  tx<T>(fn: (t: Tx) => Promise<T>): Promise<T>;
  close(): Promise<void>;
  healthCheck(): Promise<boolean>;
}

export interface DatabaseConfig {
  provider: 'tcb' | 'mysql';
  url?: string;
  tcb?: {
    envId: string;
    secretId: string;
    secretKey: string;
    sessionToken?: string;
  };
}