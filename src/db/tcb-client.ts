import tcb from '@cloudbase/node-sdk';
import { logger } from '../utils/logger.js';

export interface TCBConfig {
  envId: string;
  secretId: string;
  secretKey: string;
  sessionToken?: string;
}

// Type definitions using inference
export type TcbDb = any; // TCB Database type
export type TcbCollection<T = any> = any; // TCB Collection type
export type TcbTransaction = any; // TCB Transaction type

export class TCBDatabase {
  private static instance: TCBDatabase;
  private app: any;
  private database: any;
  public readonly db: any;
  public readonly _: any; // Command object

  private constructor(config: TCBConfig) {
    this.app = tcb.init({
      env: config.envId,
      secretId: config.secretId,
      secretKey: config.secretKey,
      ...(config.sessionToken && { sessionToken: config.sessionToken }),
      timeout: 5000,
    });

    this.database = this.app.database();
    this.db = this.database;
    this._ = (this.database as any).command;
  }

  static async initialize(config: TCBConfig): Promise<TCBDatabase> {
    if (!TCBDatabase.instance) {
      TCBDatabase.instance = new TCBDatabase(config);
      await TCBDatabase.instance.createCollectionsAndIndexes();
    }
    return TCBDatabase.instance;
  }

  static getInstance(): TCBDatabase {
    if (!TCBDatabase.instance) {
      throw new Error('TCB Database not initialized. Call initialize() first.');
    }
    return TCBDatabase.instance;
  }

  collection(name: string): any {
    return this.database.collection(name);
  }

  async startTransaction(): Promise<any> {
    return (this.database as any).startTransaction();
  }

  async createCollectionsAndIndexes(): Promise<void> {
    try {
      // Collections to create (simplified 6-table design)
      const collections = [
        'users',
        'identities', 
        'clients',
        'auth_codes',
        'tokens',
        'jwks',
      ];

      logger.info('Setting up TCB collection indexes...');

      // Index definitions (simplified 6-table design)
      const indexDefinitions = [
        // users collection
        { collection: 'users', field: 'createdAt', type: 'normal' },
        { collection: 'users', field: 'isDisabled', type: 'normal' },

        // identities collection
        { collection: 'identities', fields: ['provider', 'openid'], type: 'unique_compound' },
        { collection: 'identities', field: 'unionid', type: 'normal' },
        { collection: 'identities', field: 'userId', type: 'normal' },

        // clients collection
        { collection: 'clients', field: 'clientId', type: 'unique' },

        // auth_codes (with TTL)
        { collection: 'auth_codes', field: 'code', type: 'unique' },
        { collection: 'auth_codes', field: 'expiresAt', type: 'ttl', ttl: 0 },

        // tokens (combined access/refresh tokens)
        { collection: 'tokens', field: 'jti', type: 'unique' },
        { collection: 'tokens', field: 'userId', type: 'normal' },
        { collection: 'tokens', field: 'sessionId', type: 'normal' },
        { collection: 'tokens', field: 'refreshTokenJti', type: 'normal' },

        // jwks collection
        { collection: 'jwks', field: 'keyId', type: 'unique' },
        { collection: 'jwks', field: 'isActive', type: 'normal' },
      ];

      logger.info(
        { indexCount: indexDefinitions.length },
        'TCB indexes should be configured in console or via admin API'
      );

      // Initialize default data
      await this.initializeDefaultData();

    } catch (error) {
      logger.error(error, 'Failed to set up TCB collections and indexes');
      throw error;
    }
  }

  private async initializeDefaultData(): Promise<void> {
    try {
      // Check if default clients exist
      const clientsCol = this.collection('clients');
      const existingClients = await clientsCol
        .where({ clientId: this._.in(['xjp-web', 'xjp-cli']) })
        .get();

      if (!existingClients.data || existingClients.data.length === 0) {
        // Insert default OAuth clients
        await clientsCol.add({
          clientId: 'xjp-web',
          name: 'XiaoJin Pro Web',
          redirectUris: ['https://xiaojinpro.com/callback', 'https://*.xiaojinpro.com/callback'],
          firstParty: true,
          allowedScopes: ['openid', 'profile', 'email'],
          isDisabled: false,
          createdAt: new Date(),
        });

        await clientsCol.add({
          clientId: 'xjp-cli',
          name: 'XiaoJin Pro CLI',
          redirectUris: ['http://localhost:8989/callback', 'xjp://callback'],
          firstParty: true,
          allowedScopes: ['openid', 'profile', 'offline_access'],
          isDisabled: false,
          createdAt: new Date(),
        });

        logger.info('Default OAuth clients created');
      }
    } catch (error) {
      logger.error(error, 'Failed to initialize default data');
    }
  }

  async healthCheck(): Promise<boolean> {
    try {
      // Simple read test
      const result = await this.collection('clients')
        .limit(1)
        .get();
      return true;
    } catch (error) {
      logger.error(error, 'TCB health check failed');
      return false;
    }
  }

  async close(): Promise<void> {
    // TCB SDK doesn't require explicit connection closing
    logger.info('TCB connection closed');
  }
}

// Helper functions for common queries
export async function findOne<T = any>(
  collection: string,
  where: any
): Promise<T | null> {
  const db = TCBDatabase.getInstance();
  const result = await db.collection(collection)
    .where(where)
    .limit(1)
    .get();
  
  return result.data && result.data.length > 0 ? result.data[0] as T : null;
}

export async function findMany<T = any>(
  collection: string,
  where: any,
  options?: { limit?: number; offset?: number; orderBy?: { field: string; order: 'asc' | 'desc' } }
): Promise<T[]> {
  const db = TCBDatabase.getInstance();
  let query = db.collection(collection).where(where);
  
  if (options?.orderBy) {
    query = query.orderBy(options.orderBy.field, options.orderBy.order);
  }
  
  if (options?.offset) {
    query = query.skip(options.offset);
  }
  
  if (options?.limit) {
    query = query.limit(options.limit);
  }
  
  const result = await query.get();
  return (result.data || []) as T[];
}

export async function insertOne(
  collection: string,
  data: any
): Promise<string> {
  const db = TCBDatabase.getInstance();
  const result = await db.collection(collection).add({
    ...data,
    _createTime: new Date(),
    _updateTime: new Date(),
  });
  
  return result.id;
}

export async function updateOne(
  collection: string,
  where: any,
  data: any
): Promise<boolean> {
  const db = TCBDatabase.getInstance();
  const result = await db.collection(collection)
    .where(where)
    .update({
      ...data,
      _updateTime: new Date(),
    });
  
  return result.updated > 0;
}

export async function deleteOne(
  collection: string,
  where: any
): Promise<boolean> {
  const db = TCBDatabase.getInstance();
  const result = await db.collection(collection)
    .where(where)
    .remove();
  
  return result.deleted > 0;
}