import { DatabaseAdapter } from '../db/DatabaseAdapter.js';
import { logger } from '../utils/logger.js';

export interface Identity {
  id: number;
  user_id: number;
  provider: string;
  openid: string;
  unionid?: string;
  profile?: any;
  created_at: Date;
}

export interface CreateIdentityData {
  user_id: number;
  provider: string;
  openid: string;
  unionid?: string;
  profile?: any;
}

export class IdentitiesRepo {
  constructor(private db: DatabaseAdapter) {}

  async findByProviderAndOpenId(provider: string, openid: string): Promise<Identity | null> {
    try {
      return await this.db.queryOne<Identity>(
        'SELECT * FROM identities WHERE provider = ? AND openid = ?',
        [provider, openid]
      );
    } catch (error) {
      logger.error({ error, provider, openid }, 'Failed to find identity by provider and openid');
      throw error;
    }
  }

  async findByUnionId(unionid: string): Promise<Identity | null> {
    try {
      return await this.db.queryOne<Identity>(
        'SELECT * FROM identities WHERE unionid = ?',
        [unionid]
      );
    } catch (error) {
      logger.error({ error, unionid }, 'Failed to find identity by unionid');
      throw error;
    }
  }

  async findByUserId(userId: number): Promise<Identity[]> {
    try {
      const result = await this.db.query<Identity>(
        'SELECT * FROM identities WHERE user_id = ? ORDER BY created_at DESC',
        [userId]
      );
      return result.rows;
    } catch (error) {
      logger.error({ error, userId }, 'Failed to find identities by user id');
      throw error;
    }
  }

  async create(identityData: CreateIdentityData): Promise<Identity> {
    try {
      return await this.db.tx(async (t) => {
        const result = await t.query(
          `INSERT INTO identities (user_id, provider, openid, unionid, profile, created_at)
           VALUES (?, ?, ?, ?, ?, NOW())`,
          [
            identityData.user_id,
            identityData.provider,
            identityData.openid,
            identityData.unionid || null,
            identityData.profile ? JSON.stringify(identityData.profile) : null
          ]
        );

        const insertId = (result as any).insertId;
        const identity = await t.queryOne<Identity>('SELECT * FROM identities WHERE id = ?', [insertId]);
        
        if (!identity) {
          throw new Error('Failed to retrieve created identity');
        }

        logger.info({ identityId: identity.id, userId: identityData.user_id }, 'Identity created successfully');
        return identity;
      });
    } catch (error) {
      logger.error({ error, identityData }, 'Failed to create identity');
      throw error;
    }
  }

  async updateUnionId(id: number, unionid: string): Promise<boolean> {
    try {
      const result = await this.db.query(
        'UPDATE identities SET unionid = ? WHERE id = ?',
        [unionid, id]
      );
      
      const success = (result as any).affectedRows > 0;
      if (success) {
        logger.info({ identityId: id, unionid }, 'Identity unionid updated successfully');
      }
      
      return success;
    } catch (error) {
      logger.error({ error, id, unionid }, 'Failed to update identity unionid');
      throw error;
    }
  }

  async updateProfile(id: number, profile: any): Promise<boolean> {
    try {
      const result = await this.db.query(
        'UPDATE identities SET profile = ? WHERE id = ?',
        [JSON.stringify(profile), id]
      );
      
      const success = (result as any).affectedRows > 0;
      if (success) {
        logger.info({ identityId: id }, 'Identity profile updated successfully');
      }
      
      return success;
    } catch (error) {
      logger.error({ error, id, profile }, 'Failed to update identity profile');
      throw error;
    }
  }

  async delete(id: number): Promise<boolean> {
    try {
      const result = await this.db.query('DELETE FROM identities WHERE id = ?', [id]);
      
      const success = (result as any).affectedRows > 0;
      if (success) {
        logger.info({ identityId: id }, 'Identity deleted successfully');
      }
      
      return success;
    } catch (error) {
      logger.error({ error, id }, 'Failed to delete identity');
      throw error;
    }
  }

  async deleteByUserId(userId: number): Promise<number> {
    try {
      const result = await this.db.query('DELETE FROM identities WHERE user_id = ?', [userId]);
      
      const deletedCount = (result as any).affectedRows;
      logger.info({ userId, deletedCount }, 'User identities deleted successfully');
      
      return deletedCount;
    } catch (error) {
      logger.error({ error, userId }, 'Failed to delete user identities');
      throw error;
    }
  }
}