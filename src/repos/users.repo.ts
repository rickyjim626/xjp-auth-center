import { DatabaseAdapter } from '../db/DatabaseAdapter.js';
import { logger } from '../utils/logger.js';

export interface User {
  id: number;
  unionid?: string;
  openid_mp?: string;
  openid_open?: string;
  nickname?: string;
  avatar?: string;
  email?: string;
  is_admin: boolean;
  is_disabled: boolean;
  created_at: Date;
  updated_at: Date;
  last_login_at?: Date;
}

export interface CreateUserData {
  unionid?: string;
  openid_mp?: string;
  openid_open?: string;
  nickname?: string;
  avatar?: string;
  email?: string;
  is_admin?: boolean;
}

export interface UpdateUserData {
  nickname?: string;
  avatar?: string;
  email?: string;
  last_login_at?: Date;
}

export class UsersRepo {
  constructor(private db: DatabaseAdapter) {}

  async findById(id: number): Promise<User | null> {
    try {
      return await this.db.queryOne<User>(
        'SELECT * FROM users WHERE id = ?',
        [id]
      );
    } catch (error) {
      logger.error({ error, id }, 'Failed to find user by id');
      throw error;
    }
  }

  async findByUnionId(unionid: string): Promise<User | null> {
    try {
      return await this.db.queryOne<User>(
        'SELECT * FROM users WHERE unionid = ?',
        [unionid]
      );
    } catch (error) {
      logger.error({ error, unionid }, 'Failed to find user by unionid');
      throw error;
    }
  }

  async findByOpenId(openid: string, provider: 'mp' | 'open'): Promise<User | null> {
    try {
      const column = provider === 'mp' ? 'openid_mp' : 'openid_open';
      return await this.db.queryOne<User>(
        `SELECT * FROM users WHERE ${column} = ?`,
        [openid]
      );
    } catch (error) {
      logger.error({ error, openid, provider }, 'Failed to find user by openid');
      throw error;
    }
  }

  async create(userData: CreateUserData): Promise<User> {
    try {
      return await this.db.tx(async (t) => {
        const result = await t.query(
          `INSERT INTO users (unionid, openid_mp, openid_open, nickname, avatar, email, is_admin, is_disabled, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, FALSE, NOW(), NOW())`,
          [
            userData.unionid || null,
            userData.openid_mp || null,
            userData.openid_open || null,
            userData.nickname || null,
            userData.avatar || null,
            userData.email || null,
            userData.is_admin || false
          ]
        );

        const insertId = (result as any).insertId;
        const user = await t.queryOne<User>('SELECT * FROM users WHERE id = ?', [insertId]);
        
        if (!user) {
          throw new Error('Failed to retrieve created user');
        }

        logger.info({ userId: user.id }, 'User created successfully');
        return user;
      });
    } catch (error) {
      logger.error({ error, userData }, 'Failed to create user');
      throw error;
    }
  }

  async update(id: number, updateData: UpdateUserData): Promise<User | null> {
    try {
      return await this.db.tx(async (t) => {
        const setClauses: string[] = [];
        const values: any[] = [];

        if (updateData.nickname !== undefined) {
          setClauses.push('nickname = ?');
          values.push(updateData.nickname);
        }
        if (updateData.avatar !== undefined) {
          setClauses.push('avatar = ?');
          values.push(updateData.avatar);
        }
        if (updateData.email !== undefined) {
          setClauses.push('email = ?');
          values.push(updateData.email);
        }
        if (updateData.last_login_at !== undefined) {
          setClauses.push('last_login_at = ?');
          values.push(updateData.last_login_at);
        }

        if (setClauses.length === 0) {
          return await t.queryOne<User>('SELECT * FROM users WHERE id = ?', [id]);
        }

        setClauses.push('updated_at = NOW()');
        values.push(id);

        await t.query(
          `UPDATE users SET ${setClauses.join(', ')} WHERE id = ?`,
          values
        );

        return await t.queryOne<User>('SELECT * FROM users WHERE id = ?', [id]);
      });
    } catch (error) {
      logger.error({ error, id, updateData }, 'Failed to update user');
      throw error;
    }
  }

  async updateLastLogin(id: number): Promise<void> {
    try {
      await this.db.query(
        'UPDATE users SET last_login_at = NOW(), updated_at = NOW() WHERE id = ?',
        [id]
      );
    } catch (error) {
      logger.error({ error, id }, 'Failed to update last login');
      throw error;
    }
  }

  async disable(id: number): Promise<boolean> {
    try {
      const result = await this.db.query(
        'UPDATE users SET is_disabled = TRUE, updated_at = NOW() WHERE id = ?',
        [id]
      );
      return (result as any).affectedRows > 0;
    } catch (error) {
      logger.error({ error, id }, 'Failed to disable user');
      throw error;
    }
  }

  async enable(id: number): Promise<boolean> {
    try {
      const result = await this.db.query(
        'UPDATE users SET is_disabled = FALSE, updated_at = NOW() WHERE id = ?',
        [id]
      );
      return (result as any).affectedRows > 0;
    } catch (error) {
      logger.error({ error, id }, 'Failed to enable user');
      throw error;
    }
  }

  async list(options?: {
    limit?: number;
    offset?: number;
    includeDisabled?: boolean;
  }): Promise<User[]> {
    try {
      const { limit = 50, offset = 0, includeDisabled = false } = options || {};
      
      let sql = 'SELECT * FROM users';
      const params: any[] = [];

      if (!includeDisabled) {
        sql += ' WHERE is_disabled = FALSE';
      }

      sql += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
      params.push(limit, offset);

      const result = await this.db.query<User>(sql, params);
      return result.rows;
    } catch (error) {
      logger.error({ error, options }, 'Failed to list users');
      throw error;
    }
  }
}