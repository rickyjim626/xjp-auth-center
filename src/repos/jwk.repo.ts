import { DatabaseAdapter } from '../db/DatabaseAdapter.js';
import { logger } from '../utils/logger.js';

export interface JWK {
  id: number;
  key_id: string;
  key_type: string;
  algorithm: string;
  public_key: string;
  private_key: string;
  is_active: boolean;
  created_at: Date;
  rotated_at?: Date;
}

export interface CreateJWKData {
  key_id: string;
  key_type: string;
  algorithm: string;
  public_key: string;
  private_key: string;
}

export class JWKRepo {
  constructor(private db: DatabaseAdapter) {}

  async findActiveKey(): Promise<JWK | null> {
    try {
      return await this.db.queryOne<JWK>(
        'SELECT * FROM jwks WHERE is_active = TRUE ORDER BY created_at DESC LIMIT 1'
      );
    } catch (error) {
      logger.error({ error }, 'Failed to find active JWK');
      throw error;
    }
  }

  async findByKeyId(keyId: string): Promise<JWK | null> {
    try {
      return await this.db.queryOne<JWK>(
        'SELECT * FROM jwks WHERE key_id = ?',
        [keyId]
      );
    } catch (error) {
      logger.error({ error, keyId }, 'Failed to find JWK by key ID');
      throw error;
    }
  }

  async listPublicKeys(includeInactive = false): Promise<JWK[]> {
    try {
      let sql = 'SELECT id, key_id, key_type, algorithm, public_key, is_active, created_at, rotated_at FROM jwks';
      
      if (!includeInactive) {
        sql += ' WHERE is_active = TRUE OR rotated_at > DATE_SUB(NOW(), INTERVAL 24 HOUR)';
      }
      
      sql += ' ORDER BY created_at DESC';

      const result = await this.db.query<JWK>(sql);
      return result.rows;
    } catch (error) {
      logger.error({ error }, 'Failed to list public JWKs');
      throw error;
    }
  }

  async create(jwkData: CreateJWKData): Promise<JWK> {
    try {
      return await this.db.tx(async (t) => {
        const result = await t.query(
          `INSERT INTO jwks (key_id, key_type, algorithm, public_key, private_key, is_active, created_at)
           VALUES (?, ?, ?, ?, ?, TRUE, NOW())`,
          [
            jwkData.key_id,
            jwkData.key_type,
            jwkData.algorithm,
            jwkData.public_key,
            jwkData.private_key
          ]
        );

        const insertId = (result as any).insertId;
        const jwk = await t.queryOne<JWK>('SELECT * FROM jwks WHERE id = ?', [insertId]);
        
        if (!jwk) {
          throw new Error('Failed to retrieve created JWK');
        }

        logger.info({ keyId: jwk.key_id }, 'JWK created successfully');
        return jwk;
      });
    } catch (error) {
      logger.error({ error, jwkData }, 'Failed to create JWK');
      throw error;
    }
  }

  async rotate(currentKeyId: string, newJwkData: CreateJWKData): Promise<JWK> {
    try {
      return await this.db.tx(async (t) => {
        // 将当前密钥标记为非活跃状态
        await t.query(
          'UPDATE jwks SET is_active = FALSE, rotated_at = NOW() WHERE key_id = ?',
          [currentKeyId]
        );

        // 创建新密钥
        const result = await t.query(
          `INSERT INTO jwks (key_id, key_type, algorithm, public_key, private_key, is_active, created_at)
           VALUES (?, ?, ?, ?, ?, TRUE, NOW())`,
          [
            newJwkData.key_id,
            newJwkData.key_type,
            newJwkData.algorithm,
            newJwkData.public_key,
            newJwkData.private_key
          ]
        );

        const insertId = (result as any).insertId;
        const newJwk = await t.queryOne<JWK>('SELECT * FROM jwks WHERE id = ?', [insertId]);
        
        if (!newJwk) {
          throw new Error('Failed to retrieve rotated JWK');
        }

        logger.info({ 
          oldKeyId: currentKeyId, 
          newKeyId: newJwk.key_id 
        }, 'JWK rotated successfully');
        
        return newJwk;
      });
    } catch (error) {
      logger.error({ error, currentKeyId, newJwKData: newJwkData }, 'Failed to rotate JWK');
      throw error;
    }
  }

  async deactivate(keyId: string): Promise<boolean> {
    try {
      const result = await this.db.query(
        'UPDATE jwks SET is_active = FALSE, rotated_at = NOW() WHERE key_id = ? AND is_active = TRUE',
        [keyId]
      );
      
      const success = (result as any).affectedRows > 0;
      if (success) {
        logger.info({ keyId }, 'JWK deactivated');
      }
      
      return success;
    } catch (error) {
      logger.error({ error, keyId }, 'Failed to deactivate JWK');
      throw error;
    }
  }

  async cleanupOldKeys(olderThanDays = 30): Promise<number> {
    try {
      const result = await this.db.query(
        'DELETE FROM jwks WHERE is_active = FALSE AND rotated_at < DATE_SUB(NOW(), INTERVAL ? DAY)',
        [olderThanDays]
      );
      
      const deletedCount = (result as any).affectedRows;
      if (deletedCount > 0) {
        logger.info({ deletedCount, olderThanDays }, 'Old JWKs cleaned up');
      }
      
      return deletedCount;
    } catch (error) {
      logger.error({ error, olderThanDays }, 'Failed to cleanup old JWKs');
      throw error;
    }
  }

  // 生成 JWKS 格式的公钥列表 (用于 /.well-known/jwks.json)
  async getPublicJWKS(): Promise<{ keys: any[] }> {
    try {
      const keys = await this.listPublicKeys();
      
      return {
        keys: keys.map(key => ({
          kid: key.key_id,
          kty: key.key_type,
          alg: key.algorithm,
          use: 'sig',
          // 需要将 PEM 格式转换为 JWK 格式
          // 这里简化处理，实际应该解析 PEM 获取具体字段
          key: key.public_key
        }))
      };
    } catch (error) {
      logger.error({ error }, 'Failed to get public JWKS');
      throw error;
    }
  }
}