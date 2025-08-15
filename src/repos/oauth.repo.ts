import { DatabaseAdapter } from '../db/DatabaseAdapter.js';
import { logger } from '../utils/logger.js';

export interface OAuthClient {
  id: number;
  client_id: string;
  name: string;
  redirect_uris: string[];
  first_party: boolean;
  allowed_scopes: string[];
  is_disabled: boolean;
  created_at: Date;
}

export interface AuthCode {
  id: number;
  code: string;
  client_id: string;
  user_id: number;
  redirect_uri: string;
  scopes: string[];
  code_challenge?: string;
  code_challenge_method?: string;
  expires_at: Date;
  created_at: Date;
  used_at?: Date;
}

export interface Token {
  id: number;
  jti: string;
  user_id: number;
  client_id: string;
  session_id: string;
  token_type: 'access_token' | 'refresh_token';
  scopes: string[];
  refresh_token_jti?: string;
  parent_refresh_token_jti?: string;
  device_info?: any;
  expires_at: Date;
  created_at: Date;
  revoked_at?: Date;
  last_used_at?: Date;
}

export interface CreateAuthCodeData {
  code: string;
  client_id: string;
  user_id: number;
  redirect_uri: string;
  scopes: string[];
  code_challenge?: string;
  code_challenge_method?: string;
  expires_at: Date;
}

export interface CreateTokenData {
  jti: string;
  user_id: number;
  client_id: string;
  session_id: string;
  token_type: 'access_token' | 'refresh_token';
  scopes: string[];
  refresh_token_jti?: string;
  parent_refresh_token_jti?: string;
  device_info?: any;
  expires_at: Date;
}

export class OAuthRepo {
  constructor(private db: DatabaseAdapter) {}

  // OAuth 客户端管理
  async findClientById(clientId: string): Promise<OAuthClient | null> {
    try {
      const client = await this.db.queryOne<any>(
        'SELECT * FROM oauth_clients WHERE client_id = ?',
        [clientId]
      );
      
      if (!client) return null;
      
      return {
        ...client,
        redirect_uris: JSON.parse(client.redirect_uris),
        allowed_scopes: JSON.parse(client.allowed_scopes)
      };
    } catch (error) {
      logger.error({ error, clientId }, 'Failed to find OAuth client');
      throw error;
    }
  }

  async listClients(includeDisabled = false): Promise<OAuthClient[]> {
    try {
      let sql = 'SELECT * FROM oauth_clients';
      if (!includeDisabled) {
        sql += ' WHERE is_disabled = FALSE';
      }
      sql += ' ORDER BY created_at DESC';

      const result = await this.db.query<any>(sql);
      
      return result.rows.map(client => ({
        ...client,
        redirect_uris: JSON.parse(client.redirect_uris),
        allowed_scopes: JSON.parse(client.allowed_scopes)
      }));
    } catch (error) {
      logger.error({ error }, 'Failed to list OAuth clients');
      throw error;
    }
  }

  // 授权码管理
  async createAuthCode(authCodeData: CreateAuthCodeData): Promise<AuthCode> {
    try {
      return await this.db.tx(async (t) => {
        const result = await t.query(
          `INSERT INTO auth_codes (code, client_id, user_id, redirect_uri, scopes, code_challenge, code_challenge_method, expires_at, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW())`,
          [
            authCodeData.code,
            authCodeData.client_id,
            authCodeData.user_id,
            authCodeData.redirect_uri,
            JSON.stringify(authCodeData.scopes),
            authCodeData.code_challenge || null,
            authCodeData.code_challenge_method || null,
            authCodeData.expires_at
          ]
        );

        const insertId = (result as any).insertId;
        const authCode = await t.queryOne<any>('SELECT * FROM auth_codes WHERE id = ?', [insertId]);
        
        if (!authCode) {
          throw new Error('Failed to retrieve created auth code');
        }

        return {
          ...authCode,
          scopes: JSON.parse(authCode.scopes)
        };
      });
    } catch (error) {
      logger.error({ error, authCodeData }, 'Failed to create auth code');
      throw error;
    }
  }

  async findAuthCode(code: string): Promise<AuthCode | null> {
    try {
      const authCode = await this.db.queryOne<any>(
        'SELECT * FROM auth_codes WHERE code = ?',
        [code]
      );
      
      if (!authCode) return null;
      
      return {
        ...authCode,
        scopes: JSON.parse(authCode.scopes)
      };
    } catch (error) {
      logger.error({ error, code }, 'Failed to find auth code');
      throw error;
    }
  }

  async markAuthCodeAsUsed(code: string): Promise<boolean> {
    try {
      const result = await this.db.query(
        'UPDATE auth_codes SET used_at = NOW() WHERE code = ? AND used_at IS NULL',
        [code]
      );
      
      const success = (result as any).affectedRows > 0;
      if (success) {
        logger.info({ code }, 'Auth code marked as used');
      }
      
      return success;
    } catch (error) {
      logger.error({ error, code }, 'Failed to mark auth code as used');
      throw error;
    }
  }

  async deleteAuthCode(code: string): Promise<boolean> {
    try {
      const result = await this.db.query('DELETE FROM auth_codes WHERE code = ?', [code]);
      
      const success = (result as any).affectedRows > 0;
      if (success) {
        logger.info({ code }, 'Auth code deleted');
      }
      
      return success;
    } catch (error) {
      logger.error({ error, code }, 'Failed to delete auth code');
      throw error;
    }
  }

  // 令牌管理
  async createToken(tokenData: CreateTokenData): Promise<Token> {
    try {
      return await this.db.tx(async (t) => {
        const result = await t.query(
          `INSERT INTO tokens (jti, user_id, client_id, session_id, token_type, scopes, refresh_token_jti, parent_refresh_token_jti, device_info, expires_at, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())`,
          [
            tokenData.jti,
            tokenData.user_id,
            tokenData.client_id,
            tokenData.session_id,
            tokenData.token_type,
            JSON.stringify(tokenData.scopes),
            tokenData.refresh_token_jti || null,
            tokenData.parent_refresh_token_jti || null,
            tokenData.device_info ? JSON.stringify(tokenData.device_info) : null,
            tokenData.expires_at
          ]
        );

        const insertId = (result as any).insertId;
        const token = await t.queryOne<any>('SELECT * FROM tokens WHERE id = ?', [insertId]);
        
        if (!token) {
          throw new Error('Failed to retrieve created token');
        }

        return {
          ...token,
          scopes: JSON.parse(token.scopes),
          device_info: token.device_info ? JSON.parse(token.device_info) : null
        };
      });
    } catch (error) {
      logger.error({ error, tokenData }, 'Failed to create token');
      throw error;
    }
  }

  async findTokenByJti(jti: string): Promise<Token | null> {
    try {
      const token = await this.db.queryOne<any>(
        'SELECT * FROM tokens WHERE jti = ?',
        [jti]
      );
      
      if (!token) return null;
      
      return {
        ...token,
        scopes: JSON.parse(token.scopes),
        device_info: token.device_info ? JSON.parse(token.device_info) : null
      };
    } catch (error) {
      logger.error({ error, jti }, 'Failed to find token by jti');
      throw error;
    }
  }

  async findTokensByUserId(userId: number, options?: {
    tokenType?: 'access_token' | 'refresh_token';
    includeRevoked?: boolean;
    limit?: number;
  }): Promise<Token[]> {
    try {
      const { tokenType, includeRevoked = false, limit = 50 } = options || {};
      
      let sql = 'SELECT * FROM tokens WHERE user_id = ?';
      const params: any[] = [userId];

      if (tokenType) {
        sql += ' AND token_type = ?';
        params.push(tokenType);
      }

      if (!includeRevoked) {
        sql += ' AND revoked_at IS NULL';
      }

      sql += ' ORDER BY created_at DESC LIMIT ?';
      params.push(limit);

      const result = await this.db.query<any>(sql, params);
      
      return result.rows.map(token => ({
        ...token,
        scopes: JSON.parse(token.scopes),
        device_info: token.device_info ? JSON.parse(token.device_info) : null
      }));
    } catch (error) {
      logger.error({ error, userId, options }, 'Failed to find tokens by user id');
      throw error;
    }
  }

  async revokeToken(jti: string): Promise<boolean> {
    try {
      const result = await this.db.query(
        'UPDATE tokens SET revoked_at = NOW() WHERE jti = ? AND revoked_at IS NULL',
        [jti]
      );
      
      const success = (result as any).affectedRows > 0;
      if (success) {
        logger.info({ jti }, 'Token revoked');
      }
      
      return success;
    } catch (error) {
      logger.error({ error, jti }, 'Failed to revoke token');
      throw error;
    }
  }

  async revokeTokensBySessionId(sessionId: string): Promise<number> {
    try {
      const result = await this.db.query(
        'UPDATE tokens SET revoked_at = NOW() WHERE session_id = ? AND revoked_at IS NULL',
        [sessionId]
      );
      
      const revokedCount = (result as any).affectedRows;
      logger.info({ sessionId, revokedCount }, 'Session tokens revoked');
      
      return revokedCount;
    } catch (error) {
      logger.error({ error, sessionId }, 'Failed to revoke session tokens');
      throw error;
    }
  }

  async updateTokenLastUsed(jti: string): Promise<void> {
    try {
      await this.db.query(
        'UPDATE tokens SET last_used_at = NOW() WHERE jti = ?',
        [jti]
      );
    } catch (error) {
      logger.error({ error, jti }, 'Failed to update token last used');
      throw error;
    }
  }

  // 清理过期数据
  async cleanupExpiredAuthCodes(): Promise<number> {
    try {
      const result = await this.db.query('DELETE FROM auth_codes WHERE expires_at < NOW()');
      
      const deletedCount = (result as any).affectedRows;
      if (deletedCount > 0) {
        logger.info({ deletedCount }, 'Expired auth codes cleaned up');
      }
      
      return deletedCount;
    } catch (error) {
      logger.error({ error }, 'Failed to cleanup expired auth codes');
      throw error;
    }
  }

  async cleanupExpiredTokens(): Promise<number> {
    try {
      const result = await this.db.query('DELETE FROM tokens WHERE expires_at < NOW() AND revoked_at IS NULL');
      
      const deletedCount = (result as any).affectedRows;
      if (deletedCount > 0) {
        logger.info({ deletedCount }, 'Expired tokens cleaned up');
      }
      
      return deletedCount;
    } catch (error) {
      logger.error({ error }, 'Failed to cleanup expired tokens');
      throw error;
    }
  }
}