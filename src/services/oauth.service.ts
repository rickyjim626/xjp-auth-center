import { db } from '../db/client.js';
import { jwtService } from './jwt.service.js';
import { logger } from '../utils/logger.js';
import { generateRefreshToken, verifyCodeChallenge } from '../utils/crypto.js';

interface TokenRequest {
  grant_type: 'authorization_code' | 'refresh_token';
  code?: string;
  refresh_token?: string;
  client_id: string;
  client_secret?: string;
  redirect_uri?: string;
  code_verifier?: string;
}

interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  refresh_token?: string;
  scope?: string;
}

export class OAuthService {
  private static instance: OAuthService;

  private constructor() {}

  static getInstance(): OAuthService {
    if (!OAuthService.instance) {
      OAuthService.instance = new OAuthService();
    }
    return OAuthService.instance;
  }

  async exchangeToken(request: TokenRequest): Promise<TokenResponse> {
    if (request.grant_type === 'authorization_code') {
      return this.exchangeAuthorizationCode(request);
    } else if (request.grant_type === 'refresh_token') {
      return this.refreshAccessToken(request);
    } else {
      throw new Error('Invalid grant_type');
    }
  }

  private async exchangeAuthorizationCode(request: TokenRequest): Promise<TokenResponse> {
    if (!request.code) {
      throw new Error('Missing authorization code');
    }

    // Validate auth code
    const codeResult = await db.query(
      `SELECT * FROM auth_codes 
       WHERE code = $1 AND expires_at > NOW()`,
      [request.code]
    );

    if (codeResult.rows.length === 0) {
      throw new Error('Invalid or expired authorization code');
    }

    const authCode = codeResult.rows[0];

    // Validate client
    if (authCode.client_id !== request.client_id) {
      throw new Error('Client mismatch');
    }

    // Validate redirect_uri
    if (authCode.redirect_uri && authCode.redirect_uri !== request.redirect_uri) {
      throw new Error('Redirect URI mismatch');
    }

    // Validate PKCE if present
    if (authCode.code_challenge) {
      if (!request.code_verifier) {
        throw new Error('Missing code verifier');
      }
      
      const valid = verifyCodeChallenge(
        request.code_verifier,
        authCode.code_challenge,
        authCode.code_challenge_method || 'S256'
      );
      
      if (!valid) {
        throw new Error('Invalid code verifier');
      }
    }

    // Delete auth code (one-time use)
    await db.query('DELETE FROM auth_codes WHERE code = $1', [request.code]);

    // Get user info
    const userResult = await db.query(
      `SELECT u.*, i.unionid, i.openid 
       FROM users u
       LEFT JOIN identities i ON u.id = i.user_id AND i.provider = 'wechat_open_web'
       WHERE u.id = $1`,
      [authCode.user_id]
    );

    if (userResult.rows.length === 0) {
      throw new Error('User not found');
    }

    const user = userResult.rows[0];

    // Get user roles
    const rolesResult = await db.query(
      `SELECT r.name FROM roles r
       JOIN user_roles ur ON r.id = ur.role_id
       WHERE ur.user_id = $1 AND (ur.expires_at IS NULL OR ur.expires_at > NOW())`,
      [user.id]
    );

    const roles = rolesResult.rows.map(r => r.name);

    // Create session
    const sessionResult = await db.query(
      `INSERT INTO sessions (user_id, client_id, created_at)
       VALUES ($1, $2, NOW())
       RETURNING id`,
      [user.id, request.client_id]
    );

    const sessionId = sessionResult.rows[0].id;

    // Generate tokens
    const accessToken = await jwtService.signAccessToken({
      userId: user.id.toString(),
      unionid: user.unionid,
      openid: user.openid,
      roles,
      clientId: request.client_id,
      sessionId: sessionId.toString(),
    });

    const { token: refreshToken, jti } = await jwtService.signRefreshToken({
      userId: user.id.toString(),
      clientId: request.client_id,
      sessionId: sessionId.toString(),
    });

    // Store refresh token
    await db.query(
      `INSERT INTO refresh_tokens (user_id, session_id, client_id, jti, expires_at)
       VALUES ($1, $2, $3, $4, NOW() + INTERVAL '30 days')`,
      [user.id, sessionId, request.client_id, jti]
    );

    // Audit log
    await db.query(
      `INSERT INTO audit_logs (actor, action, resource, status, ip, ts, extra)
       VALUES ($1, $2, $3, $4, $5, NOW(), $6)`,
      [
        user.id.toString(),
        'token.issue',
        `session:${sessionId}`,
        'success',
        null,
        JSON.stringify({ grant_type: 'authorization_code', client_id: request.client_id }),
      ]
    );

    logger.info({ userId: user.id, clientId: request.client_id }, 'Issued tokens via authorization code');

    return {
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: 900, // 15 minutes
      refresh_token: refreshToken,
      scope: authCode.scope || 'openid profile',
    };
  }

  private async refreshAccessToken(request: TokenRequest): Promise<TokenResponse> {
    if (!request.refresh_token) {
      throw new Error('Missing refresh token');
    }

    // Verify refresh token
    let payload;
    try {
      const result = await jwtService.verifyToken(request.refresh_token);
      payload = result.payload;
    } catch (error) {
      throw new Error('Invalid refresh token');
    }

    // Check if refresh token is revoked
    const tokenResult = await db.query(
      `SELECT * FROM refresh_tokens 
       WHERE jti = $1 AND revoked_at IS NULL AND expires_at > NOW()`,
      [payload.jti]
    );

    if (tokenResult.rows.length === 0) {
      // Check if this was a rotated token (reuse detection)
      const rotatedResult = await db.query(
        `SELECT * FROM refresh_tokens WHERE rotated_from = $1`,
        [payload.jti]
      );

      if (rotatedResult.rows.length > 0) {
        // Token reuse detected! Revoke entire chain
        logger.warn({ jti: payload.jti }, 'Refresh token reuse detected, revoking chain');
        
        await db.query(
          `UPDATE refresh_tokens 
           SET revoked_at = NOW(), revoke_reason = 'reuse_detected'
           WHERE user_id = $1 AND session_id = $2`,
          [rotatedResult.rows[0].user_id, rotatedResult.rows[0].session_id]
        );

        throw new Error('Token reuse detected');
      }

      throw new Error('Invalid or expired refresh token');
    }

    const oldToken = tokenResult.rows[0];

    // Validate client
    if (oldToken.client_id !== request.client_id) {
      throw new Error('Client mismatch');
    }

    // Get user info
    const userResult = await db.query(
      `SELECT u.*, i.unionid, i.openid 
       FROM users u
       LEFT JOIN identities i ON u.id = i.user_id AND i.provider = 'wechat_open_web'
       WHERE u.id = $1`,
      [oldToken.user_id]
    );

    if (userResult.rows.length === 0) {
      throw new Error('User not found');
    }

    const user = userResult.rows[0];

    // Get user roles
    const rolesResult = await db.query(
      `SELECT r.name FROM roles r
       JOIN user_roles ur ON r.id = ur.role_id
       WHERE ur.user_id = $1 AND (ur.expires_at IS NULL OR ur.expires_at > NOW())`,
      [user.id]
    );

    const roles = rolesResult.rows.map(r => r.name);

    // Generate new tokens (token rotation)
    const accessToken = await jwtService.signAccessToken({
      userId: user.id.toString(),
      unionid: user.unionid,
      openid: user.openid,
      roles,
      clientId: request.client_id,
      sessionId: oldToken.session_id?.toString(),
    });

    const { token: newRefreshToken, jti: newJti } = await jwtService.signRefreshToken({
      userId: user.id.toString(),
      clientId: request.client_id,
      sessionId: oldToken.session_id?.toString(),
    });

    // Rotate refresh token
    await db.transaction(async (client) => {
      // Revoke old token
      await client.query(
        `UPDATE refresh_tokens 
         SET revoked_at = NOW(), revoke_reason = 'rotated'
         WHERE jti = $1`,
        [payload.jti]
      );

      // Create new token
      await client.query(
        `INSERT INTO refresh_tokens (user_id, session_id, client_id, jti, rotated_from, expires_at)
         VALUES ($1, $2, $3, $4, $5, NOW() + INTERVAL '30 days')`,
        [user.id, oldToken.session_id, request.client_id, newJti, payload.jti]
      );

      // Update session activity
      if (oldToken.session_id) {
        await client.query(
          `UPDATE sessions SET last_activity_at = NOW() WHERE id = $1`,
          [oldToken.session_id]
        );
      }
    });

    // Audit log
    await db.query(
      `INSERT INTO audit_logs (actor, action, resource, status, ts, extra)
       VALUES ($1, $2, $3, $4, NOW(), $5)`,
      [
        user.id.toString(),
        'token.refresh',
        `session:${oldToken.session_id}`,
        'success',
        JSON.stringify({ old_jti: payload.jti, new_jti: newJti }),
      ]
    );

    logger.info({ userId: user.id, oldJti: payload.jti, newJti }, 'Refreshed tokens');

    return {
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: 900, // 15 minutes
      refresh_token: newRefreshToken,
      scope: oldToken.scope || 'openid profile',
    };
  }

  async revokeToken(token: string): Promise<void> {
    try {
      const result = await jwtService.verifyToken(token);
      const payload = result.payload;

      if (payload.type === 'refresh' && payload.jti) {
        await db.query(
          `UPDATE refresh_tokens 
           SET revoked_at = NOW(), revoke_reason = 'user_revoked'
           WHERE jti = $1`,
          [payload.jti]
        );

        logger.info({ jti: payload.jti }, 'Revoked refresh token');
      }
    } catch (error) {
      logger.warn(error, 'Failed to revoke token');
    }
  }
}

export const oauthService = OAuthService.getInstance();