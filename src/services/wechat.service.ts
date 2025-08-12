import { config } from '../config/index.js';
import { logger } from '../utils/logger.js';
import { generateLoginId } from '../utils/crypto.js';
import { db } from '../db/client.js';

interface WeChatTokenResponse {
  access_token: string;
  expires_in: number;
  refresh_token: string;
  openid: string;
  scope: string;
  unionid?: string;
}

interface WeChatUserInfo {
  openid: string;
  nickname: string;
  sex: number;
  province: string;
  city: string;
  country: string;
  headimgurl: string;
  privilege: string[];
  unionid?: string;
}

export class WeChatService {
  private static instance: WeChatService;

  private constructor() {}

  static getInstance(): WeChatService {
    if (!WeChatService.instance) {
      WeChatService.instance = new WeChatService();
    }
    return WeChatService.instance;
  }

  async generateQRCode(clientId?: string, redirectUri?: string): Promise<{
    loginId: string;
    qrUrl: string;
    expiresIn: number;
  }> {
    const loginId = generateLoginId();
    const expiresIn = 300; // 5 minutes

    // Store login ticket
    await db.query(
      `INSERT INTO login_tickets (id, status, client_id, redirect_uri, expires_at, ip, ua)
       VALUES ($1, $2, $3, $4, NOW() + INTERVAL '${expiresIn} seconds', $5, $6)`,
      [loginId, 'PENDING', clientId, redirectUri, null, null]
    );

    // Construct WeChat QR URL
    const params = new URLSearchParams({
      appid: config.wechat.appId,
      redirect_uri: config.wechat.redirectUri,
      response_type: 'code',
      scope: 'snsapi_login',
      state: loginId,
    });

    const qrUrl = `https://open.weixin.qq.com/connect/qrconnect?${params.toString()}#wechat_redirect`;

    logger.info({ loginId }, 'Generated WeChat QR code');

    return {
      loginId,
      qrUrl,
      expiresIn,
    };
  }

  async handleCallback(code: string, state: string): Promise<{
    userId: string;
    unionid?: string;
    openid: string;
    authCode: string;
  }> {
    // Validate login ticket
    const ticketResult = await db.query(
      `SELECT * FROM login_tickets WHERE id = $1 AND status = 'PENDING' AND expires_at > NOW()`,
      [state]
    );

    if (ticketResult.rows.length === 0) {
      throw new Error('Invalid or expired login ticket');
    }

    const ticket = ticketResult.rows[0];

    // Update ticket status
    await db.query(
      `UPDATE login_tickets SET status = 'AUTHORIZED', authorized_at = NOW() WHERE id = $1`,
      [state]
    );

    // Exchange code for access token
    const tokenData = await this.exchangeCodeForToken(code);

    // Get user info (optional, for display name and avatar)
    let userInfo: WeChatUserInfo | null = null;
    try {
      userInfo = await this.getUserInfo(tokenData.access_token, tokenData.openid);
    } catch (error) {
      logger.warn(error, 'Failed to fetch WeChat user info, continuing with basic data');
    }

    // Find or create user
    const userId = await this.findOrCreateUser(tokenData, userInfo);

    // Generate auth code for token exchange
    const authCode = await this.generateAuthCode(userId, ticket.client_id, ticket.redirect_uri);

    // Update ticket with success
    await db.query(
      `UPDATE login_tickets SET status = 'SUCCESS', result = $1 WHERE id = $2`,
      [JSON.stringify({ authCode, userId }), state]
    );

    return {
      userId,
      unionid: tokenData.unionid,
      openid: tokenData.openid,
      authCode,
    };
  }

  private async exchangeCodeForToken(code: string): Promise<WeChatTokenResponse> {
    const url = new URL('https://api.weixin.qq.com/sns/oauth2/access_token');
    url.searchParams.append('appid', config.wechat.appId);
    url.searchParams.append('secret', config.wechat.appSecret);
    url.searchParams.append('code', code);
    url.searchParams.append('grant_type', 'authorization_code');

    const response = await fetch(url.toString());
    const data = await response.json();

    if (data.errcode) {
      logger.error({ error: data }, 'WeChat token exchange failed');
      throw new Error(`WeChat API error: ${data.errmsg}`);
    }

    return data as WeChatTokenResponse;
  }

  private async getUserInfo(accessToken: string, openid: string): Promise<WeChatUserInfo> {
    const url = new URL('https://api.weixin.qq.com/sns/userinfo');
    url.searchParams.append('access_token', accessToken);
    url.searchParams.append('openid', openid);
    url.searchParams.append('lang', 'zh_CN');

    const response = await fetch(url.toString());
    const data = await response.json();

    if (data.errcode) {
      throw new Error(`WeChat API error: ${data.errmsg}`);
    }

    return data as WeChatUserInfo;
  }

  private async findOrCreateUser(
    tokenData: WeChatTokenResponse,
    userInfo: WeChatUserInfo | null
  ): Promise<string> {
    // First try to find by unionid if available
    if (tokenData.unionid) {
      const result = await db.query(
        `SELECT u.* FROM users u
         JOIN identities i ON u.id = i.user_id
         WHERE i.unionid = $1 AND i.provider = 'wechat_open_web'`,
        [tokenData.unionid]
      );

      if (result.rows.length > 0) {
        const userId = result.rows[0].id;
        await this.updateLastLogin(userId);
        return userId;
      }
    }

    // Try to find by openid
    const identityResult = await db.query(
      `SELECT user_id FROM identities WHERE openid = $1 AND provider = 'wechat_open_web'`,
      [tokenData.openid]
    );

    if (identityResult.rows.length > 0) {
      const userId = identityResult.rows[0].user_id;
      
      // Update unionid if we got it now
      if (tokenData.unionid) {
        await db.query(
          `UPDATE identities SET unionid = $1, updated_at = NOW() 
           WHERE user_id = $2 AND provider = 'wechat_open_web'`,
          [tokenData.unionid, userId]
        );
      }
      
      await this.updateLastLogin(userId);
      return userId;
    }

    // Create new user
    return await this.createUser(tokenData, userInfo);
  }

  private async createUser(
    tokenData: WeChatTokenResponse,
    userInfo: WeChatUserInfo | null
  ): Promise<string> {
    return await db.transaction(async (client) => {
      // Create user
      const userResult = await client.query(
        `INSERT INTO users (display_name, avatar_url, created_at, last_login_at)
         VALUES ($1, $2, NOW(), NOW())
         RETURNING id`,
        [
          userInfo?.nickname || `User_${tokenData.openid.slice(-6)}`,
          userInfo?.headimgurl || null,
        ]
      );

      const userId = userResult.rows[0].id;

      // Create identity
      await client.query(
        `INSERT INTO identities (user_id, provider, openid, unionid, raw, created_at)
         VALUES ($1, $2, $3, $4, $5, NOW())`,
        [
          userId,
          'wechat_open_web',
          tokenData.openid,
          tokenData.unionid || null,
          JSON.stringify({ tokenData, userInfo }),
        ]
      );

      // Assign default role
      const roleResult = await client.query(
        `SELECT id FROM roles WHERE name = 'user'`
      );
      
      if (roleResult.rows.length > 0) {
        await client.query(
          `INSERT INTO user_roles (user_id, role_id, granted_at)
           VALUES ($1, $2, NOW())`,
          [userId, roleResult.rows[0].id]
        );
      }

      // Audit log
      await client.query(
        `INSERT INTO audit_logs (actor, action, resource, status, ts, extra)
         VALUES ($1, $2, $3, $4, NOW(), $5)`,
        [
          userId.toString(),
          'user.create',
          `user:${userId}`,
          'success',
          JSON.stringify({ provider: 'wechat_open_web', openid: tokenData.openid }),
        ]
      );

      logger.info({ userId, openid: tokenData.openid }, 'Created new user from WeChat');

      return userId.toString();
    });
  }

  private async updateLastLogin(userId: string): Promise<void> {
    await db.query(
      `UPDATE users SET last_login_at = NOW() WHERE id = $1`,
      [userId]
    );
  }

  private async generateAuthCode(
    userId: string, 
    clientId: string | null, 
    redirectUri: string | null
  ): Promise<string> {
    const { generateAuthCode } = await import('../utils/crypto.js');
    const code = generateAuthCode();

    await db.query(
      `INSERT INTO auth_codes (code, client_id, user_id, redirect_uri, expires_at)
       VALUES ($1, $2, $3, $4, NOW() + INTERVAL '10 minutes')`,
      [code, clientId || 'xjp-web', userId, redirectUri || 'https://xiaojinpro.com/callback']
    );

    return code;
  }

  async getLoginTicketStatus(loginId: string): Promise<{
    status: string;
    result?: any;
  }> {
    const result = await db.query(
      `SELECT status, result FROM login_tickets WHERE id = $1`,
      [loginId]
    );

    if (result.rows.length === 0) {
      return { status: 'NOT_FOUND' };
    }

    return result.rows[0];
  }
}

export const wechatService = WeChatService.getInstance();