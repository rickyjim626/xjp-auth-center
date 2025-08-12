import { getConfig } from '../config/auth-config.js';
import { logger } from '../utils/logger.js';
import { generateLoginId, generateAuthCode } from '../utils/crypto.js';
import { TCBDatabase, findOne, insertOne, updateOne } from '../db/tcb-client.js';

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

export class WeChatServiceTCB {
  private static instance: WeChatServiceTCB;
  private db: TCBDatabase | null = null;

  private constructor() {}

  static getInstance(): WeChatServiceTCB {
    if (!WeChatServiceTCB.instance) {
      WeChatServiceTCB.instance = new WeChatServiceTCB();
    }
    return WeChatServiceTCB.instance;
  }

  private async getDb(): Promise<TCBDatabase> {
    if (!this.db) {
      this.db = TCBDatabase.getInstance();
    }
    return this.db;
  }

  async generateQRCode(clientId?: string, redirectUri?: string): Promise<{
    loginId: string;
    qrUrl: string;
    expiresIn: number;
  }> {
    const config = await getConfig();
    const loginId = generateLoginId();
    const expiresIn = 300; // 5 minutes

    // Store login ticket
    const expiresAt = new Date(Date.now() + expiresIn * 1000);
    await insertOne('login_states', {
      loginId,
      status: 'PENDING',
      clientId,
      redirectUri,
      expiresAt,
      createdAt: new Date(),
    });

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
    const db = await this.getDb();
    const now = new Date();

    // Validate login ticket
    const ticket = await findOne('login_states', {
      loginId: state,
      status: 'PENDING',
      expiresAt: db._.gt(now),
    });

    if (!ticket) {
      throw new Error('Invalid or expired login ticket');
    }

    // Update ticket status
    await updateOne(
      'login_states',
      { loginId: state },
      { status: 'AUTHORIZED', authorizedAt: now }
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
    const authCode = await this.generateAuthCode(userId, ticket.clientId, ticket.redirectUri);

    // Update ticket with success
    await updateOne(
      'login_states',
      { loginId: state },
      { 
        status: 'SUCCESS', 
        result: { authCode, userId },
        completedAt: now,
      }
    );

    return {
      userId,
      unionid: tokenData.unionid,
      openid: tokenData.openid,
      authCode,
    };
  }

  private async exchangeCodeForToken(code: string): Promise<WeChatTokenResponse> {
    const config = await getConfig();
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
    const db = await this.getDb();

    // First try to find by unionid if available
    if (tokenData.unionid) {
      const identity = await findOne('identities', {
        unionid: tokenData.unionid,
        provider: 'wechat_open_web',
      });

      if (identity) {
        await this.updateLastLogin(identity.userId);
        return identity.userId;
      }
    }

    // Try to find by openid
    const identity = await findOne('identities', {
      openid: tokenData.openid,
      provider: 'wechat_open_web',
    });

    if (identity) {
      // Update unionid if we got it now
      if (tokenData.unionid && !identity.unionid) {
        await updateOne(
          'identities',
          { _id: identity._id },
          { unionid: tokenData.unionid }
        );
      }
      
      await this.updateLastLogin(identity.userId);
      return identity.userId;
    }

    // Create new user
    return await this.createUser(tokenData, userInfo);
  }

  private async createUser(
    tokenData: WeChatTokenResponse,
    userInfo: WeChatUserInfo | null
  ): Promise<string> {
    const db = await this.getDb();
    const now = new Date();

    // Use transaction for atomicity
    const transaction = await db.startTransaction();

    try {
      // Create user
      const userId = await transaction.collection('users').add({
        displayName: userInfo?.nickname || `User_${tokenData.openid.slice(-6)}`,
        avatarUrl: userInfo?.headimgurl || null,
        isDisabled: false,
        createdAt: now,
        lastLoginAt: now,
      });

      // Create identity
      await transaction.collection('identities').add({
        userId: userId.id,
        provider: 'wechat_open_web',
        openid: tokenData.openid,
        unionid: tokenData.unionid || null,
        raw: { tokenData, userInfo },
        createdAt: now,
      });

      // Assign default role
      const role = await transaction.collection('roles')
        .where({ name: 'user' })
        .limit(1)
        .get();

      if (role.data && role.data.length > 0) {
        await transaction.collection('user_roles').add({
          userId: userId.id,
          roleId: role.data[0]._id,
          grantedAt: now,
        });
      }

      // Audit log
      await transaction.collection('audits').add({
        actor: userId.id,
        action: 'user.create',
        resource: `user:${userId.id}`,
        status: 'success',
        ts: now,
        extra: { provider: 'wechat_open_web', openid: tokenData.openid },
      });

      await transaction.commit();

      logger.info({ userId: userId.id, openid: tokenData.openid }, 'Created new user from WeChat');

      return userId.id;
    } catch (error) {
      await transaction.rollback();
      logger.error(error, 'Failed to create user');
      throw error;
    }
  }

  private async updateLastLogin(userId: string): Promise<void> {
    await updateOne('users', { _id: userId }, { lastLoginAt: new Date() });
  }

  private async generateAuthCode(
    userId: string, 
    clientId: string | null, 
    redirectUri: string | null
  ): Promise<string> {
    const code = generateAuthCode();
    const now = new Date();
    const expiresAt = new Date(now.getTime() + 10 * 60 * 1000); // 10 minutes

    await insertOne('auth_codes', {
      code,
      clientId: clientId || 'xjp-web',
      userId,
      redirectUri: redirectUri || 'https://xiaojinpro.com/callback',
      expiresAt,
      used: false,
      createdAt: now,
    });

    return code;
  }

  async getLoginTicketStatus(loginId: string): Promise<{
    status: string;
    result?: any;
  }> {
    const ticket = await findOne('login_states', { loginId });

    if (!ticket) {
      return { status: 'NOT_FOUND' };
    }

    return {
      status: ticket.status,
      result: ticket.result,
    };
  }
}

export const wechatServiceTCB = WeChatServiceTCB.getInstance();