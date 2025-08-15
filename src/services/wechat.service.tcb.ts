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
  errcode?: number;
  errmsg?: string;
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
  errcode?: number;
  errmsg?: string;
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

    // Construct WeChat QR URL for PC scanning with embedded clientId/redirectUri in state
    const state = JSON.stringify({ 
      loginId,
      clientId: clientId || 'xjp-web',
      redirectUri: redirectUri || 'https://xiaojinpro.com/callback',
    });

    const params = new URLSearchParams({
      appid: config.wechat.openAppId,
      redirect_uri: config.wechat.redirectUri,
      response_type: 'code',
      scope: 'snsapi_login',
      state: Buffer.from(state).toString('base64'),
    });

    const qrUrl = `https://open.weixin.qq.com/connect/qrconnect?${params.toString()}#wechat_redirect`;

    logger.info({ loginId }, 'Generated WeChat QR code');

    return {
      loginId,
      qrUrl,
      expiresIn,
    };
  }

  async handleCallback(code: string, state: string, isFromMP: boolean = false): Promise<{
    userId: string;
    unionid?: string;
    openid: string;
    authCode: string;
  }> {
    const now = new Date();

    // Decode state to get clientId and redirectUri
    let stateData: any;
    try {
      const decoded = Buffer.from(state, 'base64').toString('utf-8');
      stateData = JSON.parse(decoded);
    } catch (error) {
      throw new Error('Invalid state parameter');
    }

    // Exchange code for access token
    const tokenData = await this.exchangeCodeForToken(code, isFromMP);

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
    const authCode = await this.generateAuthCode(userId, stateData.clientId, stateData.redirectUri);

    return {
      userId,
      unionid: tokenData.unionid,
      openid: tokenData.openid,
      authCode,
    };
  }

  private async exchangeCodeForToken(code: string, isFromMP: boolean = false): Promise<WeChatTokenResponse> {
    const config = await getConfig();
    const url = new URL('https://api.weixin.qq.com/sns/oauth2/access_token');
    
    // Use different app credentials based on source
    if (isFromMP) {
      url.searchParams.append('appid', config.wechat.mpAppId);
      url.searchParams.append('secret', config.wechat.mpAppSecret);
    } else {
      url.searchParams.append('appid', config.wechat.openAppId);
      url.searchParams.append('secret', config.wechat.openAppSecret);
    }
    
    url.searchParams.append('code', code);
    url.searchParams.append('grant_type', 'authorization_code');

    const response = await fetch(url.toString());
    const data = (await response.json()) as WeChatTokenResponse;

    if (data.errcode) {
      logger.error({ error: data }, 'WeChat token exchange failed');
      throw new Error(`WeChat API error: ${data.errmsg}`);
    }

    return data;
  }

  private async getUserInfo(accessToken: string, openid: string): Promise<WeChatUserInfo> {
    const url = new URL('https://api.weixin.qq.com/sns/userinfo');
    url.searchParams.append('access_token', accessToken);
    url.searchParams.append('openid', openid);
    url.searchParams.append('lang', 'zh_CN');

    const response = await fetch(url.toString());
    const data = (await response.json()) as WeChatUserInfo;

    if (data.errcode) {
      throw new Error(`WeChat API error: ${data.errmsg}`);
    }

    return data;
  }

  private async findOrCreateUser(
    tokenData: WeChatTokenResponse,
    userInfo: WeChatUserInfo | null
  ): Promise<string> {
    const config = await getConfig();
    
    // First try to find by unionid if available
    if (tokenData.unionid && config.wechat.useUnionId) {
      const identity = await findOne('identities', {
        provider: 'wechat',
        unionid: tokenData.unionid,
      });

      if (identity) {
        await this.updateLastLogin(identity.userId);
        return identity.userId;
      }
    }

    // Try to find by openid
    const identity = await findOne('identities', {
      provider: 'wechat',
      openid: tokenData.openid,
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
      // Create user (simplified with isAdmin flag)
      const userId = await transaction.collection('users').add({
        displayName: userInfo?.nickname || `User_${tokenData.openid.slice(-6)}`,
        email: null,
        avatar: userInfo?.headimgurl || null,
        isAdmin: false,
        isDisabled: false,
        createdAt: now,
        lastLoginAt: now,
      });

      // Create identity (simplified with openid field)
      await transaction.collection('identities').add({
        userId: userId.id,
        provider: 'wechat',
        openid: tokenData.openid,
        unionid: tokenData.unionid || null,
        profile: {
          nickname: userInfo?.nickname,
          headimgurl: userInfo?.headimgurl,
          rawData: { tokenData, userInfo }
        },
        createdAt: now,
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
      scopes: ['openid', 'profile'],
      expiresAt,
      createdAt: now,
    });

    return code;
  }
}

export const wechatServiceTCB = WeChatServiceTCB.getInstance();