import { FastifyPluginAsync } from 'fastify';
import { z } from 'zod';
import { getConfig } from '../config/auth-config.js';
import { getRepos } from '../repos/index.js';
import { getRedisManager } from '../infra/redis.js';
import { logger } from '../utils/logger.js';
import crypto from 'crypto';

// WeChat API interfaces
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

const qrSchema = z.object({
  client_id: z.string().optional(),
  redirect_uri: z.string().url().optional(),
});

const callbackSchema = z.object({
  code: z.string(),
  state: z.string(),
});

export const authRoutes: FastifyPluginAsync = async (fastify) => {
  const config = await getConfig();
  const repos = getRepos();
  const redis = getRedisManager();

  // Generate WeChat QR code
  fastify.post('/auth/wechat/qr', async (request, reply) => {
    try {
      const body = request.body ? qrSchema.parse(request.body) : {};
      
      const loginId = crypto.randomBytes(16).toString('hex');
      const expiresIn = 300; // 5 minutes

      // Store login state in Redis
      await redis.setLoginState(loginId, {
        clientId: body.client_id || 'xjp-web',
        redirectUri: body.redirect_uri || 'https://xiaojinpro.com/callback',
        status: 'PENDING',
        createdAt: new Date(),
      }, expiresIn);

      // Build WeChat QR URL
      const callbackUrl = `${config.jwt.issuer}/auth/wechat/callback`;
      const state = Buffer.from(JSON.stringify({
        loginId,
        clientId: body.client_id || 'xjp-web',
        redirectUri: body.redirect_uri || 'https://xiaojinpro.com/callback',
      })).toString('base64url');

      const qrUrl = new URL('https://open.weixin.qq.com/connect/qrconnect');
      qrUrl.searchParams.set('appid', config.wechat.openAppId);
      qrUrl.searchParams.set('redirect_uri', callbackUrl);
      qrUrl.searchParams.set('response_type', 'code');
      qrUrl.searchParams.set('scope', 'snsapi_login');
      qrUrl.searchParams.set('state', state);
      qrUrl.hash = 'wechat_redirect';

      logger.info({ loginId }, 'Generated WeChat QR code');

      return reply.send({
        loginId,
        qrUrl: qrUrl.toString(),
        expiresIn,
      });
    } catch (error) {
      logger.error(error, 'Failed to generate QR code');
      return reply.status(500).send({
        error: 'internal_server_error',
        message: 'Failed to generate QR code',
      });
    }
  });

  // WeChat OAuth callback
  fastify.get('/auth/wechat/callback', async (request, reply) => {
    try {
      const query = callbackSchema.parse(request.query);
      
      // Decode state
      let stateData: any;
      try {
        const decoded = Buffer.from(query.state, 'base64url').toString('utf-8');
        stateData = JSON.parse(decoded);
      } catch (error) {
        throw new Error('Invalid state parameter');
      }

      // Determine if this is from MP or Open Platform
      const isFromMP = /MicroMessenger/i.test(request.headers['user-agent'] || '');
      
      // Exchange code for access token
      const tokenData = await exchangeCodeForToken(query.code, isFromMP, config);

      // Get user info
      let userInfo: WeChatUserInfo | null = null;
      try {
        userInfo = await getUserInfo(tokenData.access_token, tokenData.openid);
      } catch (error) {
        logger.warn(error, 'Failed to fetch WeChat user info, continuing with basic data');
      }

      // Find or create user
      const userId = await findOrCreateUser(tokenData, userInfo, repos);

      // Update login state
      await redis.setLoginState(stateData.loginId, {
        status: 'SUCCESS',
        userId,
        openid: tokenData.openid,
        unionid: tokenData.unionid,
        completedAt: new Date(),
      }, 300);

      // Generate authorization code
      const authCode = await generateAuthCode(userId, stateData.clientId, stateData.redirectUri, repos, config);

      // For API requests, return JSON
      const acceptHeader = request.headers.accept || '';
      if (acceptHeader.includes('application/json')) {
        return reply.send({
          success: true,
          authCode,
          userId,
        });
      }

      // For browser requests, redirect to success page
      return reply.redirect(`/auth/success?code=${authCode}`);
    } catch (error) {
      logger.error(error, 'WeChat callback failed');
      
      const state = (request.query as any).state;
      if (state) {
        try {
          const decoded = Buffer.from(state, 'base64url').toString('utf-8');
          const stateData = JSON.parse(decoded);
          await redis.setLoginState(stateData.loginId, {
            status: 'FAILED',
            error: error instanceof Error ? error.message : String(error),
            failedAt: new Date(),
          }, 300);
        } catch (decodeError) {
          // Ignore state decode errors
          logger.debug(decodeError, 'Failed to decode state parameter');
        }
      }

      return reply.status(400).send({
        error: 'authentication_failed',
        message: 'WeChat authentication failed',
      });
    }
  });

  // SSE login status stream
  fastify.get('/auth/login-stream', async (request, reply) => {
    const { loginId } = request.query as { loginId: string };
    
    if (!loginId) {
      return reply.status(400).send({
        error: 'invalid_request',
        message: 'Login ID is required',
      });
    }

    // Set up SSE headers
    reply.raw.setHeader('Content-Type', 'text/event-stream');
    reply.raw.setHeader('Cache-Control', 'no-cache');
    reply.raw.setHeader('Connection', 'keep-alive');
    reply.raw.setHeader('Access-Control-Allow-Origin', '*');

    // Send initial connection event
    reply.raw.write('event: connected\n');
    reply.raw.write('data: {"status":"connected"}\n\n');

    // Check login status periodically
    const checkInterval = setInterval(async () => {
      try {
        const loginState = await redis.getLoginState(loginId);
        
        if (loginState) {
          reply.raw.write('event: status\n');
          reply.raw.write(`data: ${JSON.stringify(loginState)}\n\n`);
          
          if (loginState.status === 'SUCCESS' || loginState.status === 'FAILED') {
            clearInterval(checkInterval);
            reply.raw.end();
          }
        } else {
          // Login state expired
          reply.raw.write('event: status\n');
          reply.raw.write('data: {"status":"EXPIRED"}\n\n');
          clearInterval(checkInterval);
          reply.raw.end();
        }
      } catch (error) {
        logger.error(error, 'SSE status check failed');
        clearInterval(checkInterval);
        reply.raw.end();
      }
    }, 2000); // Check every 2 seconds

    // Clean up on client disconnect
    request.raw.on('close', () => {
      clearInterval(checkInterval);
    });

    // Keep connection open
    return reply;
  });

  // Login status check (polling alternative)
  fastify.get('/auth/login-status/:loginId', async (request, reply) => {
    const { loginId } = request.params as { loginId: string };
    
    try {
      const loginState = await redis.getLoginState(loginId);
      
      if (!loginState) {
        return reply.send({ status: 'NOT_FOUND' });
      }

      return reply.send(loginState);
    } catch (error) {
      logger.error(error, 'Failed to get login status');
      return reply.status(500).send({
        error: 'internal_server_error',
        message: 'Failed to get login status',
      });
    }
  });
};

// Helper functions
async function exchangeCodeForToken(code: string, isFromMP: boolean, config: any): Promise<WeChatTokenResponse> {
  const url = new URL('https://api.weixin.qq.com/sns/oauth2/access_token');
  
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

async function getUserInfo(accessToken: string, openid: string): Promise<WeChatUserInfo> {
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

async function findOrCreateUser(
  tokenData: WeChatTokenResponse,
  userInfo: WeChatUserInfo | null,
  repos: any
): Promise<number> {
  // Try to find by unionid first
  if (tokenData.unionid) {
    const identity = await repos.identities.findByUnionId(tokenData.unionid);
    if (identity) {
      await repos.users.updateLastLogin(identity.user_id);
      return identity.user_id;
    }
  }

  // Try to find by openid
  const identity = await repos.identities.findByProviderAndOpenId('wechat', tokenData.openid);
  if (identity) {
    // Update unionid if we got it now
    if (tokenData.unionid && !identity.unionid) {
      await repos.identities.updateUnionId(identity.id, tokenData.unionid);
    }
    
    await repos.users.updateLastLogin(identity.user_id);
    return identity.user_id;
  }

  // Create new user
  const user = await repos.users.create({
    nickname: userInfo?.nickname || `User_${tokenData.openid.slice(-6)}`,
    avatar: userInfo?.headimgurl || null,
    is_admin: false,
  });

  // Create identity
  await repos.identities.create({
    user_id: user.id,
    provider: 'wechat',
    openid: tokenData.openid,
    unionid: tokenData.unionid || null,
    profile: {
      nickname: userInfo?.nickname,
      headimgurl: userInfo?.headimgurl,
      rawData: { tokenData, userInfo }
    },
  });

  logger.info({ userId: user.id, openid: tokenData.openid }, 'Created new user from WeChat');
  return user.id;
}

async function generateAuthCode(
  userId: number,
  clientId: string,
  redirectUri: string,
  repos: any,
  config: any
): Promise<string> {
  const code = crypto.randomBytes(32).toString('base64url');
  const expiresAt = new Date(Date.now() + config.oidc.authCodeExpires * 1000);

  await repos.oauth.createAuthCode({
    code,
    client_id: clientId,
    user_id: userId,
    redirect_uri: redirectUri,
    scopes: ['openid', 'profile'],
    expires_at: expiresAt,
  });

  return code;
}