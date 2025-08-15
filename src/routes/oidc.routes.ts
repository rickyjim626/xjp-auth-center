import { FastifyPluginAsync } from 'fastify';
import { z } from 'zod';
import { getConfig } from '../config/auth-config.js';
import { jwtServiceTCB } from '../services/jwt.service.tcb.js';
import { logger } from '../utils/logger.js';
import { TCBDatabase, insertOne, findOne, deleteOne } from '../db/tcb-client.js';
import crypto from 'crypto';

// PKCE验证
function verifyPKCE(verifier: string, challenge: string, method: string = 'S256'): boolean {
  if (method === 'S256') {
    const hash = crypto.createHash('sha256').update(verifier).digest('base64url');
    return hash === challenge;
  }
  return verifier === challenge;
}

// 生成授权码
function generateAuthCode(): string {
  return crypto.randomBytes(32).toString('base64url');
}

// Helper functions for authorization code management
async function storeAuthCode(code: string, data: {
  clientId: string;
  userId: string;
  redirectUri: string;
  scope: string;
  codeChallenge?: string;
  codeChallengeMethod?: string;
  expiresAt: number;
}) {
  await insertOne('auth_codes', {
    code,
    clientId: data.clientId,
    userId: data.userId,
    redirectUri: data.redirectUri,
    scopes: data.scope.split(' '),
    codeChallenge: data.codeChallenge,
    codeChallengeMethod: data.codeChallengeMethod,
    expiresAt: new Date(data.expiresAt),
    createdAt: new Date(),
  });
}

async function getAuthCode(code: string) {
  return await findOne('auth_codes', { code });
}

async function deleteAuthCode(code: string) {
  await deleteOne('auth_codes', { code });
}

// Simplified login state management using memory (can be redis in production)
const loginStates = new Map();

async function getLoginState(loginId: string) {
  const state = loginStates.get(loginId);
  if (state && state.expiresAt > Date.now()) {
    return { state };
  }
  loginStates.delete(loginId);
  return null;
}

async function setLoginState(loginId: string, state: any) {
  loginStates.set(loginId, {
    ...state,
    expiresAt: Date.now() + 10 * 60 * 1000, // 10分钟过期
  });
}

export const oidcRoutes: FastifyPluginAsync = async (fastify) => {
  const config = await getConfig();

  // OIDC Discovery Endpoint
  fastify.get('/.well-known/openid-configuration', async (request, reply) => {
    const issuer = config.jwt.issuer;
    return {
      issuer,
      authorization_endpoint: `${issuer}/oauth2/authorize`,
      token_endpoint: `${issuer}/oauth2/token`,
      userinfo_endpoint: `${issuer}/userinfo`,
      jwks_uri: `${issuer}/.well-known/jwks.json`,
      response_types_supported: ['code', 'id_token', 'token id_token'],
      subject_types_supported: ['public'],
      id_token_signing_alg_values_supported: ['RS256'],
      scopes_supported: ['openid', 'profile', 'email'],
      token_endpoint_auth_methods_supported: ['client_secret_post', 'client_secret_basic'],
      claims_supported: ['sub', 'name', 'nickname', 'picture', 'email', 'email_verified'],
      code_challenge_methods_supported: ['S256', 'plain'],
      grant_types_supported: ['authorization_code', 'refresh_token'],
    };
  });

  // JWKS Endpoint
  fastify.get('/.well-known/jwks.json', async (request, reply) => {
    const jwks = await jwtServiceTCB.getPublicJWKS();
    return jwks;
  });

  // Authorization Endpoint
  const authorizeSchema = z.object({
    response_type: z.enum(['code']),
    client_id: z.string(),
    redirect_uri: z.string().url(),
    scope: z.string().default('openid profile'),
    state: z.string().optional(),
    code_challenge: z.string().optional(),
    code_challenge_method: z.enum(['S256', 'plain']).optional(),
    nonce: z.string().optional(),
  });

  fastify.get('/oauth2/authorize', async (request, reply) => {
    try {
      const params = authorizeSchema.parse(request.query);
      
      // 检查PKCE（如果配置要求）
      if (config.oidc.requirePKCE && !params.code_challenge) {
        return reply.redirect(
          `${params.redirect_uri}?error=invalid_request&error_description=PKCE+required&state=${params.state || ''}`
        );
      }

      // 检查session
      const sessionId = request.cookies['auth_session'];
      const session = sessionId ? await getLoginState(sessionId) : null;
      const sessionData = session?.state;
      
      if (!sessionData || sessionData.expiresAt < Date.now()) {
        // 未登录，检查UA决定微信登录方式
        const isWechatUA = /MicroMessenger/i.test(request.headers['user-agent'] || '');
        
        // 保存授权请求到session
        const authRequestId = crypto.randomBytes(16).toString('hex');
        const authRequest = {
          ...params,
          authRequestId,
        };
        
        // 临时存储授权请求
        await setLoginState(authRequestId, {
          clientId: params.client_id,
          userId: '', // 待填充
          redirectUri: params.redirect_uri,
          scope: params.scope,
          codeChallenge: params.code_challenge,
          codeChallengeMethod: params.code_challenge_method,
          expiresAt: Date.now() + 600000, // 10分钟
        });
        
        // 构建微信授权URL
        const callbackUrl = `${config.jwt.issuer}/wechat/callback`;
        const wxState = Buffer.from(JSON.stringify({
          authRequestId,
          clientId: params.client_id,
          redirectUri: params.redirect_uri,
          state: params.state,
        })).toString('base64url');
        
        if (isWechatUA) {
          // 公众号网页授权
          const wxAuthUrl = new URL('https://open.weixin.qq.com/connect/oauth2/authorize');
          wxAuthUrl.searchParams.set('appid', config.wechat.mpAppId);
          wxAuthUrl.searchParams.set('redirect_uri', callbackUrl);
          wxAuthUrl.searchParams.set('response_type', 'code');
          wxAuthUrl.searchParams.set('scope', 'snsapi_userinfo');
          wxAuthUrl.searchParams.set('state', wxState);
          wxAuthUrl.hash = 'wechat_redirect';
          
          return reply.redirect(wxAuthUrl.toString());
        } else {
          // PC扫码登录
          const wxAuthUrl = new URL('https://open.weixin.qq.com/connect/qrconnect');
          wxAuthUrl.searchParams.set('appid', config.wechat.openAppId);
          wxAuthUrl.searchParams.set('redirect_uri', callbackUrl);
          wxAuthUrl.searchParams.set('response_type', 'code');
          wxAuthUrl.searchParams.set('scope', 'snsapi_login');
          wxAuthUrl.searchParams.set('state', wxState);
          wxAuthUrl.hash = 'wechat_redirect';
          
          return reply.redirect(wxAuthUrl.toString());
        }
      }
      
      // 已登录，生成授权码
      const code = generateAuthCode();
      await storeAuthCode(code, {
        clientId: params.client_id,
        userId: sessionData.userId,
        redirectUri: params.redirect_uri,
        scope: params.scope,
        codeChallenge: params.code_challenge,
        codeChallengeMethod: params.code_challenge_method,
        expiresAt: Date.now() + config.oidc.authCodeExpires * 1000,
      });
      
      // 重定向回客户端
      const redirectUrl = new URL(params.redirect_uri);
      redirectUrl.searchParams.set('code', code);
      if (params.state) {
        redirectUrl.searchParams.set('state', params.state);
      }
      
      return reply.redirect(redirectUrl.toString());
    } catch (error) {
      logger.error({ error }, 'Authorization error');
      return reply.code(400).send({
        error: 'invalid_request',
        error_description: 'Invalid authorization request',
      });
    }
  });

  // Token Endpoint
  const tokenSchema = z.object({
    grant_type: z.enum(['authorization_code', 'refresh_token']),
    code: z.string().optional(),
    redirect_uri: z.string().url().optional(),
    client_id: z.string(),
    client_secret: z.string().optional(),
    code_verifier: z.string().optional(),
    refresh_token: z.string().optional(),
  });

  fastify.post('/oauth2/token', async (request, reply) => {
    try {
      const params = tokenSchema.parse(request.body);
      
      if (params.grant_type === 'authorization_code') {
        // 验证授权码
        const authCodeData = await getAuthCode(params.code!);
        if (!authCodeData) {
          return reply.code(400).send({
            error: 'invalid_grant',
            error_description: 'Invalid authorization code',
          });
        }
        
        // 验证过期
        if (authCodeData.expiresAt.getTime() < Date.now()) {
          await deleteAuthCode(params.code!);
          return reply.code(400).send({
            error: 'invalid_grant',
            error_description: 'Authorization code expired',
          });
        }
        
        // 验证客户端
        if (authCodeData.clientId !== params.client_id) {
          return reply.code(400).send({
            error: 'invalid_client',
            error_description: 'Client mismatch',
          });
        }
        
        // 验证redirect_uri
        if (authCodeData.redirectUri !== params.redirect_uri) {
          return reply.code(400).send({
            error: 'invalid_grant',
            error_description: 'Redirect URI mismatch',
          });
        }
        
        // 验证PKCE
        if (authCodeData.codeChallenge) {
          if (!params.code_verifier) {
            return reply.code(400).send({
              error: 'invalid_grant',
              error_description: 'PKCE verifier required',
            });
          }
          
          const valid = verifyPKCE(
            params.code_verifier,
            authCodeData.codeChallenge,
            authCodeData.codeChallengeMethod || 'S256'
          );
          
          if (!valid) {
            return reply.code(400).send({
              error: 'invalid_grant',
              error_description: 'PKCE verification failed',
            });
          }
        }
        
        // 删除已使用的授权码
        await deleteAuthCode(params.code!);
        
        // 生成tokens
        const { accessToken, refreshToken, idToken } = await jwtServiceTCB.generateTokens({
          userId: authCodeData.userId.toString(),
          clientId: authCodeData.clientId,
          scopes: authCodeData.scopes,
        });
        
        return {
          access_token: accessToken,
          token_type: 'Bearer',
          expires_in: 900, // 15分钟
          refresh_token: refreshToken,
          id_token: idToken,
          scope: authCodeData.scopes.join(' '),
        };
      }
      
      if (params.grant_type === 'refresh_token') {
        // 验证refresh token
        const payload = await jwtServiceTCB.verifyRefreshToken(params.refresh_token!);
        
        // 生成新的tokens
        const { accessToken, refreshToken, idToken } = await jwtServiceTCB.generateTokens({
          userId: payload.sub,
          clientId: params.client_id,
          scope: payload.scope,
        });
        
        return {
          access_token: accessToken,
          token_type: 'Bearer',
          expires_in: 900,
          refresh_token: refreshToken,
          id_token: idToken,
          scope: payload.scope,
        };
      }
      
      return reply.code(400).send({
        error: 'unsupported_grant_type',
        error_description: 'Grant type not supported',
      });
    } catch (error) {
      logger.error({ error }, 'Token error');
      return reply.code(400).send({
        error: 'invalid_request',
        error_description: 'Invalid token request',
      });
    }
  });

  // UserInfo Endpoint
  fastify.get('/userinfo', async (request, reply) => {
    try {
      const authHeader = request.headers.authorization;
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return reply.code(401).send({
          error: 'invalid_token',
          error_description: 'Bearer token required',
        });
      }
      
      const token = authHeader.substring(7);
      const payload = await jwtServiceTCB.verifyAccessToken(token);
      
      // TODO: 从数据库获取用户信息
      const userInfo = {
        sub: payload.sub,
        name: payload.name || 'User',
        nickname: payload.nickname,
        picture: payload.picture,
        email: payload.email,
        email_verified: false,
      };
      
      return userInfo;
    } catch (error) {
      logger.error({ error }, 'UserInfo error');
      return reply.code(401).send({
        error: 'invalid_token',
        error_description: 'Invalid or expired token',
      });
    }
  });
};