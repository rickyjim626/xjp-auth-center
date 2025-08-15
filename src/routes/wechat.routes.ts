import { FastifyPluginAsync } from 'fastify';
import { z } from 'zod';
import { getConfig } from '../config/auth-config.js';
import { wechatServiceTCB } from '../services/wechat.service.tcb.js';
import { jwtServiceTCB } from '../services/jwt.service.tcb.js';
import { logger } from '../utils/logger.js';
import { TCBDatabase, insertOne, findOne, deleteOne } from '../db/tcb-client.js';
import crypto from 'crypto';

// Helper functions for login state management
async function setLoginState(loginId: string, state: any) {
  await insertOne('login_states', {
    loginId,
    state,
    expiresAt: Date.now() + 10 * 60 * 1000, // 10分钟过期
  });
}

async function getLoginState(loginId: string) {
  return await findOne('login_states', { loginId });
}

async function deleteLoginState(loginId: string) {
  await deleteOne('login_states', { loginId });
}

export const wechatRoutes: FastifyPluginAsync = async (fastify) => {
  const config = await getConfig();

  // 微信回调处理
  fastify.get('/wechat/callback', async (request, reply) => {
    try {
      const { code, state } = request.query as { code: string; state: string };
      
      if (!code || !state) {
        return reply.code(400).send({
          error: 'invalid_request',
          error_description: 'Missing code or state parameter',
        });
      }

      // 解析state（包含原始授权请求信息）
      let authRequest: any;
      try {
        authRequest = JSON.parse(Buffer.from(state, 'base64url').toString());
      } catch (error) {
        logger.error({ error, state }, 'Failed to parse state');
        return reply.code(400).send({
          error: 'invalid_request',
          error_description: 'Invalid state parameter',
        });
      }

      // 判断是否来自公众号
      const isFromMP = authRequest.source === 'mp';
      
      // 处理微信回调
      const result = await wechatServiceTCB.handleCallback(code, authRequest.authRequestId || state, isFromMP);
      
      // 创建session
      const sessionId = crypto.randomBytes(32).toString('hex');
      const sessionExpires = Date.now() + config.cookie.sessionExpires;
      
      await setLoginState(sessionId, {
        userId: result.userId,
        unionId: result.unionid,
        openId: result.openid,
        expiresAt: sessionExpires,
      });
      
      // 设置session cookie
      reply.setCookie('auth_session', sessionId, {
        httpOnly: true,
        secure: config.cookie.secure,
        sameSite: config.cookie.sameSite,
        path: '/',
        maxAge: config.cookie.sessionExpires / 1000, // 转换为秒
      });
      
      // 如果有原始的授权请求，重定向回authorize端点
      if (authRequest.clientId && authRequest.redirectUri) {
        const authorizeUrl = new URL(`${config.jwt.issuer}/oauth2/authorize`);
        authorizeUrl.searchParams.set('response_type', 'code');
        authorizeUrl.searchParams.set('client_id', authRequest.clientId);
        authorizeUrl.searchParams.set('redirect_uri', authRequest.redirectUri);
        if (authRequest.scope) {
          authorizeUrl.searchParams.set('scope', authRequest.scope);
        }
        if (authRequest.state) {
          authorizeUrl.searchParams.set('state', authRequest.state);
        }
        if (authRequest.codeChallenge) {
          authorizeUrl.searchParams.set('code_challenge', authRequest.codeChallenge);
          authorizeUrl.searchParams.set('code_challenge_method', authRequest.codeChallengeMethod || 'S256');
        }
        
        return reply.redirect(authorizeUrl.toString());
      }
      
      // 默认重定向到首页
      return reply.redirect(authRequest.redirectUri || 'https://xiaojinpro.com');
    } catch (error) {
      logger.error({ error }, 'WeChat callback error');
      return reply.code(500).send({
        error: 'server_error',
        error_description: 'Failed to process WeChat callback',
      });
    }
  });

  // 生成微信登录URL（API方式）
  fastify.post('/wechat/login-url', async (request, reply) => {
    try {
      const schema = z.object({
        type: z.enum(['pc', 'mp']).default('pc'),
        redirectUri: z.string().url().optional(),
        state: z.string().optional(),
      });
      
      const params = schema.parse(request.body);
      
      // 生成state
      const authState = Buffer.from(JSON.stringify({
        source: params.type,
        redirectUri: params.redirectUri,
        state: params.state,
        timestamp: Date.now(),
      })).toString('base64url');
      
      const callbackUrl = `${config.jwt.issuer}/wechat/callback`;
      
      let loginUrl: string;
      if (params.type === 'mp') {
        // 公众号网页授权
        const wxAuthUrl = new URL('https://open.weixin.qq.com/connect/oauth2/authorize');
        wxAuthUrl.searchParams.set('appid', config.wechat.mpAppId);
        wxAuthUrl.searchParams.set('redirect_uri', callbackUrl);
        wxAuthUrl.searchParams.set('response_type', 'code');
        wxAuthUrl.searchParams.set('scope', 'snsapi_userinfo');
        wxAuthUrl.searchParams.set('state', authState);
        wxAuthUrl.hash = 'wechat_redirect';
        loginUrl = wxAuthUrl.toString();
      } else {
        // PC扫码登录
        const wxAuthUrl = new URL('https://open.weixin.qq.com/connect/qrconnect');
        wxAuthUrl.searchParams.set('appid', config.wechat.openAppId);
        wxAuthUrl.searchParams.set('redirect_uri', callbackUrl);
        wxAuthUrl.searchParams.set('response_type', 'code');
        wxAuthUrl.searchParams.set('scope', 'snsapi_login');
        wxAuthUrl.searchParams.set('state', authState);
        wxAuthUrl.hash = 'wechat_redirect';
        loginUrl = wxAuthUrl.toString();
      }
      
      return {
        loginUrl,
        type: params.type,
      };
    } catch (error) {
      logger.error({ error }, 'Failed to generate WeChat login URL');
      return reply.code(400).send({
        error: 'invalid_request',
        error_description: 'Failed to generate login URL',
      });
    }
  });

  // 检查登录状态
  fastify.get('/wechat/check-session', async (request, reply) => {
    const sessionId = request.cookies['auth_session'];
    
    if (!sessionId) {
      return { logged_in: false };
    }
    
    const session = await getLoginState(sessionId);
    if (!session || session.state.expiresAt < Date.now()) {
      await deleteLoginState(sessionId);
      return { logged_in: false };
    }
    
    return {
      logged_in: true,
      user_id: session.state.userId,
      expires_at: session.state.expiresAt,
    };
  });

  // 登出
  fastify.post('/wechat/logout', async (request, reply) => {
    const sessionId = request.cookies['auth_session'];
    
    if (sessionId) {
      await deleteLoginState(sessionId);
      reply.clearCookie('auth_session');
    }
    
    return { success: true };
  });
};

// 导出session管理器供其他模块使用
export async function getSession(sessionId: string) {
  const session = await getLoginState(sessionId);
  if (!session || session.state.expiresAt < Date.now()) {
    await deleteLoginState(sessionId);
    return null;
  }
  return session.state;
}

export async function createSession(userId: string, unionId?: string, openId?: string) {
  const sessionId = crypto.randomBytes(32).toString('hex');
  const sessionExpires = Date.now() + 86400000; // 24小时
  
  await setLoginState(sessionId, {
    userId,
    unionId,
    openId: openId || '',
    expiresAt: sessionExpires,
  });
  
  return sessionId;
}