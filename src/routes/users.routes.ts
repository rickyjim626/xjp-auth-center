import { FastifyPluginAsync } from 'fastify';
import { z } from 'zod';
import { getRepos } from '../repos/index.js';
import { logger } from '../utils/logger.js';

// Simplified JWT verification middleware
async function authenticate(request: any, reply: any) {
  try {
    const authHeader = request.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return reply.status(401).send({ error: 'unauthorized' });
    }

    const token = authHeader.substring(7);
    
    // Simplified token validation - in a real implementation you'd verify JWT
    // For now, we'll extract user info from a simple token format
    if (token.startsWith('at_')) {
      const jti = token.substring(3);
      const repos = getRepos();
      const tokenRecord = await repos.oauth.findTokenByJti(jti);
      
      if (!tokenRecord || tokenRecord.token_type !== 'access_token' || tokenRecord.revoked_at) {
        return reply.status(401).send({ error: 'invalid_token' });
      }

      if (tokenRecord.expires_at.getTime() < Date.now()) {
        return reply.status(401).send({ error: 'token_expired' });
      }

      // Update last used
      await repos.oauth.updateTokenLastUsed(jti);
      
      request.user = {
        sub: tokenRecord.user_id.toString(),
        scopes: tokenRecord.scopes,
        clientId: tokenRecord.client_id,
        sessionId: tokenRecord.session_id,
      };
    } else {
      // For backward compatibility with JWT tokens, you'd verify with JWT service here
      return reply.status(401).send({ error: 'invalid_token_format' });
    }
  } catch (error) {
    logger.error(error, 'Authentication failed');
    return reply.status(401).send({ error: 'invalid_token' });
  }
}

export const usersRoutes: FastifyPluginAsync = async (fastify) => {
  const repos = getRepos();

  // Get current user
  fastify.get('/v1/users/me', { preHandler: authenticate }, async (request, reply) => {
    const user = (request as any).user;
    
    try {
      const userId = parseInt(user.sub);
      
      // Get user info
      const userInfo = await repos.users.findById(userId);
      if (!userInfo) {
        return reply.status(404).send({ error: 'user_not_found' });
      }

      // Get user identities
      const identities = await repos.identities.findByUserId(userId);
      
      const result = {
        id: userInfo.id,
        display_name: userInfo.nickname,
        avatar_url: userInfo.avatar,
        email: userInfo.email || null,
        is_admin: userInfo.is_admin,
        created_at: userInfo.created_at,
        last_login_at: userInfo.last_login_at,
        identities: identities.map(i => ({
          provider: i.provider,
          openid: i.openid,
          unionid: i.unionid
        }))
      };

      return reply.send(result);
    } catch (error) {
      logger.error(error, 'Failed to get user profile');
      return reply.status(500).send({ error: 'internal_server_error' });
    }
  });

  // Update current user
  fastify.patch('/v1/users/me', { preHandler: authenticate }, async (request, reply) => {
    const user = (request as any).user;
    
    const updateSchema = z.object({
      display_name: z.string().min(1).max(100).optional(),
      avatar_url: z.string().url().optional(),
      email: z.string().email().optional(),
    });

    try {
      const updates = updateSchema.parse(request.body);
      const userId = parseInt(user.sub);
      
      // Update user info
      const updated = await repos.users.update(userId, {
        nickname: updates.display_name,
        avatar: updates.avatar_url,
        email: updates.email,
      });

      if (!updated) {
        return reply.status(404).send({ error: 'user_not_found' });
      }

      return reply.send({ success: true });
    } catch (error) {
      if (error instanceof z.ZodError) {
        return reply.status(400).send({ 
          error: 'validation_error',
          details: error.errors 
        });
      }
      
      logger.error(error, 'Failed to update user profile');
      return reply.status(500).send({ error: 'internal_server_error' });
    }
  });

  // Get user sessions
  fastify.get('/v1/sessions', { preHandler: authenticate }, async (request, reply) => {
    const user = (request as any).user;
    
    try {
      const userId = parseInt(user.sub);
      
      const tokens = await repos.oauth.findTokensByUserId(userId, {
        tokenType: 'refresh_token',
        includeRevoked: false,
        limit: 20,
      });

      return reply.send({
        sessions: tokens.map(token => ({
          id: token.session_id,
          client_id: token.client_id,
          created_at: token.created_at,
          last_activity_at: token.last_used_at || token.created_at,
          expires_at: token.expires_at,
          device_info: token.device_info,
        }))
      });
    } catch (error) {
      logger.error(error, 'Failed to get sessions');
      return reply.status(500).send({ error: 'internal_server_error' });
    }
  });

  // Revoke session
  fastify.post('/v1/sessions/:sessionId/revoke', { preHandler: authenticate }, async (request, reply) => {
    const user = (request as any).user;
    const { sessionId } = request.params as { sessionId: string };

    try {
      const userId = parseInt(user.sub);
      
      // Verify session belongs to user
      const tokens = await repos.oauth.findTokensByUserId(userId, {
        includeRevoked: false,
      });
      
      const sessionExists = tokens.some(token => token.session_id === sessionId);
      if (!sessionExists) {
        return reply.status(404).send({ error: 'session_not_found' });
      }

      // Revoke all tokens in this session
      const revokedCount = await repos.oauth.revokeTokensBySessionId(sessionId);

      logger.info({ userId, sessionId, revokedCount }, 'Session revoked');

      return reply.send({ success: true, revoked_tokens: revokedCount });
    } catch (error) {
      logger.error(error, 'Failed to revoke session');
      return reply.status(500).send({ error: 'internal_server_error' });
    }
  });

  // UserInfo endpoint (OpenID Connect)
  fastify.get('/userinfo', { preHandler: authenticate }, async (request, reply) => {
    const user = (request as any).user;
    
    try {
      const userId = parseInt(user.sub);
      
      const userInfo = await repos.users.findById(userId);
      if (!userInfo) {
        return reply.status(404).send({ error: 'user_not_found' });
      }

      const identities = await repos.identities.findByUserId(userId);
      const wechatIdentity = identities.find(i => i.provider === 'wechat');

      // Standard OpenID Connect claims
      const result: any = {
        sub: userId.toString(),
        name: userInfo.nickname,
        nickname: userInfo.nickname,
        picture: userInfo.avatar,
        email: userInfo.email,
        email_verified: false, // We don't verify emails currently
        updated_at: Math.floor(userInfo.updated_at.getTime() / 1000),
      };

      // Add WeChat-specific claims if available
      if (wechatIdentity) {
        result['wechat_openid'] = wechatIdentity.openid;
        if (wechatIdentity.unionid) {
          result['wechat_unionid'] = wechatIdentity.unionid;
        }
      }

      return reply.send(result);
    } catch (error) {
      logger.error(error, 'UserInfo error');
      return reply.status(500).send({ error: 'internal_server_error' });
    }
  });
};