import { FastifyPluginAsync } from 'fastify';
import { z } from 'zod';
import { TCBDatabase, findOne, findMany, updateOne } from '../db/tcb-client.js';
import { jwtServiceTCB } from '../services/jwt.service.tcb.js';
import { logger } from '../utils/logger.js';

// Middleware to verify JWT and extract user
async function authenticate(request: any, reply: any) {
  try {
    const authHeader = request.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return reply.code(401).send({ error: 'unauthorized' });
    }

    const token = authHeader.substring(7);
    const result = await jwtServiceTCB.verifyToken(token);
    request.user = result.payload;
  } catch (error) {
    return reply.code(401).send({ error: 'invalid_token' });
  }
}

export const usersRoutesTCB: FastifyPluginAsync = async (fastify) => {
  // Get current user
  fastify.get('/v1/users/me', { preHandler: authenticate }, async (request, reply) => {
    const user = (request as any).user;
    
    try {
      // 获取用户基本信息
      const userInfo = await findOne('users', { id: parseInt(user.sub) });
      if (!userInfo) {
        return reply.code(404).send({ error: 'user_not_found' });
      }

      // 获取用户身份信息
      const identities = await findMany('identities', { userId: parseInt(user.sub) });
      
      // 获取用户角色
      const userRoles = await findMany('user_roles', { userId: parseInt(user.sub) });
      const roleIds = userRoles.map(ur => ur.roleId);
      const roles = roleIds.length > 0 ? await findMany('roles', { name: { $in: roleIds } }) : [];

      const result = {
        id: userInfo.id,
        display_name: userInfo.displayName,
        avatar_url: userInfo.avatarUrl,
        email: userInfo.email || null,
        phone: userInfo.phone || null,
        created_at: userInfo.createdAt,
        last_login_at: userInfo.lastLoginAt,
        identities: identities.map(i => ({
          provider: i.provider,
          openid: i.openidMap ? Object.keys(i.openidMap)[0] : null,
          unionid: i.unionid
        })),
        roles: roles.map(r => r.name)
      };

      return reply.send(result);
    } catch (error) {
      logger.error(error, 'Failed to get user profile');
      return reply.code(500).send({ error: 'internal_server_error' });
    }
  });

  // Update current user
  fastify.patch('/v1/users/me', { preHandler: authenticate }, async (request, reply) => {
    const user = (request as any).user;
    
    const updateSchema = z.object({
      display_name: z.string().min(1).max(100).optional(),
      avatar_url: z.string().url().optional(),
      email: z.string().email().optional(),
      phone: z.string().optional(),
    });

    try {
      const updates = updateSchema.parse(request.body);
      
      // 更新用户信息
      const updated = await updateOne('users', 
        { id: parseInt(user.sub) }, 
        {
          ...(updates.display_name && { displayName: updates.display_name }),
          ...(updates.avatar_url && { avatarUrl: updates.avatar_url }),
          ...(updates.email && { email: updates.email }),
          ...(updates.phone && { phone: updates.phone }),
          updatedAt: new Date(),
        }
      );

      if (!updated) {
        return reply.code(404).send({ error: 'user_not_found' });
      }

      return reply.send({ success: true });
    } catch (error) {
      if (error instanceof z.ZodError) {
        return reply.code(400).send({ 
          error: 'validation_error',
          details: error.errors 
        });
      }
      
      logger.error(error, 'Failed to update user profile');
      return reply.code(500).send({ error: 'internal_server_error' });
    }
  });

  // Get user sessions
  fastify.get('/v1/sessions', { preHandler: authenticate }, async (request, reply) => {
    const user = (request as any).user;
    
    try {
      const sessions = await findMany('sessions', { 
        userId: parseInt(user.sub),
        revokedAt: null 
      });

      return reply.send({
        sessions: sessions.map(s => ({
          id: s._id,
          client_id: s.clientId,
          created_at: s.createdAt,
          last_activity_at: s.lastActivityAt,
        }))
      });
    } catch (error) {
      logger.error(error, 'Failed to get sessions');
      return reply.code(500).send({ error: 'internal_server_error' });
    }
  });

  // Revoke session
  fastify.post('/v1/sessions/:id/revoke', { preHandler: authenticate }, async (request, reply) => {
    const user = (request as any).user;
    const { id } = request.params as { id: string };

    try {
      // 检查session是否属于当前用户
      const session = await findOne('sessions', { 
        _id: id, 
        userId: parseInt(user.sub) 
      });

      if (!session) {
        return reply.code(404).send({ error: 'session_not_found' });
      }

      // 撤销session
      await updateOne('sessions', { _id: id }, { revokedAt: new Date() });

      // 撤销相关的refresh tokens
      await updateOne('refresh_toke', 
        { sessionId: id, revokedAt: null }, 
        { revokedAt: new Date() }
      );

      return reply.send({ success: true });
    } catch (error) {
      logger.error(error, 'Failed to revoke session');
      return reply.code(500).send({ error: 'internal_server_error' });
    }
  });
};