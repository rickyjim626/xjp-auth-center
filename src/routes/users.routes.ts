import { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { db } from '../db/client.js';
import { jwtService } from '../services/jwt.service.js';
import { logger } from '../utils/logger.js';

// Middleware to verify JWT and extract user
async function authenticate(request: any, reply: any) {
  try {
    const authHeader = request.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return reply.code(401).send({ error: 'unauthorized' });
    }

    const token = authHeader.substring(7);
    const result = await jwtService.verifyToken(token);
    request.user = result.payload;
  } catch (error) {
    return reply.code(401).send({ error: 'invalid_token' });
  }
}

export async function usersRoutes(fastify: FastifyInstance) {
  // Get current user
  fastify.get('/v1/users/me', { preHandler: authenticate }, async (request, reply) => {
    const user = (request as any).user;
    
    try {
      const result = await db.query(
        `SELECT u.id, u.display_name, u.avatar_url, u.email, u.phone,
                u.created_at, u.last_login_at,
                COALESCE(
                  json_agg(
                    DISTINCT jsonb_build_object(
                      'provider', i.provider,
                      'openid', i.openid,
                      'unionid', i.unionid
                    )
                  ) FILTER (WHERE i.id IS NOT NULL),
                  '[]'::json
                ) as identities,
                COALESCE(
                  json_agg(DISTINCT r.name) FILTER (WHERE r.id IS NOT NULL),
                  '[]'::json
                ) as roles
         FROM users u
         LEFT JOIN identities i ON u.id = i.user_id
         LEFT JOIN user_roles ur ON u.id = ur.user_id
         LEFT JOIN roles r ON ur.role_id = r.id
         WHERE u.id = $1
         GROUP BY u.id`,
        [user.sub]
      );

      if (result.rows.length === 0) {
        return reply.code(404).send({ error: 'user_not_found' });
      }

      return reply.send(result.rows[0]);
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
      const body = updateSchema.parse(request.body);
      
      const updates: string[] = [];
      const values: any[] = [];
      let paramCount = 1;

      if (body.display_name !== undefined) {
        updates.push(`display_name = $${paramCount++}`);
        values.push(body.display_name);
      }
      if (body.avatar_url !== undefined) {
        updates.push(`avatar_url = $${paramCount++}`);
        values.push(body.avatar_url);
      }
      if (body.email !== undefined) {
        updates.push(`email = $${paramCount++}`);
        values.push(body.email);
      }
      if (body.phone !== undefined) {
        updates.push(`phone = $${paramCount++}`);
        values.push(body.phone);
      }

      if (updates.length === 0) {
        return reply.code(400).send({ error: 'no_updates' });
      }

      values.push(user.sub);
      
      const result = await db.query(
        `UPDATE users SET ${updates.join(', ')}, updated_at = NOW()
         WHERE id = $${paramCount}
         RETURNING id, display_name, avatar_url, email, phone, created_at, updated_at`,
        values
      );

      // Audit log
      await db.query(
        `INSERT INTO audit_logs (actor, action, resource, status, ts, extra)
         VALUES ($1, $2, $3, $4, NOW(), $5)`,
        [user.sub, 'user.update', `user:${user.sub}`, 'success', JSON.stringify(body)]
      );

      return reply.send(result.rows[0]);
    } catch (error) {
      logger.error(error, 'Failed to update user');
      return reply.code(500).send({ error: 'internal_server_error' });
    }
  });

  // Get user sessions
  fastify.get('/v1/sessions', { preHandler: authenticate }, async (request, reply) => {
    const user = (request as any).user;
    
    try {
      const result = await db.query(
        `SELECT id, client_id, device, ip, ua, created_at, last_activity_at
         FROM sessions
         WHERE user_id = $1 AND revoked_at IS NULL
         ORDER BY last_activity_at DESC`,
        [user.sub]
      );

      return reply.send({
        sessions: result.rows,
        current_session_id: user['xjp.sid'],
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
      // Verify session belongs to user
      const sessionResult = await db.query(
        `SELECT * FROM sessions WHERE id = $1 AND user_id = $2`,
        [id, user.sub]
      );

      if (sessionResult.rows.length === 0) {
        return reply.code(404).send({ error: 'session_not_found' });
      }

      // Revoke session and associated refresh tokens
      await db.transaction(async (client) => {
        await client.query(
          `UPDATE sessions SET revoked_at = NOW() WHERE id = $1`,
          [id]
        );

        await client.query(
          `UPDATE refresh_tokens 
           SET revoked_at = NOW(), revoke_reason = 'session_revoked'
           WHERE session_id = $1 AND revoked_at IS NULL`,
          [id]
        );
      });

      // Audit log
      await db.query(
        `INSERT INTO audit_logs (actor, action, resource, status, ts)
         VALUES ($1, $2, $3, $4, NOW())`,
        [user.sub, 'session.revoke', `session:${id}`, 'success']
      );

      return reply.send({ success: true });
    } catch (error) {
      logger.error(error, 'Failed to revoke session');
      return reply.code(500).send({ error: 'internal_server_error' });
    }
  });

  // List users (admin only)
  fastify.get('/v1/users', { preHandler: authenticate }, async (request, reply) => {
    const user = (request as any).user;
    
    // Check admin role
    if (!user['xjp.roles']?.includes('admin')) {
      return reply.code(403).send({ error: 'forbidden' });
    }

    const querySchema = z.object({
      limit: z.coerce.number().min(1).max(100).default(20),
      offset: z.coerce.number().min(0).default(0),
      search: z.string().optional(),
    });

    try {
      const query = querySchema.parse(request.query);
      
      let whereClause = '';
      const values: any[] = [query.limit, query.offset];
      
      if (query.search) {
        whereClause = `WHERE display_name ILIKE $3 OR email ILIKE $3`;
        values.push(`%${query.search}%`);
      }

      const result = await db.query(
        `SELECT u.id, u.display_name, u.avatar_url, u.email, u.is_disabled,
                u.created_at, u.last_login_at,
                COUNT(DISTINCT i.id) as identity_count,
                COUNT(DISTINCT s.id) as active_sessions
         FROM users u
         LEFT JOIN identities i ON u.id = i.user_id
         LEFT JOIN sessions s ON u.id = s.user_id AND s.revoked_at IS NULL
         ${whereClause}
         GROUP BY u.id
         ORDER BY u.created_at DESC
         LIMIT $1 OFFSET $2`,
        values
      );

      const countResult = await db.query(
        `SELECT COUNT(*) FROM users ${whereClause}`,
        query.search ? [`%${query.search}%`] : []
      );

      return reply.send({
        users: result.rows,
        total: parseInt(countResult.rows[0].count),
        limit: query.limit,
        offset: query.offset,
      });
    } catch (error) {
      logger.error(error, 'Failed to list users');
      return reply.code(500).send({ error: 'internal_server_error' });
    }
  });

  // Disable/enable user (admin only)
  fastify.post('/v1/users/:id/disable', { preHandler: authenticate }, async (request, reply) => {
    const user = (request as any).user;
    const { id } = request.params as { id: string };
    
    // Check admin role
    if (!user['xjp.roles']?.includes('admin')) {
      return reply.code(403).send({ error: 'forbidden' });
    }

    const bodySchema = z.object({
      disabled: z.boolean(),
    });

    try {
      const body = bodySchema.parse(request.body);
      
      await db.query(
        `UPDATE users SET is_disabled = $1, updated_at = NOW() WHERE id = $2`,
        [body.disabled, id]
      );

      // Revoke all sessions if disabling
      if (body.disabled) {
        await db.query(
          `UPDATE sessions SET revoked_at = NOW() 
           WHERE user_id = $1 AND revoked_at IS NULL`,
          [id]
        );

        await db.query(
          `UPDATE refresh_tokens 
           SET revoked_at = NOW(), revoke_reason = 'user_disabled'
           WHERE user_id = $1 AND revoked_at IS NULL`,
          [id]
        );
      }

      // Audit log
      await db.query(
        `INSERT INTO audit_logs (actor, action, resource, status, ts, extra)
         VALUES ($1, $2, $3, $4, NOW(), $5)`,
        [
          user.sub,
          body.disabled ? 'user.disable' : 'user.enable',
          `user:${id}`,
          'success',
          JSON.stringify({ admin: user.sub }),
        ]
      );

      return reply.send({ success: true });
    } catch (error) {
      logger.error(error, 'Failed to update user status');
      return reply.code(500).send({ error: 'internal_server_error' });
    }
  });

  // Get audit logs
  fastify.get('/v1/audit', { preHandler: authenticate }, async (request, reply) => {
    const user = (request as any).user;
    
    // Check admin role or own logs
    const isAdmin = user['xjp.roles']?.includes('admin');
    
    const querySchema = z.object({
      limit: z.coerce.number().min(1).max(100).default(50),
      offset: z.coerce.number().min(0).default(0),
      actor: z.string().optional(),
      action: z.string().optional(),
      from: z.string().datetime().optional(),
      to: z.string().datetime().optional(),
    });

    try {
      const query = querySchema.parse(request.query);
      
      const conditions: string[] = [];
      const values: any[] = [];
      let paramCount = 1;

      // Non-admins can only see their own logs
      if (!isAdmin) {
        conditions.push(`actor = $${paramCount++}`);
        values.push(user.sub);
      } else if (query.actor) {
        conditions.push(`actor = $${paramCount++}`);
        values.push(query.actor);
      }

      if (query.action) {
        conditions.push(`action = $${paramCount++}`);
        values.push(query.action);
      }

      if (query.from) {
        conditions.push(`ts >= $${paramCount++}`);
        values.push(query.from);
      }

      if (query.to) {
        conditions.push(`ts <= $${paramCount++}`);
        values.push(query.to);
      }

      const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

      const result = await db.query(
        `SELECT * FROM audit_logs
         ${whereClause}
         ORDER BY ts DESC
         LIMIT $${paramCount} OFFSET $${paramCount + 1}`,
        [...values, query.limit, query.offset]
      );

      return reply.send({
        logs: result.rows,
        limit: query.limit,
        offset: query.offset,
      });
    } catch (error) {
      logger.error(error, 'Failed to get audit logs');
      return reply.code(500).send({ error: 'internal_server_error' });
    }
  });
}