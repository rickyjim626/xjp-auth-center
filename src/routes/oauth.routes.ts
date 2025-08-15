import { FastifyPluginAsync } from 'fastify';
import { z } from 'zod';
import { getConfig } from '../config/auth-config.js';
import { getRepos } from '../repos/index.js';
import { getRedisManager } from '../infra/redis.js';
import { logger } from '../utils/logger.js';
import crypto from 'crypto';
import * as jose from 'jose';

// PKCE verification
function verifyPKCE(verifier: string, challenge: string, method: string = 'S256'): boolean {
  if (method === 'S256') {
    const hash = crypto.createHash('sha256').update(verifier).digest('base64url');
    return hash === challenge;
  }
  return verifier === challenge;
}

// Generate authorization code
function generateAuthCode(): string {
  return crypto.randomBytes(32).toString('base64url');
}

export const oauthRoutes: FastifyPluginAsync = async (fastify) => {
  const config = await getConfig();
  const repos = getRepos();
  const redis = getRedisManager();

  // OIDC Discovery Endpoint
  fastify.get('/.well-known/openid-configuration', async (request, reply) => {
    const issuer = config.jwt.issuer;
    
    return reply.send({
      issuer,
      authorization_endpoint: `${issuer}/oauth2/authorize`,
      token_endpoint: `${issuer}/oauth2/token`,
      userinfo_endpoint: `${issuer}/userinfo`,
      jwks_uri: `${issuer}/.well-known/jwks.json`,
      response_types_supported: ['code'],
      subject_types_supported: ['public'],
      id_token_signing_alg_values_supported: ['RS256'],
      scopes_supported: ['openid', 'profile', 'email', 'offline_access'],
      token_endpoint_auth_methods_supported: ['client_secret_post', 'none'],
      claims_supported: [
        'sub', 'iss', 'aud', 'exp', 'iat', 'nbf', 'jti',
        'name', 'nickname', 'picture', 'email', 'email_verified'
      ],
      code_challenge_methods_supported: ['S256', 'plain'],
      grant_types_supported: ['authorization_code', 'refresh_token'],
    });
  });

  // JWKS Endpoint - 统一实现，移除重复
  fastify.get('/.well-known/jwks.json', async (request, reply) => {
    try {
      const publicKeys = await repos.jwk.listPublicKeys();
      
      const keys = publicKeys.map(key => {
        // Convert PEM to JWK format for RS256
        // This is a simplified implementation - in production you'd want proper PEM parsing
        return {
          kid: key.key_id,
          kty: key.key_type,
          alg: key.algorithm,
          use: 'sig',
          // Note: In a real implementation, you'd properly parse the PEM and extract n, e for RSA
          // For now, we'll return the key info we have
        };
      });

      return reply
        .header('Cache-Control', 'public, max-age=300') // Cache for 5 minutes
        .send({ keys });
    } catch (error) {
      logger.error(error, 'Failed to get JWKS');
      return reply.status(500).send({
        error: 'internal_server_error',
        message: 'Failed to retrieve JWKS',
      });
    }
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
      
      // Validate client
      const client = await repos.oauth.findClientById(params.client_id);
      if (!client || client.is_disabled) {
        return reply.redirect(
          `${params.redirect_uri}?error=invalid_client&error_description=Client+not+found&state=${params.state || ''}`
        );
      }

      // Validate redirect URI
      const isValidRedirect = client.redirect_uris.some(uri => {
        if (uri.includes('*')) {
          const pattern = uri.replace(/\*/g, '.*');
          return new RegExp(`^${pattern}$`).test(params.redirect_uri);
        }
        return uri === params.redirect_uri;
      });

      if (!isValidRedirect) {
        return reply.status(400).send({
          error: 'invalid_redirect_uri',
          error_description: 'Redirect URI not allowed for this client',
        });
      }

      // Check PKCE requirement
      if (config.oidc.requirePKCE && !params.code_challenge) {
        return reply.redirect(
          `${params.redirect_uri}?error=invalid_request&error_description=PKCE+required&state=${params.state || ''}`
        );
      }

      // Check for existing session (simplified - in real implementation you'd check JWT cookie)
      const sessionId = request.cookies['auth_session'];
      let userId: number | null = null;

      if (sessionId) {
        // Try to get user from session (simplified)
        const sessionData = await redis.getLoginState(sessionId);
        if (sessionData && sessionData.userId) {
          userId = sessionData.userId;
        }
      }

      if (!userId) {
        // No valid session, redirect to WeChat login
        const loginId = crypto.randomBytes(16).toString('hex');
        
        // Store authorization request
        await redis.setLoginState(loginId, {
          authRequest: params,
          createdAt: new Date(),
        }, 600); // 10 minutes

        // Build WeChat OAuth URL based on User-Agent
        const isWechatUA = /MicroMessenger/i.test(request.headers['user-agent'] || '');
        const callbackUrl = `${config.jwt.issuer}/auth/wechat/callback`;
        const wxState = Buffer.from(JSON.stringify({
          loginId,
          clientId: params.client_id,
          redirectUri: params.redirect_uri,
          state: params.state,
        })).toString('base64url');

        let wxAuthUrl: URL;
        if (isWechatUA) {
          // WeChat MP OAuth
          wxAuthUrl = new URL('https://open.weixin.qq.com/connect/oauth2/authorize');
          wxAuthUrl.searchParams.set('appid', config.wechat.mpAppId);
          wxAuthUrl.searchParams.set('redirect_uri', callbackUrl);
          wxAuthUrl.searchParams.set('response_type', 'code');
          wxAuthUrl.searchParams.set('scope', 'snsapi_userinfo');
          wxAuthUrl.searchParams.set('state', wxState);
          wxAuthUrl.hash = 'wechat_redirect';
        } else {
          // WeChat Open Platform OAuth
          wxAuthUrl = new URL('https://open.weixin.qq.com/connect/qrconnect');
          wxAuthUrl.searchParams.set('appid', config.wechat.openAppId);
          wxAuthUrl.searchParams.set('redirect_uri', callbackUrl);
          wxAuthUrl.searchParams.set('response_type', 'code');
          wxAuthUrl.searchParams.set('scope', 'snsapi_login');
          wxAuthUrl.searchParams.set('state', wxState);
          wxAuthUrl.hash = 'wechat_redirect';
        }

        return reply.redirect(wxAuthUrl.toString());
      }

      // User is authenticated, generate authorization code
      const code = generateAuthCode();
      const expiresAt = new Date(Date.now() + config.oidc.authCodeExpires * 1000);

      await repos.oauth.createAuthCode({
        code,
        client_id: params.client_id,
        user_id: userId,
        redirect_uri: params.redirect_uri,
        scopes: params.scope.split(' '),
        code_challenge: params.code_challenge,
        code_challenge_method: params.code_challenge_method,
        expires_at: expiresAt,
      });

      // Redirect back to client
      const redirectUrl = new URL(params.redirect_uri);
      redirectUrl.searchParams.set('code', code);
      if (params.state) {
        redirectUrl.searchParams.set('state', params.state);
      }

      return reply.redirect(redirectUrl.toString());
    } catch (error) {
      logger.error({ error }, 'Authorization error');
      return reply.status(400).send({
        error: 'invalid_request',
        error_description: 'Invalid authorization request',
      });
    }
  });

  // Token Endpoint - 统一实现
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
        if (!params.code) {
          return reply.status(400).send({
            error: 'invalid_request',
            error_description: 'Authorization code is required',
          });
        }

        // Validate authorization code
        const authCode = await repos.oauth.findAuthCode(params.code);
        if (!authCode) {
          return reply.status(400).send({
            error: 'invalid_grant',
            error_description: 'Invalid authorization code',
          });
        }

        // Check expiration
        if (authCode.expires_at.getTime() < Date.now()) {
          await repos.oauth.deleteAuthCode(params.code);
          return reply.status(400).send({
            error: 'invalid_grant',
            error_description: 'Authorization code expired',
          });
        }

        // Validate client
        if (authCode.client_id !== params.client_id) {
          return reply.status(400).send({
            error: 'invalid_client',
            error_description: 'Client mismatch',
          });
        }

        // Validate redirect URI
        if (authCode.redirect_uri !== params.redirect_uri) {
          return reply.status(400).send({
            error: 'invalid_grant',
            error_description: 'Redirect URI mismatch',
          });
        }

        // Validate PKCE
        if (authCode.code_challenge) {
          if (!params.code_verifier) {
            return reply.status(400).send({
              error: 'invalid_grant',
              error_description: 'PKCE verifier required',
            });
          }

          const valid = verifyPKCE(
            params.code_verifier,
            authCode.code_challenge,
            authCode.code_challenge_method || 'S256'
          );

          if (!valid) {
            return reply.status(400).send({
              error: 'invalid_grant',
              error_description: 'PKCE verification failed',
            });
          }
        }

        // Mark code as used
        await repos.oauth.markAuthCodeAsUsed(params.code);

        // Generate tokens (simplified - in real implementation you'd use JWT service)
        const sessionId = crypto.randomBytes(16).toString('hex');
        const accessTokenJti = crypto.randomBytes(16).toString('hex');
        const refreshTokenJti = crypto.randomBytes(16).toString('hex');

        const accessTokenExpires = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes
        const refreshTokenExpires = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000); // 30 days

        // Store tokens in database
        await repos.oauth.createToken({
          jti: accessTokenJti,
          user_id: authCode.user_id,
          client_id: authCode.client_id,
          session_id: sessionId,
          token_type: 'access_token',
          scopes: authCode.scopes,
          refresh_token_jti: refreshTokenJti,
          expires_at: accessTokenExpires,
        });

        await repos.oauth.createToken({
          jti: refreshTokenJti,
          user_id: authCode.user_id,
          client_id: authCode.client_id,
          session_id: sessionId,
          token_type: 'refresh_token',
          scopes: authCode.scopes,
          expires_at: refreshTokenExpires,
        });

        return reply.send({
          access_token: `at_${accessTokenJti}`, // Simplified token format
          token_type: 'Bearer',
          expires_in: 900, // 15 minutes
          refresh_token: `rt_${refreshTokenJti}`,
          scope: authCode.scopes.join(' '),
        });
      }

      if (params.grant_type === 'refresh_token') {
        // Implement refresh token logic
        return reply.status(400).send({
          error: 'unsupported_grant_type',
          error_description: 'Refresh token flow not yet implemented',
        });
      }

      return reply.status(400).send({
        error: 'unsupported_grant_type',
        error_description: 'Grant type not supported',
      });
    } catch (error) {
      logger.error({ error }, 'Token error');
      return reply.status(400).send({
        error: 'invalid_request',
        error_description: 'Invalid token request',
      });
    }
  });

  // Legacy OAuth endpoint redirects
  fastify.get('/oauth/token', async (request, reply) => {
    return reply.redirect(301, '/oauth2/token');
  });

  fastify.post('/oauth/token', async (request, reply) => {
    return reply.redirect(307, '/oauth2/token'); // Preserve POST method
  });
};