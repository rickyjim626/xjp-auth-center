import { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { oauthService } from '../services/oauth.service.js';
import { jwtService } from '../services/jwt.service.js';
import { logger } from '../utils/logger.js';

const tokenSchema = z.object({
  grant_type: z.enum(['authorization_code', 'refresh_token']),
  code: z.string().optional(),
  refresh_token: z.string().optional(),
  client_id: z.string(),
  client_secret: z.string().optional(),
  redirect_uri: z.string().optional(),
  code_verifier: z.string().optional(),
});

const revokeSchema = z.object({
  token: z.string(),
  token_type_hint: z.enum(['access_token', 'refresh_token']).optional(),
});

export async function oauthRoutes(fastify: FastifyInstance) {
  // Token endpoint
  fastify.post('/oauth/token', async (request, reply) => {
    try {
      const body = tokenSchema.parse(request.body);
      
      const result = await oauthService.exchangeToken(body);
      
      return reply.send(result);
    } catch (error) {
      logger.error(error, 'Token exchange failed');
      
      const errorMessage = error instanceof Error ? error.message : 'Invalid request';
      const errorCode = errorMessage.includes('expired') ? 'invalid_grant' :
                       errorMessage.includes('mismatch') ? 'invalid_request' :
                       errorMessage.includes('reuse') ? 'invalid_grant' :
                       'invalid_request';
      
      return reply.code(400).send({
        error: errorCode,
        error_description: errorMessage,
      });
    }
  });

  // Token revocation
  fastify.post('/oauth/revoke', async (request, reply) => {
    try {
      const body = revokeSchema.parse(request.body);
      
      await oauthService.revokeToken(body.token);
      
      return reply.code(200).send();
    } catch (error) {
      logger.error(error, 'Token revocation failed');
      // Revocation should always return 200 per RFC 7009
      return reply.code(200).send();
    }
  });

  // JWKS endpoint
  fastify.get('/.well-known/jwks.json', async (request, reply) => {
    try {
      const jwks = await jwtService.getJWKS();
      
      return reply
        .header('Cache-Control', 'public, max-age=300') // Cache for 5 minutes
        .send(jwks);
    } catch (error) {
      logger.error(error, 'Failed to get JWKS');
      return reply.code(500).send({
        error: 'internal_server_error',
        message: 'Failed to retrieve JWKS',
      });
    }
  });

  // OpenID Configuration (optional but useful)
  fastify.get('/.well-known/openid-configuration', async (request, reply) => {
    const baseUrl = `${request.protocol}://${request.hostname}`;
    
    return reply
      .header('Cache-Control', 'public, max-age=3600') // Cache for 1 hour
      .send({
        issuer: baseUrl,
        authorization_endpoint: `${baseUrl}/oauth/authorize`,
        token_endpoint: `${baseUrl}/oauth/token`,
        revocation_endpoint: `${baseUrl}/oauth/revoke`,
        jwks_uri: `${baseUrl}/.well-known/jwks.json`,
        response_types_supported: ['code'],
        grant_types_supported: ['authorization_code', 'refresh_token'],
        subject_types_supported: ['public'],
        id_token_signing_alg_values_supported: ['EdDSA', 'ES256'],
        scopes_supported: ['openid', 'profile', 'email', 'offline_access'],
        token_endpoint_auth_methods_supported: ['client_secret_post', 'none'],
        claims_supported: [
          'sub', 'iss', 'aud', 'exp', 'iat', 'nbf', 'jti',
          'xjp.uid', 'xjp.roles', 'xjp.scopes', 'xjp.wechat.unionid', 'xjp.wechat.openid',
        ],
        code_challenge_methods_supported: ['S256', 'plain'],
      });
  });
}