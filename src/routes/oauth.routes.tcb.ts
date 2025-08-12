import { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { jwtServiceTCB } from '../services/jwt.service.tcb.js';
import { logger } from '../utils/logger.js';

export async function oauthRoutesTCB(fastify: FastifyInstance) {
  // JWKS endpoint
  fastify.get('/.well-known/jwks.json', async (request, reply) => {
    try {
      const jwks = await jwtServiceTCB.getJWKS();
      
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

  // OpenID Configuration
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