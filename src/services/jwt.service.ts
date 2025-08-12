import * as jose from 'jose';
import * as ed from '@noble/ed25519';
import { db } from '../db/client.js';
import { config } from '../config/index.js';
import { logger } from '../utils/logger.js';
import { generateRandomId } from '../utils/crypto.js';

interface TokenPayload {
  userId: string;
  unionid?: string;
  openid?: string;
  roles?: string[];
  scopes?: string[];
  clientId?: string;
  sessionId?: string;
}

interface JWK {
  kid: string;
  kty: string;
  alg: string;
  use: string;
  crv?: string;
  x?: string;
  d?: string;
}

export class JWTService {
  private static instance: JWTService;
  private currentKid: string | null = null;
  private privateKey: Uint8Array | null = null;
  private publicKey: Uint8Array | null = null;

  private constructor() {}

  static getInstance(): JWTService {
    if (!JWTService.instance) {
      JWTService.instance = new JWTService();
    }
    return JWTService.instance;
  }

  async initialize(): Promise<void> {
    await this.ensureKeyPair();
  }

  private async ensureKeyPair(): Promise<void> {
    try {
      // Check for existing active key
      const result = await db.query<{ kid: string; private_jwk: any }>(
        'SELECT kid, private_jwk FROM jwk_keys WHERE disabled_at IS NULL ORDER BY created_at DESC LIMIT 1'
      );

      if (result.rows.length > 0) {
        const key = result.rows[0];
        this.currentKid = key.kid;
        
        if (key.private_jwk && key.private_jwk.d) {
          this.privateKey = jose.base64url.decode(key.private_jwk.d);
          this.publicKey = jose.base64url.decode(key.private_jwk.x);
        }
        logger.info({ kid: this.currentKid }, 'Loaded existing JWK key pair');
      } else {
        await this.generateNewKeyPair();
      }
    } catch (error) {
      logger.error(error, 'Failed to load JWK keys, generating new pair');
      await this.generateNewKeyPair();
    }
  }

  private async generateNewKeyPair(): Promise<void> {
    // Generate Ed25519 key pair
    this.privateKey = ed.utils.randomPrivateKey();
    this.publicKey = await ed.getPublicKeyAsync(this.privateKey);
    this.currentKid = `key_${generateRandomId(16)}`;

    const publicJwk = {
      kty: 'OKP',
      crv: 'Ed25519',
      x: jose.base64url.encode(this.publicKey),
      use: 'sig',
      alg: 'EdDSA',
      kid: this.currentKid,
    };

    const privateJwk = {
      ...publicJwk,
      d: jose.base64url.encode(this.privateKey),
    };

    // Store in database
    await db.query(
      `INSERT INTO jwk_keys (kid, alg, use, public_jwk, private_jwk) 
       VALUES ($1, $2, $3, $4, $5)`,
      [this.currentKid, 'EdDSA', 'sig', publicJwk, privateJwk]
    );

    logger.info({ kid: this.currentKid }, 'Generated new Ed25519 key pair');
  }

  async signAccessToken(payload: TokenPayload): Promise<string> {
    if (!this.privateKey || !this.currentKid) {
      await this.ensureKeyPair();
    }

    const now = Math.floor(Date.now() / 1000);
    const exp = now + this.parseExpiry(config.jwt.accessTokenExpires);

    const claims = {
      iss: config.jwt.issuer,
      sub: payload.userId,
      aud: payload.clientId || 'xiaojinpro',
      exp,
      iat: now,
      nbf: now,
      jti: generateRandomId(16),
      'xjp.uid': payload.userId,
      'xjp.roles': payload.roles || [],
      'xjp.scopes': payload.scopes || [],
      ...(payload.unionid && { 'xjp.wechat.unionid': payload.unionid }),
      ...(payload.openid && { 'xjp.wechat.openid': payload.openid }),
      ...(payload.sessionId && { 'xjp.sid': payload.sessionId }),
    };

    const jwt = await new jose.SignJWT(claims)
      .setProtectedHeader({ alg: 'EdDSA', kid: this.currentKid! })
      .sign(await this.getSigningKey());

    return jwt;
  }

  async signRefreshToken(payload: TokenPayload): Promise<{ token: string; jti: string }> {
    if (!this.privateKey || !this.currentKid) {
      await this.ensureKeyPair();
    }

    const now = Math.floor(Date.now() / 1000);
    const exp = now + this.parseExpiry(config.jwt.refreshTokenExpires);
    const jti = `jti_${generateRandomId(24)}`;

    const claims = {
      iss: config.jwt.issuer,
      sub: payload.userId,
      aud: payload.clientId || 'xiaojinpro',
      exp,
      iat: now,
      nbf: now,
      jti,
      type: 'refresh',
      ...(payload.sessionId && { sid: payload.sessionId }),
    };

    const jwt = await new jose.SignJWT(claims)
      .setProtectedHeader({ alg: 'EdDSA', kid: this.currentKid! })
      .sign(await this.getSigningKey());

    return { token: jwt, jti };
  }

  async verifyToken(token: string): Promise<jose.JWTVerifyResult> {
    const jwks = await this.getJWKS();
    const JWKS = jose.createLocalJWKSet(jwks);
    
    return jose.jwtVerify(token, JWKS, {
      issuer: config.jwt.issuer,
      clockTolerance: 5,
    });
  }

  async getJWKS(): Promise<{ keys: JWK[] }> {
    const result = await db.query<{ public_jwk: any }>(
      `SELECT public_jwk FROM jwk_keys 
       WHERE disabled_at IS NULL 
          OR disabled_at > NOW() - INTERVAL '24 hours'
       ORDER BY created_at DESC`
    );

    const keys = result.rows.map(row => row.public_jwk);
    return { keys };
  }

  private async getSigningKey(): Promise<KeyLike> {
    if (!this.privateKey) {
      throw new Error('Private key not initialized');
    }

    const privateJwk = {
      kty: 'OKP',
      crv: 'Ed25519',
      x: jose.base64url.encode(this.publicKey!),
      d: jose.base64url.encode(this.privateKey),
      use: 'sig',
      alg: 'EdDSA',
      kid: this.currentKid!,
    };

    return jose.importJWK(privateJwk, 'EdDSA');
  }

  private parseExpiry(expiry: string): number {
    const match = expiry.match(/^(\d+)([smhd])$/);
    if (!match) {
      throw new Error(`Invalid expiry format: ${expiry}`);
    }

    const value = parseInt(match[1]);
    const unit = match[2];

    switch (unit) {
      case 's':
        return value;
      case 'm':
        return value * 60;
      case 'h':
        return value * 60 * 60;
      case 'd':
        return value * 60 * 60 * 24;
      default:
        throw new Error(`Invalid expiry unit: ${unit}`);
    }
  }

  async rotateKeys(): Promise<void> {
    // Disable current key (keep for verification for 24h)
    if (this.currentKid) {
      await db.query(
        'UPDATE jwk_keys SET disabled_at = NOW() + INTERVAL \'24 hours\' WHERE kid = $1',
        [this.currentKid]
      );
    }

    // Generate new key pair
    await this.generateNewKeyPair();
  }
}

// Type definition for jose
type KeyLike = Parameters<typeof jose.SignJWT.prototype.sign>[0];

export const jwtService = JWTService.getInstance();