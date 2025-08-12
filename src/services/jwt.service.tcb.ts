import * as jose from 'jose';
import * as ed from '@noble/ed25519';
import { getConfig } from '../config/auth-config.js';
import { logger } from '../utils/logger.js';
import { generateRandomId } from '../utils/crypto.js';
import { TCBDatabase, findOne, insertOne, findMany } from '../db/tcb-client.js';

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

export class JWTServiceTCB {
  private static instance: JWTServiceTCB;
  private currentKid: string | null = null;
  private privateKey: Uint8Array | null = null;
  private publicKey: Uint8Array | null = null;
  private configLoaded: boolean = false;

  private constructor() {}

  static getInstance(): JWTServiceTCB {
    if (!JWTServiceTCB.instance) {
      JWTServiceTCB.instance = new JWTServiceTCB();
    }
    return JWTServiceTCB.instance;
  }

  async initialize(): Promise<void> {
    await this.ensureKeyPair();
  }

  private async ensureKeyPair(): Promise<void> {
    try {
      const config = await getConfig();

      // First try to load from Secret Store config
      if (config.jwt.privateKey && config.jwt.publicJwks) {
        await this.loadFromConfig(config);
        return;
      }

      // Otherwise check database for existing keys
      const activeKey = await findOne('jwk_keys', {
        disabledAt: null,
      });

      if (activeKey && activeKey.privateJwk?.d) {
        this.currentKid = activeKey.kid;
        this.privateKey = jose.base64url.decode(activeKey.privateJwk.d);
        this.publicKey = jose.base64url.decode(activeKey.privateJwk.x);
        logger.info({ kid: this.currentKid }, 'Loaded existing JWK key pair from database');
      } else {
        await this.generateNewKeyPair();
      }

      this.configLoaded = true;
    } catch (error) {
      logger.error(error, 'Failed to load JWK keys, generating new pair');
      await this.generateNewKeyPair();
    }
  }

  private async loadFromConfig(config: any): Promise<void> {
    try {
      // Parse private key from PEM or JWK format
      const privateKeyData = config.jwt.privateKey;
      
      if (privateKeyData.startsWith('-----BEGIN')) {
        // PEM format - need to extract the key
        const keyData = privateKeyData
          .replace(/-----BEGIN PRIVATE KEY-----/, '')
          .replace(/-----END PRIVATE KEY-----/, '')
          .replace(/\s/g, '');
        
        const decoded = jose.base64url.decode(keyData);
        // For Ed25519, the private key is the last 32 bytes
        this.privateKey = decoded.slice(-32);
        this.publicKey = await ed.getPublicKeyAsync(this.privateKey);
      } else {
        // Assume base64 encoded raw key
        this.privateKey = jose.base64url.decode(privateKeyData);
        this.publicKey = await ed.getPublicKeyAsync(this.privateKey);
      }

      // Get kid from JWKS
      const jwks = config.jwt.publicJwks;
      if (jwks && jwks.keys && jwks.keys.length > 0) {
        this.currentKid = jwks.keys[0].kid || 'xiaojinpro-auth-2025';
      } else {
        this.currentKid = 'xiaojinpro-auth-2025';
      }

      logger.info({ kid: this.currentKid }, 'Loaded JWK key pair from Secret Store config');
      this.configLoaded = true;
    } catch (error) {
      logger.error(error, 'Failed to load keys from config');
      throw error;
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
    await insertOne('jwk_keys', {
      kid: this.currentKid,
      alg: 'EdDSA',
      use: 'sig',
      publicJwk,
      privateJwk,
      createdAt: new Date(),
      disabledAt: null,
    });

    logger.info({ kid: this.currentKid }, 'Generated new Ed25519 key pair');
    this.configLoaded = true;
  }

  async signAccessToken(payload: TokenPayload): Promise<string> {
    if (!this.configLoaded) {
      await this.ensureKeyPair();
    }

    const config = await getConfig();
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
    if (!this.configLoaded) {
      await this.ensureKeyPair();
    }

    const config = await getConfig();
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
    const config = await getConfig();
    const jwks = await this.getJWKS();
    const JWKS = jose.createLocalJWKSet(jwks);
    
    return jose.jwtVerify(token, JWKS, {
      issuer: config.jwt.issuer,
      clockTolerance: 5,
    });
  }

  async getJWKS(): Promise<{ keys: JWK[] }> {
    const config = await getConfig();

    // If we have JWKS from config, use that
    if (config.jwt.publicJwks) {
      return config.jwt.publicJwks;
    }

    // Otherwise get from database
    const db = TCBDatabase.getInstance();
    const now = new Date();
    const dayAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000);

    const keys = await findMany('jwk_keys', {
      $or: [
        { disabledAt: null },
        { disabledAt: db._.gt(dayAgo) },
      ],
    }, {
      orderBy: { field: 'createdAt', order: 'desc' },
    });

    return {
      keys: keys.map(k => k.publicJwk),
    };
  }

  private async getSigningKey(): Promise<KeyLike> {
    if (!this.privateKey || !this.publicKey) {
      throw new Error('Private key not initialized');
    }

    const privateJwk = {
      kty: 'OKP',
      crv: 'Ed25519',
      x: jose.base64url.encode(this.publicKey),
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
    const db = TCBDatabase.getInstance();
    
    // Disable current key (keep for verification for 24h)
    if (this.currentKid) {
      const futureDate = new Date(Date.now() + 24 * 60 * 60 * 1000);
      await db.collection('jwk_keys')
        .where({ kid: this.currentKid })
        .update({ disabledAt: futureDate });
    }

    // Generate new key pair
    await this.generateNewKeyPair();
  }
}

// Type definition for jose
type KeyLike = Parameters<typeof jose.SignJWT.prototype.sign>[0];

export const jwtServiceTCB = JWTServiceTCB.getInstance();