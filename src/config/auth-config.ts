import { z } from 'zod';
import { secretStoreClient } from '../services/secret-store.client.js';
import { logger } from '../utils/logger.js';
import dotenv from 'dotenv';

// Load environment-specific .env file
const env = process.env.NODE_ENV || process.env.ENV || 'development';
if (env === 'production') {
  dotenv.config({ path: '.env.production' });
} else {
  dotenv.config();
}

const authConfigSchema = z.object({
  env: z.enum(['development', 'staging', 'production']).default('development'),
  server: z.object({
    port: z.number().default(3000),
    host: z.string().default('0.0.0.0'),
  }),
  database: z.object({
    provider: z.enum(['tcb', 'mysql']).default('mysql'),
    url: z.string().optional(), // MySQL connection string
    migrateOnStartup: z.boolean().default(false),
  }),
  tcb: z.object({
    envId: z.string(),
    secretId: z.string(),
    secretKey: z.string(),
    sessionToken: z.string().optional(),
    region: z.string().default('ap-shanghai'),
  }),
  redis: z.object({
    enabled: z.boolean().default(false),
    url: z.string().optional(),
  }),
  wechat: z.object({
    // 开放平台网站应用（PC扫码登录）
    openAppId: z.string(),
    openAppSecret: z.string(),
    // 公众号（微信内H5）
    mpAppId: z.string(),
    mpAppSecret: z.string(),
    // 统一回调域名
    redirectUri: z.string(),
    // UnionID支持
    useUnionId: z.boolean().default(true),
  }),
  jwt: z.object({
    issuer: z.string(),
    algorithm: z.literal('RS256').default('RS256'), // 锁定算法
    kid: z.string().default('kid-2025-01'),
    privateKey: z.string(),
    privateKeyB64: z.string().optional(), // Base64 编码的私钥
    publicKey: z.string().optional(),
    publicJwks: z.any().optional(),
    accessTokenExpires: z.string().default('15m'),
    refreshTokenExpires: z.string().default('30d'),
    idTokenExpires: z.string().default('1h'),
  }),
  oidc: z.object({
    // PKCE配置
    requirePKCE: z.boolean().default(true),
    // 授权码过期时间（秒）
    authCodeExpires: z.number().default(600),
  }),
  cookie: z.object({
    secret: z.string(),
    secure: z.boolean().default(true),
    sameSite: z.enum(['strict', 'lax', 'none']).default('lax'),
    sessionExpires: z.number().default(86400000), // 24小时
  }),
  security: z.object({
    corsOrigin: z.array(z.string()),
    rateLimitMax: z.number().default(100),
    rateLimitWindow: z.number().default(60000),
    csrfProtection: z.boolean().default(true),
  }),
  secretStore: z.object({
    useSecretStore: z.boolean().default(false),
    url: z.string().optional(),
    apiKey: z.string().optional(),
  }),
});

export type AuthConfig = z.infer<typeof authConfigSchema>;

class ConfigLoader {
  private static instance: ConfigLoader;
  private config: AuthConfig | null = null;
  private loadPromise: Promise<AuthConfig> | null = null;

  private constructor() {}

  static getInstance(): ConfigLoader {
    if (!ConfigLoader.instance) {
      ConfigLoader.instance = new ConfigLoader();
    }
    return ConfigLoader.instance;
  }

  async load(): Promise<AuthConfig> {
    // If already loading, wait for that to complete
    if (this.loadPromise) {
      return this.loadPromise;
    }

    // If already loaded, return cached config
    if (this.config) {
      return this.config;
    }

    // Start loading
    this.loadPromise = this.loadConfig();
    this.config = await this.loadPromise;
    this.loadPromise = null;

    return this.config;
  }

  private async loadConfig(): Promise<AuthConfig> {
    const isDev = process.env.ENV === 'development';
    const useSecretStore = process.env.USE_SECRET_STORE === 'true' || !isDev;

    let rawConfig: any;

    if (useSecretStore && process.env.XJP_KEY_AUTH) {
      logger.info('Loading configuration from Secret Store...');
      rawConfig = await this.loadFromSecretStore();
    } else {
      logger.info('Loading configuration from environment variables...');
      rawConfig = this.loadFromEnv();
    }

    try {
      const config = authConfigSchema.parse(rawConfig);
      logger.info({ env: config.env }, 'Configuration loaded successfully');
      return config;
    } catch (error) {
      logger.error(error, 'Invalid configuration');
      throw new Error('Failed to load valid configuration');
    }
  }

  private async loadFromSecretStore(): Promise<any> {
    try {
      // Load all configs from prod/auth namespace
      const { secrets, configs } = await secretStoreClient.getNamespaceConfig('prod/auth');

      // Parse CORS origins
      const corsOrigin = configs.CORS_ORIGINS 
        ? configs.CORS_ORIGINS.split(',').map(s => s.trim())
        : ['https://xiaojinpro.com', 'https://*.xiaojinpro.com'];

      // Parse JWT public JWKS if present
      let publicJwks;
      try {
        publicJwks = configs.JWT_PUBLIC_JWKS ? JSON.parse(configs.JWT_PUBLIC_JWKS) : undefined;
      } catch {
        publicJwks = undefined;
      }

      return {
        env: process.env.ENV || configs.ENV || 'production',
        server: {
          port: parseInt(process.env.PORT || '3000'),
          host: process.env.HOST || '0.0.0.0',
        },
        tcb: {
          envId: configs.TCB_ENV_ID || configs.TCB_ENV_NAME,
          secretId: secrets.TENCENTCLOUD_SECRETID,
          secretKey: secrets.TENCENTCLOUD_SECRETKEY,
          sessionToken: secrets.TENCENTCLOUD_SESSIONTOKEN,
          region: configs.TCB_REGION || 'ap-shanghai',
        },
        wechat: {
          openAppId: secrets.WECHAT_OPEN_APPID,
          openAppSecret: secrets.WECHAT_OPEN_SECRET,
          mpAppId: secrets.WECHAT_MP_APPID,
          mpAppSecret: secrets.WECHAT_MP_SECRET,
          redirectUri: configs.WECHAT_REDIRECT_URI || 'https://auth.xiaojinpro.com/wechat/callback',
          useUnionId: configs.USE_UNIONID !== 'false',
        },
        jwt: {
          issuer: configs.ISSUER || 'https://auth.xiaojinpro.com',
          kid: configs.JWT_KID || 'kid-2025-01',
          privateKey: secrets.JWT_PRIVATE_KEY?.replace(/\\n/g, '\n'),
          publicKey: secrets.JWT_PUBLIC_KEY?.replace(/\\n/g, '\n'),
          publicJwks: publicJwks,
          accessTokenExpires: configs.JWT_ACCESS_TOKEN_EXPIRES || '15m',
          refreshTokenExpires: configs.JWT_REFRESH_TOKEN_EXPIRES || '30d',
          idTokenExpires: configs.JWT_ID_TOKEN_EXPIRES || '1h',
        },
        oidc: {
          requirePKCE: configs.REQUIRE_PKCE !== 'false',
          authCodeExpires: parseInt(configs.AUTH_CODE_EXPIRES || '600'),
        },
        cookie: {
          secret: secrets.COOKIE_SECRET || configs.COOKIE_SECRET,
          secure: configs.COOKIE_SECURE !== 'false',
          sameSite: (configs.COOKIE_SAME_SITE as 'strict' | 'lax' | 'none') || 'lax',
          sessionExpires: parseInt(configs.SESSION_EXPIRES || '86400000'),
        },
        security: {
          corsOrigin,
          rateLimitMax: parseInt(configs.RATE_LIMIT_MAX || '100'),
          rateLimitWindow: parseInt(configs.RATE_LIMIT_WINDOW || '60000'),
          csrfProtection: configs.CSRF_PROTECTION !== 'false',
        },
        secretStore: {
          useSecretStore: true,
          url: process.env.SECRET_STORE_URL || 'https://yzuukzffofsw.sg-members-1.clawcloudrun.com',
          apiKey: process.env.XJP_KEY_AUTH || '',
        },
      };
    } catch (error) {
      logger.error(error, 'Failed to load config from Secret Store');
      throw error;
    }
  }

  private loadFromEnv(): any {
    const corsOrigin = process.env.CORS_ORIGIN 
      ? process.env.CORS_ORIGIN.split(',').map(s => s.trim())
      : ['http://localhost:3000', 'http://localhost:3001'];

    return {
      env: process.env.NODE_ENV || process.env.ENV || 'development',
      server: {
        port: parseInt(process.env.PORT || '3000'),
        host: process.env.HOST || '0.0.0.0',
      },
      database: {
        provider: (process.env.DB_TYPE === 'mysql' || process.env.DB_URL) ? 'mysql' : 'tcb',
        url: process.env.DB_URL,
        migrateOnStartup: process.env.MIGRATE_ON_STARTUP === 'true',
      },
      tcb: {
        envId: process.env.TCB_ENV_ID || 'xiaojinpro-5ghvhq9v9875c1ea',
        secretId: process.env.TENCENTCLOUD_SECRETID || '',
        secretKey: process.env.TENCENTCLOUD_SECRETKEY || '',
        sessionToken: process.env.TENCENTCLOUD_SESSIONTOKEN,
        region: process.env.TCB_REGION || 'ap-shanghai',
      },
      redis: {
        enabled: process.env.REDIS_ENABLED === 'true',
        url: process.env.REDIS_URL,
      },
      wechat: {
        openAppId: process.env.WECHAT_OPEN_APPID || process.env.WECHAT_WEB_APPID || '',
        openAppSecret: process.env.WECHAT_OPEN_SECRET || process.env.WECHAT_WEB_APPSECRET || '',
        mpAppId: process.env.WECHAT_MP_APPID || '',
        mpAppSecret: process.env.WECHAT_MP_SECRET || '',
        redirectUri: process.env.WECHAT_REDIRECT_URI || 'https://auth.xiaojinpro.com/wechat/callback',
        useUnionId: process.env.USE_UNIONID !== 'false',
      },
      jwt: {
        issuer: process.env.ISSUER || 'https://auth.xiaojinpro.com',
        algorithm: 'RS256' as const,
        kid: process.env.JWT_KID || 'kid-2025-01',
        privateKey: process.env.JWT_PRIVATE_KEY_B64 
          ? Buffer.from(process.env.JWT_PRIVATE_KEY_B64, 'base64').toString('utf-8')
          : process.env.JWT_PRIVATE_KEY?.replace(/\\n/g, '\n') || '',
        privateKeyB64: process.env.JWT_PRIVATE_KEY_B64,
        publicKey: process.env.JWT_PUBLIC_KEY?.replace(/\\n/g, '\n'),
        accessTokenExpires: process.env.JWT_ACCESS_TOKEN_EXPIRES || '15m',
        refreshTokenExpires: process.env.JWT_REFRESH_TOKEN_EXPIRES || '30d',
        idTokenExpires: process.env.JWT_ID_TOKEN_EXPIRES || '1h',
      },
      oidc: {
        requirePKCE: process.env.REQUIRE_PKCE !== 'false',
        authCodeExpires: parseInt(process.env.AUTH_CODE_EXPIRES || '600'),
      },
      cookie: {
        secret: process.env.COOKIE_SECRET || 'a-strong-random-string',
        secure: process.env.COOKIE_SECURE !== 'false',
        sameSite: (process.env.COOKIE_SAME_SITE as 'strict' | 'lax' | 'none') || 'lax',
        sessionExpires: parseInt(process.env.SESSION_EXPIRES || '86400000'),
      },
      security: {
        corsOrigin,
        rateLimitMax: parseInt(process.env.RATE_LIMIT_MAX || '100'),
        rateLimitWindow: parseInt(process.env.RATE_LIMIT_WINDOW || '60000'),
        csrfProtection: process.env.CSRF_PROTECTION !== 'false',
      },
      secretStore: {
        useSecretStore: process.env.USE_SECRET_STORE === 'true',
        url: process.env.SECRET_STORE_URL || '',
        apiKey: process.env.XJP_KEY_AUTH || '',
      },
    };
  }

  clearCache(): void {
    this.config = null;
    this.loadPromise = null;
  }
}

export const configLoader = ConfigLoader.getInstance();

// Export a function to get config
export async function getConfig(): Promise<AuthConfig> {
  return configLoader.load();
}

// Export helper functions
export async function isDev(): Promise<boolean> {
  const config = await getConfig();
  return config.env === 'development';
}

export async function isProd(): Promise<boolean> {
  const config = await getConfig();
  return config.env === 'production';
}