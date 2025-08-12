import { z } from 'zod';
import { secretStoreClient } from '../services/secret-store.client.js';
import { logger } from '../utils/logger.js';
import dotenv from 'dotenv';

dotenv.config();

const authConfigSchema = z.object({
  env: z.enum(['development', 'staging', 'production']).default('development'),
  server: z.object({
    port: z.number().default(3001),
    host: z.string().default('0.0.0.0'),
  }),
  tcb: z.object({
    envId: z.string(),
    secretId: z.string(),
    secretKey: z.string(),
    sessionToken: z.string().optional(),
  }),
  wechat: z.object({
    appId: z.string(),
    appSecret: z.string(),
    redirectUri: z.string(),
  }),
  jwt: z.object({
    issuer: z.string(),
    accessTokenExpires: z.string().default('15m'),
    refreshTokenExpires: z.string().default('30d'),
    privateKey: z.string().optional(),
    publicJwks: z.any().optional(),
  }),
  security: z.object({
    corsOrigin: z.array(z.string()),
    rateLimitMax: z.number().default(100),
    rateLimitWindow: z.number().default(60000),
  }),
  secretStore: z.object({
    url: z.string(),
    apiKey: z.string(),
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
          port: parseInt(process.env.PORT || '3001'),
          host: process.env.HOST || '0.0.0.0',
        },
        tcb: {
          envId: configs.TCB_ENV_ID || configs.TCB_ENV_NAME,
          secretId: secrets.TENCENTCLOUD_SECRETID,
          secretKey: secrets.TENCENTCLOUD_SECRETKEY,
          sessionToken: secrets.TENCENTCLOUD_SESSIONTOKEN,
        },
        wechat: {
          appId: secrets.WECHAT_WEB_APPID,
          appSecret: secrets.WECHAT_WEB_APPSECRET,
          redirectUri: configs.WECHAT_REDIRECT_URI || 'https://auth.xiaojinpro.com/auth/wechat/callback',
        },
        jwt: {
          issuer: configs.ISSUER || 'https://auth.xiaojinpro.com',
          accessTokenExpires: configs.JWT_ACCESS_TOKEN_EXPIRES || '15m',
          refreshTokenExpires: configs.JWT_REFRESH_TOKEN_EXPIRES || '30d',
          privateKey: secrets.JWT_PRIVATE_KEY,
          publicJwks,
        },
        security: {
          corsOrigin,
          rateLimitMax: parseInt(configs.RATE_LIMIT_MAX || '100'),
          rateLimitWindow: parseInt(configs.RATE_LIMIT_WINDOW || '60000'),
        },
        secretStore: {
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
      env: process.env.ENV || 'development',
      server: {
        port: parseInt(process.env.PORT || '3001'),
        host: process.env.HOST || '0.0.0.0',
      },
      tcb: {
        envId: process.env.TCB_ENV_ID || '',
        secretId: process.env.TENCENTCLOUD_SECRETID || '',
        secretKey: process.env.TENCENTCLOUD_SECRETKEY || '',
        sessionToken: process.env.TENCENTCLOUD_SESSIONTOKEN,
      },
      wechat: {
        appId: process.env.WECHAT_WEB_APPID || '',
        appSecret: process.env.WECHAT_WEB_APPSECRET || '',
        redirectUri: process.env.WECHAT_REDIRECT_URI || 'http://localhost:3001/auth/wechat/callback',
      },
      jwt: {
        issuer: process.env.ISSUER || 'http://localhost:3001',
        accessTokenExpires: process.env.JWT_ACCESS_TOKEN_EXPIRES || '15m',
        refreshTokenExpires: process.env.JWT_REFRESH_TOKEN_EXPIRES || '30d',
      },
      security: {
        corsOrigin,
        rateLimitMax: parseInt(process.env.RATE_LIMIT_MAX || '100'),
        rateLimitWindow: parseInt(process.env.RATE_LIMIT_WINDOW || '60000'),
      },
      secretStore: {
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