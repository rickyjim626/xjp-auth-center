import dotenv from 'dotenv';
import { z } from 'zod';

dotenv.config();

const configSchema = z.object({
  env: z.enum(['development', 'staging', 'production']).default('development'),
  server: z.object({
    port: z.number().default(3001),
    host: z.string().default('0.0.0.0'),
  }),
  db: z.object({
    connectionString: z.string(),
    poolSize: z.number().default(20),
  }),
  redis: z.object({
    url: z.string().optional(),
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
  }),
  security: z.object({
    corsOrigin: z.string().transform(s => s.split(',')),
    rateLimitMax: z.number().default(100),
    rateLimitWindow: z.number().default(60000),
  }),
});

const rawConfig = {
  env: process.env.ENV || 'development',
  server: {
    port: parseInt(process.env.PORT || '3001'),
    host: process.env.HOST || '0.0.0.0',
  },
  db: {
    connectionString: process.env.PG_CONNECTION_STRING || '',
    poolSize: parseInt(process.env.PG_POOL_SIZE || '20'),
  },
  redis: {
    url: process.env.REDIS_URL,
  },
  wechat: {
    appId: process.env.WECHAT_WEB_APPID || '',
    appSecret: process.env.WECHAT_WEB_APPSECRET || '',
    redirectUri: process.env.WECHAT_REDIRECT_URI || 'https://auth.xiaojinpro.com/auth/wechat/callback',
  },
  jwt: {
    issuer: process.env.ISSUER || 'https://auth.xiaojinpro.com',
    accessTokenExpires: process.env.JWT_ACCESS_TOKEN_EXPIRES || '15m',
    refreshTokenExpires: process.env.JWT_REFRESH_TOKEN_EXPIRES || '30d',
  },
  security: {
    corsOrigin: process.env.CORS_ORIGIN || 'https://xiaojinpro.com,https://*.xiaojinpro.com',
    rateLimitMax: parseInt(process.env.RATE_LIMIT_MAX || '100'),
    rateLimitWindow: parseInt(process.env.RATE_LIMIT_WINDOW || '60000'),
  },
};

export const config = configSchema.parse(rawConfig);

export const isDev = config.env === 'development';
export const isProd = config.env === 'production';