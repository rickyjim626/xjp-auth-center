import { createClient, RedisClientType } from 'redis';
import { logger } from '../utils/logger.js';

export class RedisManager {
  private client: RedisClientType | null = null;
  private enabled: boolean;

  constructor(url?: string, enabled = true) {
    this.enabled = enabled;
    
    if (this.enabled && url) {
      this.client = createClient({ url });
      this.client.on('error', (err) => {
        logger.error({ error: err }, 'Redis client error');
      });
    }
  }

  async connect(): Promise<void> {
    if (this.enabled && this.client && !this.client.isOpen) {
      await this.client.connect();
      logger.info('Redis connected');
    }
  }

  async disconnect(): Promise<void> {
    if (this.enabled && this.client && this.client.isOpen) {
      await this.client.disconnect();
      logger.info('Redis disconnected');
    }
  }

  async ping(): Promise<boolean> {
    if (!this.enabled || !this.client) return true;
    
    try {
      const result = await this.client.ping();
      return result === 'PONG';
    } catch (error) {
      logger.error({ error }, 'Redis ping failed');
      return false;
    }
  }

  // 登录状态管理
  async setLoginState(loginId: string, state: any, ttlSeconds = 600): Promise<void> {
    if (!this.enabled) {
      // 回退到内存存储 (开发模式)
      this.memoryStore.set(loginId, {
        data: state,
        expires: Date.now() + ttlSeconds * 1000
      });
      return;
    }

    await this.client!.setEx(`login:${loginId}`, ttlSeconds, JSON.stringify(state));
  }

  async getLoginState(loginId: string): Promise<any | null> {
    if (!this.enabled) {
      const item = this.memoryStore.get(loginId);
      if (item && item.expires > Date.now()) {
        return item.data;
      }
      this.memoryStore.delete(loginId);
      return null;
    }

    const data = await this.client!.get(`login:${loginId}`);
    return data ? JSON.parse(data) : null;
  }

  async deleteLoginState(loginId: string): Promise<void> {
    if (!this.enabled) {
      this.memoryStore.delete(loginId);
      return;
    }

    await this.client!.del(`login:${loginId}`);
  }

  // 授权码缓存 (可选，减少数据库查询)
  async setAuthCode(code: string, data: any, ttlSeconds = 600): Promise<void> {
    if (!this.enabled) return;
    
    await this.client!.setEx(`auth_code:${code}`, ttlSeconds, JSON.stringify(data));
  }

  async getAuthCode(code: string): Promise<any | null> {
    if (!this.enabled) return null;
    
    const data = await this.client!.get(`auth_code:${code}`);
    return data ? JSON.parse(data) : null;
  }

  async deleteAuthCode(code: string): Promise<void> {
    if (!this.enabled) return;
    
    await this.client!.del(`auth_code:${code}`);
  }

  // 速率限制 (可选)
  async checkRateLimit(key: string, limit: number, windowSeconds: number): Promise<{ allowed: boolean; remaining: number }> {
    if (!this.enabled) {
      return { allowed: true, remaining: limit };
    }

    const current = await this.client!.incr(`rate:${key}`);
    
    if (current === 1) {
      await this.client!.expire(`rate:${key}`, windowSeconds);
    }

    return {
      allowed: current <= limit,
      remaining: Math.max(0, limit - current)
    };
  }

  // 内存回退存储 (当 Redis 未启用时)
  private memoryStore = new Map<string, { data: any; expires: number }>();
  
  // 清理过期的内存缓存
  private cleanExpiredMemory(): void {
    const now = Date.now();
    for (const [key, item] of this.memoryStore) {
      if (item.expires <= now) {
        this.memoryStore.delete(key);
      }
    }
  }
}

// 全局实例
let redisManager: RedisManager;

export function createRedisManager(url?: string, enabled = true): RedisManager {
  if (!redisManager) {
    redisManager = new RedisManager(url, enabled);
  }
  return redisManager;
}

export function getRedisManager(): RedisManager {
  if (!redisManager) {
    throw new Error('Redis manager not initialized. Call createRedisManager() first.');
  }
  return redisManager;
}