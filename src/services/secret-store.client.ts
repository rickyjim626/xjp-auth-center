import axios, { AxiosInstance } from 'axios';
import { logger } from '../utils/logger.js';

interface SecretStoreConfig {
  secrets: Record<string, string>;
  configs: Record<string, string>;
}

export class SecretStoreClient {
  private static instance: SecretStoreClient;
  private client: AxiosInstance;
  private cache: Map<string, { value: any; expires: number }> = new Map();
  private readonly CACHE_TTL = 5 * 60 * 1000; // 5 minutes

  private constructor() {
    const baseURL = process.env.SECRET_STORE_URL || 'https://yzuukzffofsw.sg-members-1.clawcloudrun.com';
    const apiKey = process.env.XJP_KEY_AUTH || '';

    if (!apiKey) {
      logger.warn('XJP_KEY_AUTH not set, using local environment variables');
    }

    this.client = axios.create({
      baseURL,
      headers: {
        'Authorization': `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
      },
      timeout: 5000,
    });
  }

  static getInstance(): SecretStoreClient {
    if (!SecretStoreClient.instance) {
      SecretStoreClient.instance = new SecretStoreClient();
    }
    return SecretStoreClient.instance;
  }

  async getSecret(namespace: string, key: string): Promise<string> {
    const cacheKey = `secret:${namespace}:${key}`;
    const cached = this.getFromCache(cacheKey);
    if (cached) return cached;

    try {
      const response = await this.client.get(`/v1/secrets/${key}`, {
        params: { ns: namespace },
      });
      
      const value = response.data; // API returns value directly for secrets
      this.setCache(cacheKey, value);
      return value;
    } catch (error) {
      logger.error({ error, namespace, key }, 'Failed to get secret from Secret Store');
      throw error;
    }
  }

  async getConfig(namespace: string, key: string): Promise<string> {
    const cacheKey = `config:${namespace}:${key}`;
    const cached = this.getFromCache(cacheKey);
    if (cached) return cached;

    try {
      const response = await this.client.get(`/v1/configs/${key}`, {
        params: { ns: namespace },
      });
      
      const value = response.data.value;
      this.setCache(cacheKey, value);
      return value;
    } catch (error) {
      logger.error({ error, namespace, key }, 'Failed to get config from Secret Store');
      throw error;
    }
  }

  async getNamespaceConfig(namespace: string): Promise<SecretStoreConfig> {
    const cacheKey = `namespace:${namespace}`;
    const cached = this.getFromCache(cacheKey);
    if (cached) return cached;

    try {
      const response = await this.client.get('/v1/sync/export', {
        params: { ns: namespace },
      });
      
      const config: SecretStoreConfig = {
        secrets: response.data.secrets || {},
        configs: response.data.configs || {},
      };
      
      this.setCache(cacheKey, config);
      return config;
    } catch (error) {
      logger.error({ error, namespace }, 'Failed to get namespace config from Secret Store');
      throw error;
    }
  }

  async healthCheck(): Promise<{ status: 'healthy' | 'unhealthy'; latency?: number }> {
    const start = Date.now();
    try {
      await this.client.get('/health');
      return {
        status: 'healthy',
        latency: Date.now() - start,
      };
    } catch (error) {
      return { status: 'unhealthy' };
    }
  }

  private getFromCache(key: string): any {
    const cached = this.cache.get(key);
    if (cached && cached.expires > Date.now()) {
      return cached.value;
    }
    this.cache.delete(key);
    return null;
  }

  private setCache(key: string, value: any): void {
    this.cache.set(key, {
      value,
      expires: Date.now() + this.CACHE_TTL,
    });
  }

  clearCache(): void {
    this.cache.clear();
  }
}

export const secretStoreClient = SecretStoreClient.getInstance();