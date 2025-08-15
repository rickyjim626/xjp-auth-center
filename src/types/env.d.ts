declare namespace NodeJS {
  interface ProcessEnv {
    // Environment
    ENV?: 'development' | 'staging' | 'production';
    PORT?: string;
    HOST?: string;
    
    // TCB Configuration
    TCB_ENV_ID?: string;
    TENCENTCLOUD_SECRETID?: string;
    TENCENTCLOUD_SECRETKEY?: string;
    TENCENTCLOUD_SESSIONTOKEN?: string;
    
    // WeChat OAuth
    WECHAT_WEB_APPID?: string;
    WECHAT_WEB_APPSECRET?: string;
    WECHAT_REDIRECT_URI?: string;
    
    // JWT
    ISSUER?: string;
    JWT_ACCESS_TOKEN_EXPIRES?: string;
    JWT_REFRESH_TOKEN_EXPIRES?: string;
    JWT_PRIVATE_KEY?: string;
    
    // Database
    PG_CONNECTION_STRING?: string;
    PG_POOL_SIZE?: string;
    
    // Redis
    REDIS_URL?: string;
    
    // Secret Store
    SECRET_STORE_URL?: string;
    XJP_KEY_AUTH?: string;
    USE_SECRET_STORE?: string;
    
    // Security
    CORS_ORIGIN?: string;
    RATE_LIMIT_MAX?: string;
    RATE_LIMIT_WINDOW?: string;
    
    // Logging
    LOG_LEVEL?: string;
  }
}