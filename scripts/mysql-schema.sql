-- MySQL Schema for auth-center
-- Based on the 6-table simplified design

-- 用户表
CREATE TABLE IF NOT EXISTS users (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  unionid VARCHAR(64) UNIQUE,
  openid_mp VARCHAR(64),
  openid_open VARCHAR(64),
  nickname VARCHAR(128),
  avatar VARCHAR(256),
  email VARCHAR(255),
  is_admin BOOLEAN DEFAULT FALSE,
  is_disabled BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  last_login_at TIMESTAMP NULL,
  
  INDEX idx_users_unionid (unionid),
  INDEX idx_users_openid_mp (openid_mp),
  INDEX idx_users_openid_open (openid_open),
  INDEX idx_users_created_at (created_at),
  INDEX idx_users_is_disabled (is_disabled)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 身份提供商表 (微信等)
CREATE TABLE IF NOT EXISTS identities (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  user_id BIGINT NOT NULL,
  provider VARCHAR(32) NOT NULL, -- 'wechat'
  openid VARCHAR(64) NOT NULL,
  unionid VARCHAR(64),
  profile JSON,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  
  UNIQUE KEY uk_identities_provider_openid (provider, openid),
  INDEX idx_identities_user_id (user_id),
  INDEX idx_identities_unionid (unionid),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- OAuth 客户端表
CREATE TABLE IF NOT EXISTS oauth_clients (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  client_id VARCHAR(64) UNIQUE NOT NULL,
  name VARCHAR(128),
  redirect_uris JSON NOT NULL DEFAULT ('[]'),
  first_party BOOLEAN DEFAULT FALSE,
  allowed_scopes JSON NOT NULL DEFAULT ('["openid", "profile"]'),
  is_disabled BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  
  UNIQUE KEY uk_clients_client_id (client_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 授权码表 (短期)
CREATE TABLE IF NOT EXISTS auth_codes (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  code VARCHAR(128) UNIQUE NOT NULL,
  client_id VARCHAR(64) NOT NULL,
  user_id BIGINT NOT NULL,
  redirect_uri TEXT,
  scopes JSON NOT NULL DEFAULT ('["openid", "profile"]'),
  code_challenge VARCHAR(128),
  code_challenge_method VARCHAR(10),
  expires_at TIMESTAMP NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  used_at TIMESTAMP NULL,
  
  UNIQUE KEY uk_auth_codes_code (code),
  INDEX idx_auth_codes_expires_at (expires_at),
  INDEX idx_auth_codes_client_id (client_id),
  INDEX idx_auth_codes_user_id (user_id),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (client_id) REFERENCES oauth_clients(client_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 统一令牌表 (access + refresh)
CREATE TABLE IF NOT EXISTS tokens (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  jti VARCHAR(64) UNIQUE NOT NULL,
  user_id BIGINT NOT NULL,
  client_id VARCHAR(64) NOT NULL,
  session_id VARCHAR(64) NOT NULL,
  token_type ENUM('access_token', 'refresh_token') NOT NULL,
  scopes JSON NOT NULL DEFAULT ('["openid", "profile"]'),
  refresh_token_jti VARCHAR(64),
  parent_refresh_token_jti VARCHAR(64),
  device_info JSON,
  expires_at TIMESTAMP NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  revoked_at TIMESTAMP NULL,
  last_used_at TIMESTAMP NULL,
  
  UNIQUE KEY uk_tokens_jti (jti),
  INDEX idx_tokens_user_id (user_id),
  INDEX idx_tokens_client_id (client_id),
  INDEX idx_tokens_session_id (session_id),
  INDEX idx_tokens_refresh_token_jti (refresh_token_jti),
  INDEX idx_tokens_expires_at (expires_at),
  INDEX idx_tokens_token_type (token_type),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (client_id) REFERENCES oauth_clients(client_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- JWK 密钥表
CREATE TABLE IF NOT EXISTS jwks (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  key_id VARCHAR(64) UNIQUE NOT NULL,
  key_type VARCHAR(16) NOT NULL, -- 'RSA'
  algorithm VARCHAR(16) NOT NULL, -- 'RS256'
  public_key TEXT NOT NULL,
  private_key TEXT NOT NULL,
  is_active BOOLEAN DEFAULT TRUE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  rotated_at TIMESTAMP NULL,
  
  UNIQUE KEY uk_jwks_key_id (key_id),
  INDEX idx_jwks_is_active (is_active)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 默认数据插入
INSERT IGNORE INTO oauth_clients (client_id, name, redirect_uris, first_party, allowed_scopes) VALUES
('xjp-web', 'XiaoJin Pro Web', 
 '["https://xiaojinpro.com/callback", "https://*.xiaojinpro.com/callback"]',
 TRUE, 
 '["openid", "profile", "email"]'),
('xjp-cli', 'XiaoJin Pro CLI',
 '["http://localhost:8989/callback", "xjp://callback"]',
 TRUE,
 '["openid", "profile", "offline_access"]');

-- Note: Stored procedures and events can be created manually if needed
-- Example cleanup queries (run manually or via cron):
-- DELETE FROM auth_codes WHERE expires_at < NOW();
-- DELETE FROM tokens WHERE expires_at < NOW() AND revoked_at IS NULL;
-- DELETE FROM tokens WHERE revoked_at < DATE_SUB(NOW(), INTERVAL 30 DAY);