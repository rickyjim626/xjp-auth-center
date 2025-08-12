-- Auth Center Database Schema
-- PostgreSQL 14+

-- Users table
CREATE TABLE IF NOT EXISTS users (
  id BIGSERIAL PRIMARY KEY,
  display_name TEXT,
  avatar_url TEXT,
  email TEXT,
  phone TEXT,
  is_disabled BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_login_at TIMESTAMPTZ
);

CREATE INDEX idx_users_created_at ON users(created_at);
CREATE INDEX idx_users_is_disabled ON users(is_disabled);

-- External identities (WeChat, Google, etc.)
CREATE TABLE IF NOT EXISTS identities (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  provider TEXT NOT NULL, -- 'wechat_open_web', 'google', etc.
  openid TEXT NOT NULL,
  unionid TEXT, -- WeChat UnionID for cross-app consistency
  email TEXT,
  raw JSONB, -- Raw provider response
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(provider, openid)
);

CREATE INDEX idx_identities_user_id ON identities(user_id);
CREATE INDEX idx_identities_provider_openid ON identities(provider, openid);
CREATE INDEX idx_identities_unionid ON identities(unionid) WHERE unionid IS NOT NULL;

-- OAuth clients/applications
CREATE TABLE IF NOT EXISTS clients (
  id TEXT PRIMARY KEY, -- client_id
  name TEXT NOT NULL,
  secret TEXT, -- Hashed, null for public clients
  redirect_uris TEXT[] NOT NULL DEFAULT '{}',
  allowed_scopes TEXT[] NOT NULL DEFAULT '{}',
  first_party BOOLEAN NOT NULL DEFAULT FALSE,
  is_disabled BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- OAuth authorization codes (temporary)
CREATE TABLE IF NOT EXISTS auth_codes (
  code TEXT PRIMARY KEY,
  client_id TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  redirect_uri TEXT NOT NULL,
  scope TEXT,
  code_challenge TEXT,
  code_challenge_method TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_auth_codes_expires_at ON auth_codes(expires_at);

-- User sessions
CREATE TABLE IF NOT EXISTS sessions (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  client_id TEXT REFERENCES clients(id) ON DELETE SET NULL,
  device TEXT,
  ip INET,
  ua TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_activity_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  revoked_at TIMESTAMPTZ
);

CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_revoked_at ON sessions(revoked_at);

-- Refresh tokens
CREATE TABLE IF NOT EXISTS refresh_tokens (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  session_id BIGINT REFERENCES sessions(id) ON DELETE CASCADE,
  client_id TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
  jti TEXT NOT NULL UNIQUE, -- JWT ID for tracking
  rotated_from TEXT, -- Previous refresh token jti (for rotation)
  scope TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL,
  revoked_at TIMESTAMPTZ,
  revoke_reason TEXT
);

CREATE INDEX idx_refresh_tokens_jti ON refresh_tokens(jti);
CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens(user_id);
CREATE INDEX idx_refresh_tokens_expires_at ON refresh_tokens(expires_at);
CREATE INDEX idx_refresh_tokens_rotated_from ON refresh_tokens(rotated_from);

-- JWK keys for signing/verification
CREATE TABLE IF NOT EXISTS jwk_keys (
  kid TEXT PRIMARY KEY,
  alg TEXT NOT NULL, -- 'EdDSA', 'ES256', etc.
  use TEXT NOT NULL DEFAULT 'sig', -- 'sig' or 'enc'
  public_jwk JSONB NOT NULL,
  private_jwk JSONB, -- Encrypted in production
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  rotated_at TIMESTAMPTZ,
  disabled_at TIMESTAMPTZ
);

CREATE INDEX idx_jwk_keys_disabled_at ON jwk_keys(disabled_at);

-- Login tickets for QR code flow
CREATE TABLE IF NOT EXISTS login_tickets (
  id TEXT PRIMARY KEY, -- loginId
  status TEXT NOT NULL DEFAULT 'PENDING', -- PENDING, SCANNED, AUTHORIZED, SUCCESS, FAIL, TIMEOUT
  client_id TEXT REFERENCES clients(id) ON DELETE SET NULL,
  redirect_uri TEXT,
  state TEXT,
  ip INET,
  ua TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ NOT NULL,
  scanned_at TIMESTAMPTZ,
  authorized_at TIMESTAMPTZ,
  result JSONB -- Contains auth_code or error info
);

CREATE INDEX idx_login_tickets_status ON login_tickets(status);
CREATE INDEX idx_login_tickets_expires_at ON login_tickets(expires_at);

-- Roles and permissions
CREATE TABLE IF NOT EXISTS roles (
  id BIGSERIAL PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  description TEXT,
  permissions JSONB NOT NULL DEFAULT '[]',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- User role assignments
CREATE TABLE IF NOT EXISTS user_roles (
  user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role_id BIGINT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  granted_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
  granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at TIMESTAMPTZ,
  PRIMARY KEY (user_id, role_id)
);

CREATE INDEX idx_user_roles_user_id ON user_roles(user_id);
CREATE INDEX idx_user_roles_role_id ON user_roles(role_id);

-- Audit logs
CREATE TABLE IF NOT EXISTS audit_logs (
  id BIGSERIAL PRIMARY KEY,
  actor TEXT, -- user_id or system
  action TEXT NOT NULL, -- login.start, login.success, token.issue, etc.
  resource TEXT, -- What was acted upon
  ip INET,
  ua TEXT,
  status TEXT, -- success, fail
  error_code TEXT,
  ts TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  extra JSONB
);

CREATE INDEX idx_audit_logs_actor ON audit_logs(actor);
CREATE INDEX idx_audit_logs_action ON audit_logs(action);
CREATE INDEX idx_audit_logs_ts ON audit_logs(ts);

-- Cleanup function for expired records
CREATE OR REPLACE FUNCTION cleanup_expired_records() RETURNS void AS $$
BEGIN
  -- Delete expired auth codes
  DELETE FROM auth_codes WHERE expires_at < NOW();
  
  -- Delete expired login tickets
  DELETE FROM login_tickets WHERE expires_at < NOW() AND status != 'SUCCESS';
  
  -- Mark expired refresh tokens as revoked
  UPDATE refresh_tokens 
  SET revoked_at = NOW(), revoke_reason = 'expired' 
  WHERE expires_at < NOW() AND revoked_at IS NULL;
END;
$$ LANGUAGE plpgsql;

-- Update timestamp trigger
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Apply update trigger to relevant tables
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
  FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER update_identities_updated_at BEFORE UPDATE ON identities
  FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER update_clients_updated_at BEFORE UPDATE ON clients
  FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER update_roles_updated_at BEFORE UPDATE ON roles
  FOR EACH ROW EXECUTE FUNCTION update_updated_at();