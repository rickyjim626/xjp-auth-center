# Database Setup Guide

This guide covers setting up the auth-center database for both MySQL and TCB (Tencent Cloud Base) deployments.

## MySQL Setup (Recommended for self-hosted)

### Prerequisites

1. MySQL 8.0+ or MariaDB 10.5+
2. A database created: `CREATE DATABASE auth_center CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;`
3. A user with full privileges on the database

### Configuration

Update your `.env` file with database settings:

```bash
# Database Configuration
DATABASE_PROVIDER=mysql
DATABASE_URL=mysql://username:password@localhost:3306/auth_center
MIGRATE_ON_STARTUP=false

# Other required settings
ISSUER=https://your-domain.com
WECHAT_MP_APP_ID=your_mp_app_id
WECHAT_MP_APP_SECRET=your_mp_secret
WECHAT_OPEN_APP_ID=your_open_app_id
WECHAT_OPEN_APP_SECRET=your_open_secret
```

### Database Migration

1. **Verify schema** (optional but recommended):
   ```bash
   npm run verify-schema
   ```

2. **Run migration**:
   ```bash
   npm run migrate
   ```

3. **Verify tables were created**:
   ```sql
   USE auth_center;
   SHOW TABLES;
   -- Should show: auth_codes, identities, jwks, oauth_clients, tokens, users
   ```

### Default Data

The migration automatically creates two OAuth clients:
- `xjp-web`: For web applications
- `xjp-cli`: For CLI tools

You can add more clients by inserting into the `oauth_clients` table.

## TCB (Tencent Cloud Base) Setup

### Configuration

For TCB deployments, use:

```bash
DATABASE_PROVIDER=tcb
CLOUDBASE_ENV_ID=your_env_id
CLOUDBASE_SECRET_ID=your_secret_id
CLOUDBASE_SECRET_KEY=your_secret_key
CLOUDBASE_SESSION_TOKEN=your_session_token  # if using temporary credentials
```

### Database Collections

TCB uses the following collections (created automatically):
- `users`
- `identities`
- `oauth_clients`
- `auth_codes`
- `tokens`
- `jwks`

## Redis Configuration (Optional)

Redis is used for session state and rate limiting:

```bash
REDIS_ENABLED=true
REDIS_URL=redis://localhost:6379
```

If Redis is disabled, the system falls back to in-memory storage (not recommended for production).

## Health Checks

The application provides health check endpoints:

- `GET /health/live` - Basic liveness check
- `GET /health/ready` - Full readiness check (includes database and Redis)

## Development Mode

For development, you can use:

```bash
npm run dev        # Uses MySQL/Redis
npm run dev:tcb    # Uses TCB
```

## Production Deployment

1. Set `ENV=production` in your environment
2. Use proper SSL certificates
3. Configure your reverse proxy (nginx/cloudflare)
4. Set appropriate `CORS_ORIGIN` values
5. Use proper database connection pooling settings

## Troubleshooting

### Common Issues

1. **Connection refused**: Check database URL and credentials
2. **Table doesn't exist**: Run `npm run migrate`
3. **Permission denied**: Ensure database user has full privileges
4. **Charset issues**: Use utf8mb4 charset for full emoji support

### Logs

Check application logs for detailed error messages:

```bash
npm run dev 2>&1 | tee app.log
```

### Database Cleanup

To clean expired tokens and auth codes (run periodically):

```sql
-- Clean expired auth codes
DELETE FROM auth_codes WHERE expires_at < NOW();

-- Clean expired tokens
DELETE FROM tokens WHERE expires_at < NOW() AND revoked_at IS NULL;

-- Clean old revoked tokens (30+ days)
DELETE FROM tokens WHERE revoked_at < DATE_SUB(NOW(), INTERVAL 30 DAY);
```

## Migration from TCB to MySQL

To migrate from TCB to MySQL:

1. Export data from TCB collections
2. Set up MySQL database
3. Run MySQL migrations
4. Import data (adjust IDs and relationships)
5. Update configuration to use MySQL
6. Test thoroughly before switching production

For assistance with data migration, see the migration scripts in the `scripts/` directory.