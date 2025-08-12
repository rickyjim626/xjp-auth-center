# XiaoJin Pro Auth Center

微信扫码登录认证中心 - 支持 WeChat OAuth、JWT 签发、用户管理的统一认证服务。

## 功能特性

- ✅ **微信扫码登录** - PC 网页扫码认证（微信开放平台）
- ✅ **JWT 签发与验证** - Ed25519 签名，JWKS 端点
- ✅ **OAuth 2.0** - 授权码流程，支持 PKCE，刷新令牌轮换
- ✅ **SSE 实时推送** - 登录状态实时通知
- ✅ **用户管理** - 用户信息、会话管理、角色权限
- ✅ **安全审计** - 完整的操作日志记录
- ✅ **速率限制** - 防止暴力攻击

## 快速开始

### 1. 环境准备

```bash
# 安装依赖
npm install

# 复制环境变量配置
cp .env.example .env

# 编辑 .env 文件，配置必要参数：
# - WECHAT_WEB_APPID
# - WECHAT_WEB_APPSECRET
# - PG_CONNECTION_STRING
```

### 2. 数据库初始化

```bash
# 运行数据库迁移
npm run db:migrate
```

### 3. 启动服务

```bash
# 开发模式
npm run dev

# 生产构建
npm run build
npm start

# Docker Compose（包含 PostgreSQL 和 Redis）
docker-compose up
```

## API 端点

### 认证流程

```bash
# 1. 生成微信二维码
POST /auth/wechat/qr
Response: { loginId, qrUrl, expiresIn }

# 2. SSE 监听登录状态
GET /auth/login-stream?loginId=xxx
Events: pending -> scanned -> authorized -> success

# 3. 微信回调（自动处理）
GET /auth/wechat/callback?code=xxx&state=xxx

# 4. 换取令牌
POST /oauth/token
Body: {
  grant_type: "authorization_code",
  code: "xxx",
  client_id: "xxx",
  redirect_uri: "xxx"
}
Response: { access_token, refresh_token, expires_in }
```

### JWKS 公钥

```bash
GET /.well-known/jwks.json
GET /.well-known/openid-configuration
```

### 用户管理

```bash
# 当前用户信息
GET /v1/users/me
Authorization: Bearer <token>

# 更新用户信息
PATCH /v1/users/me
Body: { display_name, avatar_url, email, phone }

# 会话管理
GET /v1/sessions
POST /v1/sessions/:id/revoke

# 审计日志
GET /v1/audit
```

## 集成指南

### 前端集成

```javascript
// 1. 请求二维码
const { loginId, qrUrl } = await fetch('/auth/wechat/qr', {
  method: 'POST',
  body: JSON.stringify({ client_id: 'your-app' })
}).then(r => r.json());

// 2. 展示二维码
document.getElementById('qr-img').src = qrUrl;

// 3. SSE 监听状态
const sse = new EventSource(`/auth/login-stream?loginId=${loginId}`);
sse.addEventListener('success', (e) => {
  const { authCode } = JSON.parse(e.data);
  // 使用 authCode 换取 token
});
```

### 后端验证

```javascript
// 验证 JWT
import { createRemoteJWKSet, jwtVerify } from 'jose';

const JWKS = createRemoteJWKSet(
  new URL('https://auth.xiaojinpro.com/.well-known/jwks.json')
);

const { payload } = await jwtVerify(token, JWKS, {
  issuer: 'https://auth.xiaojinpro.com',
});

console.log('User ID:', payload.sub);
console.log('Roles:', payload['xjp.roles']);
```

## 配置说明

### 微信开放平台配置

1. 登录[微信开放平台](https://open.weixin.qq.com/)
2. 创建网站应用
3. 配置授权回调域名：`auth.xiaojinpro.com`
4. 获取 AppID 和 AppSecret

### 环境变量

| 变量名 | 说明 | 示例 |
|--------|------|------|
| WECHAT_WEB_APPID | 微信网站应用 AppID | wx1234567890 |
| WECHAT_WEB_APPSECRET | 微信网站应用 Secret | secret123 |
| WECHAT_REDIRECT_URI | 微信回调地址 | https://auth.xiaojinpro.com/auth/wechat/callback |
| PG_CONNECTION_STRING | PostgreSQL 连接字符串 | postgresql://user:pass@localhost:5432/auth |
| REDIS_URL | Redis 连接字符串（可选） | redis://localhost:6379 |
| ISSUER | JWT 签发者 | https://auth.xiaojinpro.com |
| JWT_ACCESS_TOKEN_EXPIRES | 访问令牌有效期 | 15m |
| JWT_REFRESH_TOKEN_EXPIRES | 刷新令牌有效期 | 30d |

## 部署

### Docker 部署

```bash
# 构建镜像
docker build -t auth-center .

# 运行容器
docker run -d \
  --name auth-center \
  -p 3001:3001 \
  --env-file .env \
  auth-center
```

### 腾讯云 TCB 部署

```yaml
# cloudbaserc.json
{
  "envId": "your-env-id",
  "framework": {
    "name": "auth-center",
    "plugins": {
      "node": {
        "use": "@cloudbase/framework-plugin-node",
        "inputs": {
          "name": "auth-center",
          "path": "./",
          "platform": "container",
          "containerPort": 3001,
          "cpu": 0.5,
          "mem": 1,
          "envVariables": {
            "PORT": "3001",
            "HOST": "0.0.0.0"
          }
        }
      }
    }
  }
}
```

## 安全考虑

1. **CSRF 防护** - 所有登录请求使用 state 参数
2. **速率限制** - 默认 100 请求/分钟
3. **令牌轮换** - 刷新令牌使用后自动轮换
4. **会话管理** - 支持主动注销和会话列表
5. **审计日志** - 记录所有关键操作

## 监控

健康检查端点：

- `/health` - 服务健康状态
- `/ready` - 服务就绪状态

## License

MIT