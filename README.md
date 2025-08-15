# XiaoJin Pro Auth Center - 微信登录认证中心

基于 OAuth 2.0 / OIDC 标准的统一认证中心，支持微信开放平台（PC扫码）和公众号（H5网页授权）双平台登录，并通过 UnionID 实现跨应用用户统一。

## 核心特性

- ✅ **标准 OAuth 2.0 / OIDC 实现**
  - 授权码流程 + PKCE
  - Discovery Endpoint (`.well-known/openid-configuration`)
  - JWKS Endpoint (`.well-known/jwks.json`)
  - UserInfo Endpoint

- ✅ **微信双平台登录**
  - PC/非微信环境：开放平台扫码登录
  - 微信内H5：公众号网页授权
  - UnionID 跨应用用户统一

- ✅ **腾讯云 TCB 优化**
  - 健康检查优化（initialDelaySeconds=30s）
  - 环境变量直传（避免 Secret Store 网络问题）
  - 容器化部署
  - 自定义域名支持

## 快速开始

### 1. 微信平台配置

#### 开放平台（PC扫码）
1. 登录[微信开放平台](https://open.weixin.qq.com)
2. 创建"网站应用"
3. 授权回调域设置：`auth.xiaojinpro.com`（不带协议）
4. 记录 `AppID` 和 `AppSecret`

#### 公众号（微信内H5）
1. 登录[微信公众平台](https://mp.weixin.qq.com)
2. 网页授权域名设置：`auth.xiaojinpro.com`
3. 记录 `AppID` 和 `AppSecret`

### 2. 环境变量配置

复制 `.env.template` 为 `.env.production` 并填写：

```bash
# 微信开放平台（PC扫码）
WECHAT_OPEN_APPID=wx_your_open_appid
WECHAT_OPEN_SECRET=your_open_secret

# 微信公众号（H5）
WECHAT_MP_APPID=wx_your_mp_appid
WECHAT_MP_SECRET=your_mp_secret

# JWT密钥（生成命令见下方）
JWT_PRIVATE_KEY=-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----

# Cookie密钥
COOKIE_SECRET=your-cookie-secret

# 腾讯云密钥
TENCENTCLOUD_SECRETID=your-secret-id
TENCENTCLOUD_SECRETKEY=your-secret-key
```

#### 生成密钥

```bash
# 生成RSA密钥对
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem

# 转换为环境变量格式（单行）
cat private.pem | awk '{printf "%s\\n", $0}'

# 生成Cookie Secret
openssl rand -hex 32
```

### 3. 部署到 TCB

```bash
# 使用部署脚本
./deploy-tcb.sh

# 选择部署方式：
# 1. 控制台部署（推荐）- 生成配置后手动在控制台部署
# 2. CLI部署 - 自动部署
# 3. 仅构建镜像 - 构建并推送镜像
```

### 4. 验证部署

访问以下端点验证：

- 健康检查：`https://auth.xiaojinpro.com/health/ready`
- OIDC Discovery：`https://auth.xiaojinpro.com/.well-known/openid-configuration`
- JWKS：`https://auth.xiaojinpro.com/.well-known/jwks.json`

## API 接口

### OIDC 标准端点

#### 1. 授权端点
```
GET /oauth2/authorize
参数：
  - response_type: code
  - client_id: 客户端ID
  - redirect_uri: 回调地址
  - scope: openid profile
  - state: 防CSRF令牌
  - code_challenge: PKCE挑战码
  - code_challenge_method: S256
```

#### 2. 令牌端点
```
POST /oauth2/token
参数：
  - grant_type: authorization_code | refresh_token
  - code: 授权码
  - redirect_uri: 回调地址
  - client_id: 客户端ID
  - code_verifier: PKCE验证码
```

#### 3. 用户信息端点
```
GET /userinfo
Headers:
  - Authorization: Bearer {access_token}
```

### 微信特定端点

#### 生成登录URL
```
POST /wechat/login-url
Body:
  {
    "type": "pc" | "mp",
    "redirectUri": "https://your-site.com/callback",
    "state": "random-state"
  }
```

#### 检查会话
```
GET /wechat/check-session
```

#### 登出
```
POST /wechat/logout
```

## 客户端接入示例

### JavaScript/TypeScript

```typescript
// 1. 生成授权URL
const authUrl = new URL('https://auth.xiaojinpro.com/oauth2/authorize');
authUrl.searchParams.set('response_type', 'code');
authUrl.searchParams.set('client_id', 'your-client-id');
authUrl.searchParams.set('redirect_uri', 'https://your-app.com/callback');
authUrl.searchParams.set('scope', 'openid profile');
authUrl.searchParams.set('state', generateRandomState());

// PKCE
const verifier = generateCodeVerifier();
const challenge = await generateCodeChallenge(verifier);
authUrl.searchParams.set('code_challenge', challenge);
authUrl.searchParams.set('code_challenge_method', 'S256');

// 保存verifier到sessionStorage
sessionStorage.setItem('code_verifier', verifier);

// 跳转到授权页
window.location.href = authUrl.toString();

// 2. 回调处理
const urlParams = new URLSearchParams(window.location.search);
const code = urlParams.get('code');
const state = urlParams.get('state');

// 验证state
if (state !== sessionStorage.getItem('auth_state')) {
  throw new Error('State mismatch');
}

// 3. 换取令牌
const response = await fetch('https://auth.xiaojinpro.com/oauth2/token', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
  },
  body: JSON.stringify({
    grant_type: 'authorization_code',
    code,
    redirect_uri: 'https://your-app.com/callback',
    client_id: 'your-client-id',
    code_verifier: sessionStorage.getItem('code_verifier'),
  }),
});

const tokens = await response.json();
// tokens = { access_token, refresh_token, id_token, ... }

// 4. 获取用户信息
const userResponse = await fetch('https://auth.xiaojinpro.com/userinfo', {
  headers: {
    'Authorization': `Bearer ${tokens.access_token}`,
  },
});

const userInfo = await userResponse.json();
```

## TCB 部署要点

### 关键配置

1. **健康检查**
   - initialDelaySeconds: 30s（必须 >= 启动时间）
   - 路径：`/health/ready`
   - 不依赖外部服务

2. **环境变量**
   - 使用 JSON 批量导入
   - 多行文本（如私钥）使用 `\n` 转义

3. **域名配置**
   - 域名必须备案
   - 微信回调域只填域名，不带协议

4. **网络配置**
   - 短期：ENV 直传，避免 Secret Store
   - 长期：配置 NAT 网关获取固定出口IP

### 容器配置

```json
{
  "serviceName": "auth-center",
  "containerPort": 3000,
  "cpu": 0.5,
  "mem": 1,
  "minNum": 1,
  "maxNum": 3,
  "policyType": "cpu",
  "policyThreshold": 60,
  "initialDelaySeconds": 30
}
```

## 故障排查

### 常见问题

1. **版本一直异常**
   - 检查 initialDelaySeconds 是否足够长
   - 查看容器日志确认启动错误

2. **微信回调失败**
   - 确认回调域名只填域名部分
   - 检查 AppID/Secret 是否正确
   - 查看微信接口返回的错误码

3. **JWT验证失败**
   - 确认 ISSUER 配置正确
   - 检查私钥格式（PEM格式，正确转义）

4. **跨域问题**
   - 检查 CORS_ORIGIN 环境变量
   - 确认包含所有需要的域名

## 开发

```bash
# 安装依赖
npm install

# 本地开发
npm run dev

# 构建
npm run build

# 类型检查
npm run typecheck

# Docker构建
docker build -t auth-center .

# Docker运行
docker run -p 3000:3000 --env-file .env.production auth-center
```

## 架构说明

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│   Browser   │────▶│  Auth Center │────▶│   WeChat    │
└─────────────┘     └──────────────┘     └─────────────┘
                            │
                            ▼
                    ┌──────────────┐
                    │   TCB/Cloud  │
                    │   Database   │
                    └──────────────┘
```

## 安全考虑

- ✅ HTTPS 强制
- ✅ PKCE 防止授权码劫持
- ✅ CSRF 保护（state参数）
- ✅ 限流保护
- ✅ HttpOnly/Secure Cookie
- ✅ JWT 签名验证
- ✅ 密钥轮换支持

## License

MIT