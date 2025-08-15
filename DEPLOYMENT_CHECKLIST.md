# Auth Center 部署检查清单

支持 MySQL 和 TCB (Tencent Cloud Base) 两种部署模式

## 📋 部署前检查

### 1. 环境配置

**通用检查:**
- [ ] 确认环境变量已正确设置（见下方环境变量清单）
- [ ] 确认微信开放平台应用配置正确
- [ ] 确认域名和 SSL 证书配置

**MySQL 部署模式:**
- [ ] MySQL 8.0+ 数据库已创建
- [ ] 数据库用户权限已配置
- [ ] Redis 服务已配置（可选）

**TCB 部署模式:**
- [ ] CloudBase 项目已创建（环境ID: xiaojinpro-5ghvhq9v9875c1ea）
- [ ] 腾讯云镜像仓库权限已配置
- [ ] 数据库模型已同步

### 2. 数据库模型

- [ ] 确认本地 `database-schemas/` 目录包含最新模型定义
- [ ] 确认 `cloud-models.d.ts` 类型定义与模型匹配
- [ ] 通过 `tcb db push` 推送模型到 CloudBase

### 3. 代码构建

- [ ] 运行 `npm run build` 确保 TypeScript 编译成功
- [ ] 确认无 lint 错误和类型检查错误
- [ ] 确认 Docker 镜像可以正常构建

### 4. 无 Redis 模式验证

- [ ] 确认 `REDIS_ENABLED=false` 配置
- [ ] 确认令牌存储使用 CloudBase 模型
- [ ] 确认启动时清理任务正常运行
- [ ] 验证授权码和令牌的过期清理机制

## 🚀 部署步骤

### 方案一：控制台部署（推荐）

1. 运行部署脚本：
   ```bash
   ./deploy-tcb.sh
   选择选项 1
   ```

2. 按照控制台输出的指引在 TCB 控制台完成部署

### 方案二：CLI 部署

1. 运行部署脚本：
   ```bash
   ./deploy-tcb.sh
   选择选项 2
   ```

## 🔧 环境变量清单

### 必需环境变量

```bash
# 基础配置
NODE_ENV=production
PORT=3000
HOST=0.0.0.0
ISSUER=https://auth.xiaojinpro.com

# CloudBase 配置
TCB_ENV_ID=xiaojinpro-5ghvhq9v9875c1ea
TCB_REGION=ap-shanghai
TENCENTCLOUD_SECRETID=xxx
TENCENTCLOUD_SECRETKEY=xxx

# 迁移和 Redis 配置
MIGRATE_ON_STARTUP=true
REDIS_ENABLED=false

# 微信配置
WECHAT_OPEN_APPID=xxx
WECHAT_OPEN_SECRET=xxx
WECHAT_REDIRECT_URI=https://auth.xiaojinpro.com/wechat/callback

# JWT 配置
JWT_PRIVATE_KEY=xxx
JWT_ACCESS_TOKEN_EXPIRES=15m
JWT_REFRESH_TOKEN_EXPIRES=30d

# 安全配置
CORS_ORIGIN=https://xiaojinpro.com,https://*.xiaojinpro.com
COOKIE_SECRET=xxx
RATE_LIMIT_MAX=100
RATE_LIMIT_WINDOW=60000
```

### 可选环境变量

```bash
# 微信小程序（如需要）
WECHAT_MP_APPID=xxx
WECHAT_MP_SECRET=xxx

# PostgreSQL（如需要）
PG_CONNECTION_STRING=postgresql://...
PG_POOL_SIZE=20

# Redis（如启用）
REDIS_URL=redis://...

# 调试配置
LOG_LEVEL=info
DEBUG=false
```

## ✅ 部署后验证

### 1. 健康检查

访问以下端点确认服务正常：

- [ ] https://auth.xiaojinpro.com/health/ready
- [ ] https://auth.xiaojinpro.com/health/live
- [ ] https://auth.xiaojinpro.com/.well-known/openid-configuration
- [ ] https://auth.xiaojinpro.com/.well-known/jwks.json

### 2. 功能测试

- [ ] 微信登录流程正常
- [ ] OAuth 授权码流程正常
- [ ] Token 刷新流程正常
- [ ] JWK 公钥获取正常

### 3. 监控检查

- [ ] CloudBase 控制台显示服务运行正常
- [ ] 日志输出无错误信息
- [ ] 数据库连接正常
- [ ] 启动时数据初始化成功

### 4. 无 Redis 模式验证

- [ ] 令牌存储到 CloudBase 数据库正常
- [ ] 授权码一次性使用机制正常
- [ ] 过期令牌清理任务运行正常
- [ ] 令牌刷新和轮换机制正常

## 🔍 故障排查

### 常见问题

1. **服务启动失败**
   - 检查环境变量是否完整
   - 检查 CloudBase 环境权限
   - 查看服务日志

2. **数据库连接失败**
   - 确认 TCB_ENV_ID 正确
   - 确认腾讯云凭据有效
   - 检查模型是否正确推送

3. **微信登录失败**
   - 确认微信应用配置
   - 检查回调 URI 设置
   - 验证应用密钥

4. **JWT 验证失败**
   - 检查 JWT 私钥配置
   - 确认 JWK 初始化成功
   - 验证 Issuer 配置

5. **令牌管理问题（无 Redis 模式）**
   - 检查 CloudBase 模型操作权限
   - 验证过期清理任务是否运行
   - 确认令牌存储和查询逻辑

### 日志查看

```bash
# 通过 TCB CLI 查看日志
tcb cloudrun service log -e xiaojinpro-5ghvhq9v9875c1ea -s auth-center

# 或在 TCB 控制台查看
# https://console.cloud.tencent.com/tcb/env/index
```

## 📚 相关文档

- [CloudBase 云托管文档](https://docs.cloudbase.net/)
- [CloudBase 数据模型文档](https://docs.cloudbase.net/database/model)
- [OAuth 2.0 规范](https://tools.ietf.org/html/rfc6749)
- [OpenID Connect 规范](https://openid.net/connect/)
- [微信开放平台文档](https://developers.weixin.qq.com/doc/)

## 🔄 回滚计划

如需回滚到上一版本：

1. 在 TCB 控制台找到 auth-center 服务
2. 查看版本历史
3. 选择稳定版本进行回滚
4. 验证回滚后服务正常

## 📝 变更记录

- 2025-01-XX: 完成 CloudBase 模型适配
- 2025-01-XX: 添加启动时数据迁移
- 2025-01-XX: 移除 PostgreSQL 依赖
- 2025-01-XX: 实现无 Redis 模式
- 2025-01-XX: 更新部署脚本，加入模型推送步骤