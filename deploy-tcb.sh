#!/bin/bash

# TCB部署脚本 - auth-center
# 使用方式：./deploy-tcb.sh

set -e

echo "🚀 开始部署 auth-center 到腾讯云TCB..."

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 配置
ENV_ID="xiaojinpro-5ghvhq9v9875c1ea"
SERVICE_NAME="auth-center"
REGION="ap-shanghai"
IMAGE_TAG=$(git rev-parse --short HEAD 2>/dev/null || echo "latest")
IMAGE_URL="ccr.ccs.tencentyun.com/xiaojinpro/auth-center:${IMAGE_TAG}"

# 检查必要的环境变量
check_env() {
    local required_vars=(
        "TENCENTCLOUD_SECRETID"
        "TENCENTCLOUD_SECRETKEY"
        "WECHAT_OPEN_APPID"
        "WECHAT_OPEN_SECRET"
        "WECHAT_MP_APPID"
        "WECHAT_MP_SECRET"
        "JWT_PRIVATE_KEY"
        "COOKIE_SECRET"
    )
    
    echo "📋 检查环境变量..."
    local missing_vars=()
    
    for var in "${required_vars[@]}"; do
        if [ -z "${!var}" ]; then
            missing_vars+=($var)
        fi
    done
    
    if [ ${#missing_vars[@]} -gt 0 ]; then
        echo -e "${RED}❌ 缺少必要的环境变量：${missing_vars[*]}${NC}"
        echo -e "${YELLOW}请先设置环境变量或创建 .env.production 文件${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}✅ 环境变量检查通过${NC}"
}

# 同步数据库模型
sync_models() {
    echo "📊 同步数据库模型..."
    
    # 检查是否安装了TCB CLI
    if ! command -v tcb &> /dev/null; then
        echo -e "${YELLOW}未安装TCB CLI，正在安装...${NC}"
        npm install -g @cloudbase/cli
    fi
    
    # 登录TCB（如果未登录）
    if ! tcb env list 2>/dev/null | grep -q ${ENV_ID}; then
        echo "登录TCB..."
        tcb login --apiSecretId ${TENCENTCLOUD_SECRETID} --apiSecretKey ${TENCENTCLOUD_SECRETKEY}
    fi
    
    # 推送模型到线上
    echo "推送本地模型到 CloudBase..."
    tcb db push -e ${ENV_ID}
    
    echo -e "${GREEN}✅ 数据库模型同步成功${NC}"
}

# 构建Docker镜像
build_image() {
    echo "🔨 构建Docker镜像..."
    
    # 先构建TypeScript
    npm run build
    
    # 构建Docker镜像
    docker build -t ${IMAGE_URL} .
    
    echo -e "${GREEN}✅ Docker镜像构建成功：${IMAGE_URL}${NC}"
}

# 推送镜像到腾讯云镜像仓库
push_image() {
    echo "📤 推送镜像到腾讯云镜像仓库..."
    
    # 登录腾讯云镜像仓库
    docker login ccr.ccs.tencentyun.com -u ${TENCENTCLOUD_SECRETID} -p ${TENCENTCLOUD_SECRETKEY}
    
    # 推送镜像
    docker push ${IMAGE_URL}
    
    # 打标签为latest
    docker tag ${IMAGE_URL} ccr.ccs.tencentyun.com/xiaojinpro/auth-center:latest
    docker push ccr.ccs.tencentyun.com/xiaojinpro/auth-center:latest
    
    echo -e "${GREEN}✅ 镜像推送成功${NC}"
}

# 使用控制台部署（推荐）
deploy_console() {
    echo -e "${YELLOW}📌 请按以下步骤在TCB控制台完成部署：${NC}"
    echo ""
    echo "1. 访问TCB控制台：https://console.cloud.tencent.com/tcb/env/index"
    echo "2. 选择环境：${ENV_ID}"
    echo "3. 进入【云托管】→【服务列表】"
    echo "4. 点击服务：${SERVICE_NAME}"
    echo "5. 点击【新建版本】"
    echo "6. 选择【镜像拉取】"
    echo "7. 镜像地址：${IMAGE_URL}"
    echo "8. 端口：3000"
    echo "9. 环境变量：点击【JSON导入】，粘贴以下内容："
    echo ""
    cat <<EOF
{
  "NODE_ENV": "production",
  "PORT": "3000",
  "HOST": "0.0.0.0",
  "USE_SECRET_STORE": "false",
  "ISSUER": "https://auth.xiaojinpro.com",
  "TCB_ENV_ID": "${ENV_ID}",
  "TCB_REGION": "${REGION}",
  "MIGRATE_ON_STARTUP": "true",
  "REDIS_ENABLED": "false",
  "WECHAT_OPEN_APPID": "${WECHAT_OPEN_APPID}",
  "WECHAT_OPEN_SECRET": "${WECHAT_OPEN_SECRET}",
  "WECHAT_MP_APPID": "${WECHAT_MP_APPID}",
  "WECHAT_MP_SECRET": "${WECHAT_MP_SECRET}",
  "WECHAT_REDIRECT_URI": "https://auth.xiaojinpro.com/wechat/callback",
  "USE_UNIONID": "true",
  "JWT_PRIVATE_KEY": "${JWT_PRIVATE_KEY}",
  "JWT_KID": "kid-2025-01",
  "JWT_ACCESS_TOKEN_EXPIRES": "15m",
  "JWT_REFRESH_TOKEN_EXPIRES": "30d",
  "JWT_ID_TOKEN_EXPIRES": "1h",
  "COOKIE_SECRET": "${COOKIE_SECRET}",
  "COOKIE_SECURE": "true",
  "COOKIE_SAME_SITE": "lax",
  "SESSION_EXPIRES": "86400000",
  "REQUIRE_PKCE": "true",
  "AUTH_CODE_EXPIRES": "600",
  "CORS_ORIGIN": "https://xiaojinpro.com,https://*.xiaojinpro.com",
  "RATE_LIMIT_MAX": "100",
  "RATE_LIMIT_WINDOW": "60000",
  "CSRF_PROTECTION": "true"
}
EOF
    echo ""
    echo "10. 高级配置："
    echo "    - 初始延迟时间：30秒"
    echo "    - 健康检查路径：/health/ready"
    echo "    - CPU：0.5核"
    echo "    - 内存：1GB"
    echo "    - 最小实例数：1"
    echo "    - 最大实例数：3"
    echo ""
    echo "11. 点击【部署】"
    echo ""
    echo -e "${GREEN}部署完成后，访问：https://auth.xiaojinpro.com/.well-known/openid-configuration 验证${NC}"
}

# 使用CLI部署（备选）
deploy_cli() {
    echo "🚀 使用TCB CLI部署..."
    
    # 检查是否安装了TCB CLI
    if ! command -v tcb &> /dev/null; then
        echo -e "${YELLOW}未安装TCB CLI，正在安装...${NC}"
        npm install -g @cloudbase/cli
    fi
    
    # 登录TCB
    tcb login --apiSecretId ${TENCENTCLOUD_SECRETID} --apiSecretKey ${TENCENTCLOUD_SECRETKEY}
    
    # 部署
    tcb framework deploy --envId ${ENV_ID} --verbose
    
    echo -e "${GREEN}✅ 部署成功${NC}"
}

# 验证部署
verify_deployment() {
    echo "🔍 验证部署..."
    
    local endpoints=(
        "https://auth.xiaojinpro.com/health/ready"
        "https://auth.xiaojinpro.com/.well-known/openid-configuration"
        "https://auth.xiaojinpro.com/.well-known/jwks.json"
    )
    
    for endpoint in "${endpoints[@]}"; do
        echo -n "检查 ${endpoint}..."
        if curl -f -s -o /dev/null -w "%{http_code}" ${endpoint} | grep -q "200"; then
            echo -e " ${GREEN}✅${NC}"
        else
            echo -e " ${RED}❌${NC}"
        fi
    done
}

# 主流程
main() {
    echo "选择部署方式："
    echo "1. 控制台部署（推荐）"
    echo "2. CLI部署"
    echo "3. 仅构建和推送镜像"
    read -p "请选择 (1-3): " choice
    
    case $choice in
        1)
            check_env
            sync_models
            build_image
            push_image
            deploy_console
            ;;
        2)
            check_env
            sync_models
            build_image
            push_image
            deploy_cli
            verify_deployment
            ;;
        3)
            check_env
            sync_models
            build_image
            push_image
            echo -e "${GREEN}✅ 镜像已准备好，请在控制台手动部署${NC}"
            ;;
        *)
            echo -e "${RED}无效选择${NC}"
            exit 1
            ;;
    esac
}

# 加载环境变量
if [ -f .env.production ]; then
    echo "📦 加载 .env.production..."
    export $(cat .env.production | grep -v '^#' | xargs)
fi

# 运行主流程
main