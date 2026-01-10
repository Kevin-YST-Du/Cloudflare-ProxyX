#!/bin/bash

# ================= 默认配置 =================
DEFAULT_PORT=21011
DEFAULT_PASSWORD="admin"
INSTALL_DIR="/opt/proxyx"
# ===========================================

# --- 1. 基础信息获取 ---
echo "🚀 开始安装 VPS 代理服务..."
echo "--------------------------------"

read -p "请设置服务端口 [默认 $DEFAULT_PORT]: " input_port
PORT=${input_port:-$DEFAULT_PORT}

read -p "请设置访问密码 [默认 $DEFAULT_PASSWORD]: " input_password
PASSWORD=${input_password:-$DEFAULT_PASSWORD}

echo "--------------------------------"

# --- 2. 环境检测 ---
if ! command -v node &> /dev/null; then
    echo "📦 未检测到 Node.js，正在安装..."
    if [ -x "$(command -v apt-get)" ]; then
        curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
        sudo apt-get install -y nodejs
    elif [ -x "$(command -v yum)" ]; then
        curl -fsSL https://rpm.nodesource.com/setup_18.x | sudo bash -
        sudo yum install -y nodejs
    elif [ -x "$(command -v apk)" ]; then
        apk add nodejs npm
    else
        echo "❌ 无法自动安装 Node.js，请手动安装后重试。"
        exit 1
    fi
fi

# --- 3. 部署文件 ---
echo "📂 创建安装目录: $INSTALL_DIR"
mkdir -p $INSTALL_DIR/src

if [ ! -f "src/server.js" ] || [ ! -f "package.json" ]; then
    echo "❌ 错误：当前目录下未找到 src/server.js 或 package.json"
    echo "请确保你是在项目根目录运行此脚本！"
    exit 1
fi

cp src/server.js $INSTALL_DIR/src/
cp package.json $INSTALL_DIR/

cd $INSTALL_DIR

# --- 4. 生成配置文件 (.env) [核心修改部分] ---
echo "--------------------------------"
echo "⚙️  配置文件生成向导"
echo "--------------------------------"
echo "请选择配置模式："
echo "   1) 快速默认 (仅使用刚才输入的端口和密码，其他均为默认值)"
echo "   2) 自定义配置 (逐项设置高级参数)"
echo "--------------------------------"
read -p "请输入选项 [1/2, 默认 1]: " config_choice
config_choice=${config_choice:-1}

# 初始化变量为默认值
VAR_MAX_REDIRECTS=5
VAR_ENABLE_CACHE=true
VAR_CACHE_TTL=3600
VAR_BLACKLIST=""
VAR_WHITELIST=""
VAR_ALLOW_IPS=""
VAR_ALLOW_COUNTRIES=""
VAR_DAILY_LIMIT_COUNT=200
VAR_ADMIN_IPS="127.0.0.1"
VAR_IP_LIMIT_WHITELIST="127.0.0.1"
VAR_ALLOW_REFERER="github.com,nodeseek.com"

if [ "$config_choice" == "2" ]; then
    echo -e "\n--- 进入高级配置模式 (直接回车保持默认值) ---"
    
    # 基础配置
    read -p "最大重定向次数 (MAX_REDIRECTS) [默认 5]: " input_mr
    VAR_MAX_REDIRECTS=${input_mr:-5}
    
    read -p "开启缓存 (ENABLE_CACHE) [true/false, 默认 true]: " input_cache
    VAR_ENABLE_CACHE=${input_cache:-true}
    
    if [ "$VAR_ENABLE_CACHE" == "true" ]; then
        read -p "缓存时长秒数 (CACHE_TTL) [默认 3600]: " input_ttl
        VAR_CACHE_TTL=${input_ttl:-3600}
    fi
    
    # 访问控制
    echo "--- 访问控制 (留空代表不限制) ---"
    read -p "黑名单 (BLACKLIST) [逗号分隔]: " input_bl
    VAR_BLACKLIST=${input_bl:-""}
    
    read -p "白名单 (WHITELIST) [逗号分隔]: " input_wl
    VAR_WHITELIST=${input_wl:-""}
    
    read -p "允许的国家代码 (ALLOW_COUNTRIES) [例如 CN,US]: " input_ac
    VAR_ALLOW_COUNTRIES=${input_ac:-""}

    # 额度与权限
    echo "--- 额度与权限 ---"
    read -p "每日请求限额 (DAILY_LIMIT_COUNT) [默认 200]: " input_dl
    VAR_DAILY_LIMIT_COUNT=${input_dl:-200}
    
    read -p "管理员IP (ADMIN_IPS) [默认 127.0.0.1]: " input_admin
    VAR_ADMIN_IPS=${input_admin:-"127.0.0.1"}
    
    read -p "限流白名单IP (IP_LIMIT_WHITELIST) [默认 127.0.0.1]: " input_ipwl
    VAR_IP_LIMIT_WHITELIST=${input_ipwl:-"127.0.0.1"}
    
    read -p "允许的 Referer 域名 (ALLOW_REFERER) [默认 github.com,nodeseek.com]: " input_ref
    VAR_ALLOW_REFERER=${input_ref:-"github.com,nodeseek.com"}
    
    echo "--------------------------------"
fi

echo "📄 正在写入 .env 配置文件..."
cat > .env <<EOF
# --- 基础配置 ---
PORT=$PORT
PASSWORD=$PASSWORD
MAX_REDIRECTS=$VAR_MAX_REDIRECTS
ENABLE_CACHE=$VAR_ENABLE_CACHE
CACHE_TTL=$VAR_CACHE_TTL

# --- 访问控制 ---
BLACKLIST=$VAR_BLACKLIST
WHITELIST=$VAR_WHITELIST
ALLOW_IPS=$VAR_ALLOW_IPS
ALLOW_COUNTRIES=$VAR_ALLOW_COUNTRIES

# --- 额度与权限 ---
DAILY_LIMIT_COUNT=$VAR_DAILY_LIMIT_COUNT
ADMIN_IPS=$VAR_ADMIN_IPS
IP_LIMIT_WHITELIST=$VAR_IP_LIMIT_WHITELIST
ALLOW_REFERER=$VAR_ALLOW_REFERER
EOF

# --- 5. 安装依赖 ---
echo "📦 安装 NPM 依赖..."
npm install --production

# --- 6. 配置 Systemd ---
echo "⚙️ 配置 Systemd 服务..."
cat > /etc/systemd/system/proxyx.service <<EOF
[Unit]
Description=Proxy Server Node
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=$(which node) src/server.js
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# --- 7. 启动服务 ---
systemctl daemon-reload
systemctl enable proxyx
systemctl restart proxyx

# --- 8. 验证与输出 ---
echo "--------------------------------"
echo "✅ 安装完成！服务已启动。"
echo "🌐 访问地址: http://$(curl -s ifconfig.me):$PORT/$PASSWORD/"
echo "📂 配置文件: $INSTALL_DIR/.env (如需修改，编辑此文件后运行 systemctl restart proxyx)"
echo "🔍 查看状态: systemctl status proxyx"
echo "--------------------------------"