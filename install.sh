#!/bin/bash

# ================= 默认配置 =================
DEFAULT_PORT=21011
DEFAULT_PASSWORD="admin"
INSTALL_DIR="/opt/proxyx"
# ===========================================

# --- 1. 交互式获取配置 ---
echo "🚀 开始安装 VPS 代理服务..."
echo "--------------------------------"

read -p "请设置服务端口 [默认 $DEFAULT_PORT]: " input_port
PORT=${input_port:-$DEFAULT_PORT}

read -p "请设置访问密码 [默认 $DEFAULT_PASSWORD]: " input_password
PASSWORD=${input_password:-$DEFAULT_PASSWORD}

echo "--------------------------------"
echo "📝 即将安装配置: 端口=$PORT, 密码=$PASSWORD"
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

# --- 4. 生成全量 .env 文件 (包含你要求的所有字段) ---
echo "📄 生成配置文件 (.env)..."
cat > .env <<EOF
# --- 基础配置 ---
PORT=$PORT
PASSWORD=$PASSWORD
MAX_REDIRECTS=5
ENABLE_CACHE=true
CACHE_TTL=3600

# # --- 访问控制 (留空代表允许所有) ---
BLACKLIST=
WHITELIST=
ALLOW_IPS=
ALLOW_COUNTRIES=
ALLOW_REFERER=github.com,nodeseek.com

# --- 额度与权限 ---
DAILY_LIMIT_COUNT=200
ADMIN_IPS=127.0.0.1
IP_LIMIT_WHITELIST=127.0.0.1
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
echo "📂 配置文件: $INSTALL_DIR/.env (修改后需重启服务: systemctl restart proxyx)"
echo "🔍 查看状态: systemctl status proxyx"
echo "--------------------------------"
