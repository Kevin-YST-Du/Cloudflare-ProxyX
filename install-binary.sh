#!/bin/bash

# ================= 默认配置 =================
DEFAULT_PORT=21011
DEFAULT_PASSWORD="admin"
INSTALL_DIR="/opt/proxyx"
BINARY_NAME="proxyx" 
# ===========================================

# --- 0. 自动识别架构并寻找对应文件 ---
ARCH=$(uname -m)
case $ARCH in
    x86_64)  
        TARGET_FILE="proxyx-linux-x64"
        ;;
    aarch64|arm64) 
        TARGET_FILE="proxyx-linux-arm64"
        ;;
    *)
        echo "❌ 不支持的系统架构: $ARCH"
        exit 1
        ;;
esac

echo "🔍 检测到系统架构为: $ARCH"

# 检查匹配的文件是否存在
if [ -f "$TARGET_FILE" ]; then
    echo "📦 找到匹配的文件: $TARGET_FILE"
    echo "🔄 正在重命名为 $BINARY_NAME 并赋予权限..."
    cp "$TARGET_FILE" "$BINARY_NAME" # 使用 cp 保留原文件，防止报错
    chmod +x "$BINARY_NAME"
elif [ -f "$BINARY_NAME" ]; then
    echo "✅ 已存在 $BINARY_NAME，正在确保执行权限..."
    chmod +x "$BINARY_NAME"
else
    echo "❌ 错误：当前目录下未找到 $TARGET_FILE"
    echo "----------------------------------------------------"
    echo "请确认你已上传对应架构的文件。当前目录文件列表："
    ls -p | grep -v /
    echo "----------------------------------------------------"
    exit 1
fi

# --- 1. 交互式获取配置 ---
echo "🚀 开始安装 VPS 代理服务 (二进制版)..."
echo "--------------------------------"

read -p "请设置服务端口 [默认 $DEFAULT_PORT]: " input_port
PORT=${input_port:-$DEFAULT_PORT}

read -p "请设置访问密码 [默认 $DEFAULT_PASSWORD]: " input_password
PASSWORD=${input_password:-$DEFAULT_PASSWORD}

echo "--------------------------------"

# --- 2. 部署文件 ---
echo "📂 创建安装目录: $INSTALL_DIR"
rm -rf $INSTALL_DIR
mkdir -p $INSTALL_DIR

echo "📦 安装二进制文件..."
cp "$BINARY_NAME" "$INSTALL_DIR/server"
chmod +x "$INSTALL_DIR/server"

# --- 3. 生成 .env 配置文件 ---
cat > "$INSTALL_DIR/.env" <<EOF
PORT=$PORT                  # 监听端口
PASSWORD=$PASSWORD     # 访问密码
MAX_REDIRECTS=5             # 最大跳转次数
ENABLE_CACHE=true           # 是否开启缓存
CACHE_TTL=3600              # 缓存时长(秒)

# --- 访问控制 (留空代表允许所有) ---
BLACKLIST=                  # 黑名单
WHITELIST=                  # 白名单
ALLOW_IPS=                  # 允许的IP
ALLOW_COUNTRIES=            # 允许的国家/地区

# --- 额度与权限 ---
DAILY_LIMIT_COUNT=200       # 每日额度
ADMIN_IPS=127.0.0.1         # 管理员IP
IP_LIMIT_WHITELIST=127.0.0.1 # IP白名单
ALLOW_REFERER=github.com,nodeseek.com # 允许的来源域名
EOF

# --- 4. 配置 Systemd 服务 ---
cat > /etc/systemd/system/proxyx.service <<EOF
[Unit]
Description=Proxy Server Binary
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/server
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# --- 5. 自动放行防火墙端口 (解决打不开地址的问题) ---
echo "🛡️ 正在尝试开启防火墙端口: $PORT"
if command -v ufw >/dev/null 2>&1; then
    ufw allow $PORT/tcp >/dev/null 2>&1
elif command -v firewall-cmd >/dev/null 2>&1; then
    firewall-cmd --permanent --add-port=$PORT/tcp >/dev/null 2>&1
    firewall-cmd --reload >/dev/null 2>&1
fi

# --- 6. 启动服务 ---
systemctl daemon-reload
systemctl enable proxyx
systemctl restart proxyx

# --- 7. 输出结果 ---
PUBLIC_IP=$(curl -s ifconfig.me || echo "你的服务器IP")
echo "--------------------------------"
echo "✅ 安装完成！"
echo "🌐 访问地址: http://$PUBLIC_IP:$PORT/$PASSWORD/"
echo "--------------------------------"
