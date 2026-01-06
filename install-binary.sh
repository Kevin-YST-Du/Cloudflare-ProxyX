#!/bin/bash

# ================= 默认配置 =================
DEFAULT_PORT=21011
DEFAULT_PASSWORD="admin"
INSTALL_DIR="/opt/proxy-server"
BINARY_NAME="proxy-server" # 脚本会找这个名字的文件
# ===========================================

# --- 0. 核心检查：目录下有没有二进制文件？ ---
if [ ! -f "$BINARY_NAME" ]; then
    echo "❌ 错误：当前目录下未找到名为 '$BINARY_NAME' 的文件。"
    echo "----------------------------------------------------"
    echo "请按以下步骤操作："
    echo "1. 从 GitHub Releases 下载对应的二进制文件 (如 proxy-server-vps-linux-x64)。"
    echo "2. 上传到当前目录。"
    echo "3. 将其重命名为 '$BINARY_NAME' (命令: mv proxy-server-vps-linux-x64 $BINARY_NAME)。"
    echo "4. 赋予执行权限 (命令: chmod +x $BINARY_NAME)。"
    echo "5. 再次运行本脚本。"
    echo "----------------------------------------------------"
    exit 1
fi

# --- 1. 交互式获取配置 ---
echo "🚀 开始安装 VPS 代理服务 (二进制版)..."
echo "--------------------------------"

# 询问端口
read -p "请设置服务端口 [默认 $DEFAULT_PORT]: " input_port
PORT=${input_port:-$DEFAULT_PORT}

# 询问密码
read -p "请设置访问密码 [默认 $DEFAULT_PASSWORD]: " input_password
PASSWORD=${input_password:-$DEFAULT_PASSWORD}

echo "--------------------------------"
echo "📝 即将安装配置: 端口=$PORT, 密码=$PASSWORD"
echo "--------------------------------"

# --- 2. 部署文件 ---
echo "📂 创建安装目录: $INSTALL_DIR"
# 如果存在旧的，清理旧文件
rm -rf $INSTALL_DIR
mkdir -p $INSTALL_DIR

# 复制二进制文件
echo "📦 安装二进制文件..."
cp "$BINARY_NAME" "$INSTALL_DIR/server"
chmod +x "$INSTALL_DIR/server"

# --- 3. 生成 .env 配置文件 ---
# 二进制文件启动时会自动读取同目录下的 .env
echo "📄 生成配置文件 (.env)..."
cat > "$INSTALL_DIR/.env" <<EOF
# --- 基础配置 ---
PORT=$PORT
PASSWORD=$PASSWORD
MAX_REDIRECTS=5
ENABLE_CACHE=true
CACHE_TTL=3600

# --- 访问控制 (留空代表允许所有) ---
BLACKLIST=
WHITELIST=
ALLOW_IPS=
ALLOW_COUNTRIES=

# --- 额度与权限 ---
DAILY_LIMIT_COUNT=200
ADMIN_IPS=127.0.0.1
IP_LIMIT_WHITELIST=127.0.0.1
EOF

# --- 4. 配置 Systemd 服务 (开机自启) ---
echo "⚙️ 配置 Systemd 服务..."
# 注意：WorkingDirectory 非常重要，确保程序能读到 .env
cat > /etc/systemd/system/proxy-bin.service <<EOF
[Unit]
Description=Proxy Server Binary
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
# 直接运行二进制文件，不需要 node 命令
ExecStart=$INSTALL_DIR/server
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# --- 5. 启动服务 ---
systemctl daemon-reload
systemctl enable proxy-bin
systemctl restart proxy-bin

# --- 6. 验证与输出 ---
# 获取公网 IP (如果失败则显示 localhost)
PUBLIC_IP=$(curl -s ifconfig.me || echo "你的服务器IP")

echo "--------------------------------"
echo "✅ 安装完成！服务已启动。"
echo "🌐 访问地址: http://$PUBLIC_IP:$PORT/$PASSWORD/"
echo "📂 程序目录: $INSTALL_DIR"
echo "📄 配置文件: $INSTALL_DIR/.env (修改配置后请重启服务)"
echo "🔄 重启命令: systemctl restart proxy-bin"
echo "🔍 查看状态: systemctl status proxy-bin"
echo "--------------------------------"
