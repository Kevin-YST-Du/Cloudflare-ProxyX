#!/bin/bash

# =================配置区=================
INSTALL_DIR="/opt/proxy-server"
PORT=21011
PASSWORD="123456"
# =======================================

echo "🚀 开始安装 VPS 代理服务..."

# 1. 检测是否安装了 Node.js
if ! command -v node &> /dev/null; then
    echo "📦 未检测到 Node.js，正在安装..."
    curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
    if [ -x "$(command -v apt-get)" ]; then
        sudo apt-get install -y nodejs
    elif [ -x "$(command -v yum)" ]; then
        sudo yum install -y nodejs
    fi
else
    echo "✅ Node.js 已安装: $(node -v)"
fi

# 2. 创建目录
mkdir -p $INSTALL_DIR/src
# 假设脚本在项目根目录运行，复制文件过去
if [ -f "src/server.js" ] && [ -f "package.json" ]; then
    cp src/server.js $INSTALL_DIR/src/
    cp package.json $INSTALL_DIR/
else
    echo "❌ 错误：未找到源文件，请确保你在项目根目录运行此脚本。"
    exit 1
fi

cd $INSTALL_DIR

# 3. 安装依赖
echo "📦 安装 NPM 依赖..."
npm install --production

# 4. 创建 Systemd 服务文件
echo "⚙️ 配置 Systemd 服务..."
cat > /etc/systemd/system/proxy-node.service <<EOF
[Unit]
Description=Proxy Server Node
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=$(which node) src/server.js
Environment="PORT=$PORT"
Environment="PASSWORD=$PASSWORD"
Environment="ENABLE_CACHE=true"
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# 5. 启动服务
systemctl daemon-reload
systemctl enable proxy-node
systemctl restart proxy-node

echo "✅ 安装完成！"
echo "🌐 服务端口: $PORT"
echo "🔍 查看状态: systemctl status proxy-node"
