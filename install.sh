#!/bin/bash

# ================= 默认配置 =================
DEFAULT_PORT=21011
DEFAULT_PASSWORD="admin"
INSTALL_DIR="/opt/proxyx"
# ===========================================

# --- 1. 基础信息获取 ---
echo "🚀 开始安装 VPS 代理服务 (Node.js 源码版)..."
echo "--------------------------------"

read -p "请设置服务端口 [默认 $DEFAULT_PORT]: " input_port
PORT=${input_port:-$DEFAULT_PORT}

read -p "请设置访问密码 [默认 $DEFAULT_PASSWORD]: " input_password
PASSWORD=${input_password:-$DEFAULT_PASSWORD}

echo "--------------------------------"

# --- 2. 环境检测 (Node.js) ---
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
# 如果正在运行，尝试停止
systemctl stop proxyx 2>/dev/null
rm -rf $INSTALL_DIR
mkdir -p $INSTALL_DIR/src

# 检查当前目录是否有源文件
if [ ! -f "src/server.js" ] || [ ! -f "package.json" ]; then
    echo "❌ 错误：当前目录下未找到 src/server.js 或 package.json"
    echo "请确保你是在项目根目录运行此脚本！"
    exit 1
fi

echo "📦 复制源文件..."
cp src/server.js $INSTALL_DIR/src/
cp package.json $INSTALL_DIR/

cd $INSTALL_DIR

# --- 4. 生成配置文件 (.env) [交互式配置] ---
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
    read -p "最大重定向次数 (防止死循环) [默认 5]: " input_mr
    VAR_MAX_REDIRECTS=${input_mr:-5}
    
    read -p "开启缓存 (推荐 true) [true/false, 默认 true]: " input_cache
    VAR_ENABLE_CACHE=${input_cache:-true}
    
    if [ "$VAR_ENABLE_CACHE" == "true" ]; then
        read -p "缓存时间 (单位: 秒) [默认 3600]: " input_ttl
        VAR_CACHE_TTL=${input_ttl:-3600}
    fi
    
    # 访问控制
    echo "--- 访问控制 (留空代表允许所有) ---"
    read -p "域名黑名单 (如: baidu.com,qq.com) [默认为空]: " input_bl
    VAR_BLACKLIST=${input_bl:-""}
    
    read -p "域名白名单 (设置后仅允许这些域名) [默认为空]: " input_wl
    VAR_WHITELIST=${input_wl:-""}
    
    read -p "仅允许访问的客户端 IP (白名单) [默认为空]: " input_allow_ips
    VAR_ALLOW_IPS=${input_allow_ips:-""}

    read -p "仅允许访问的国家代码 (如 CN,US) [默认为空]: " input_ac
    VAR_ALLOW_COUNTRIES=${input_ac:-""}

    # 额度与权限
    echo "--- 额度与权限 ---"
    read -p "每个 IP 每日最大请求次数 [默认 200]: " input_dl
    VAR_DAILY_LIMIT_COUNT=${input_dl:-200}
    
    read -p "管理员 IP (拥有重置额度、查看全站统计的权限) [默认 127.0.0.1]: " input_admin
    VAR_ADMIN_IPS=${input_admin:-"127.0.0.1"}
    
    read -p "免额度限制的 IP 白名单 (这些 IP 不扣费) [默认 127.0.0.1]: " input_ipwl
    VAR_IP_LIMIT_WHITELIST=${input_ipwl:-"127.0.0.1"}
    
    read -p "允许的引用来源 (免密访问) [默认 github.com,nodeseek.com]: " input_ref
    VAR_ALLOW_REFERER=${input_ref:-"github.com,nodeseek.com"}
    
    echo "--------------------------------"
fi

echo "📄 正在写入 .env 配置文件..."
cat > .env <<EOF
# --- 基础配置 ---
PORT=$PORT                  # 监听端口
PASSWORD=$PASSWORD             # 必填：访问密码 (请修改)
MAX_REDIRECTS=$VAR_MAX_REDIRECTS      # 最大重定向次数 (防止死循环)
ENABLE_CACHE=$VAR_ENABLE_CACHE           # 开启缓存 (推荐 true)
CACHE_TTL=$VAR_CACHE_TTL              # 缓存时间 (单位: 秒)

# --- 访问控制 (留空代表允许所有) ---
BLACKLIST=$VAR_BLACKLIST              # 域名黑名单 (如: baidu.com,qq.com)
WHITELIST=$VAR_WHITELIST              # 域名白名单 (设置后仅允许这些域名)
ALLOW_IPS=$VAR_ALLOW_IPS              # 仅允许访问的客户端 IP (白名单)
ALLOW_COUNTRIES=$VAR_ALLOW_COUNTRIES        # 仅允许访问的国家代码 (如 CN,US)

# --- 额度与权限 ---
DAILY_LIMIT_COUNT=$VAR_DAILY_LIMIT_COUNT      # 每个 IP 每日最大请求次数
ADMIN_IPS=$VAR_ADMIN_IPS              # 管理员 IP (拥有重置额度、查看全站统计的权限)
IP_LIMIT_WHITELIST=$VAR_IP_LIMIT_WHITELIST     # 免额度限制的 IP 白名单 (这些 IP 不扣费)
ALLOW_REFERER=$VAR_ALLOW_REFERER          # 允许的引用来源 (免密访问)
EOF

# --- 5. 安装依赖 ---
echo "📦 安装 NPM 依赖..."
npm install --production

# --- 6. 配置 Systemd ---
echo "⚙️ 配置 Systemd 服务..."
# 获取 node 的绝对路径
NODE_PATH=$(which node)
cat > /etc/systemd/system/proxyx.service <<EOF
[Unit]
Description=Proxy Server Node
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=$NODE_PATH src/server.js
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# --- 7. 自动放行防火墙端口 ---
echo "🛡️ 正在尝试开启防火墙端口: $PORT"
if command -v ufw >/dev/null 2>&1; then
    ufw allow $PORT/tcp >/dev/null 2>&1
elif command -v firewall-cmd >/dev/null 2>&1; then
    firewall-cmd --permanent --add-port=$PORT/tcp >/dev/null 2>&1
    firewall-cmd --reload >/dev/null 2>&1
else
    echo "⚠️ 未检测到 UFW 或 FirewallD，如果无法访问请手动检查防火墙设置。"
fi

# --- 8. 启动服务 ---
systemctl daemon-reload
systemctl enable proxyx
systemctl restart proxyx

# --- 9. 验证与输出 ---
PUBLIC_IP=$(curl -s ifconfig.me || echo "你的服务器IP")
echo "--------------------------------"
echo "✅ 安装完成！(Node.js 源码版)"
echo "🌐 访问地址: http://$PUBLIC_IP:$PORT/$PASSWORD/"
echo "📂 配置文件: $INSTALL_DIR/.env"
echo "🔍 查看状态: systemctl status proxyx"
echo "--------------------------------"
