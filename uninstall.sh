#!/bin/bash

# =========================================================
# ProxyX 全能卸载脚本 (Pro UI版)
# 兼容: Docker / Binary / Source (Node.js)
# =========================================================

# --- 颜色与格式定义 ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
PLAIN='\033[0m'
BOLD='\033[1m'

# --- 辅助函数：状态打印 ---
print_info() {
    printf "${BLUE}[INFO]${PLAIN} %-40s\n" "$1"
}

print_check() {
    printf "${CYAN}[检查]${PLAIN} %-40s " "$1..."
}

print_found() {
    printf "${YELLOW} -> 发现目标${PLAIN}\n"
}

print_not_found() {
    printf "${GREEN} -> 未安装 (跳过)${PLAIN}\n"
}

print_action() {
    printf "       ${RED}├─ [删除]${PLAIN} %-30s " "$1..."
}

print_success() {
    printf "${GREEN}[ OK ]${PLAIN}\n"
}

# --- 脚本开始 ---
clear
echo -e "${RED}=============================================================${PLAIN}"
echo -e "${RED}         ProxyX 全能卸载工具 (Docker/Systemd/File)          ${PLAIN}"
echo -e "${RED}=============================================================${PLAIN}"
echo "此脚本将彻底清理 ProxyX 的以下残留："
echo " 1. 运行中的 Docker 容器及相关镜像"
echo " 2. Systemd 系统服务 (守护进程)"
echo " 3. 配置文件与安装目录 (/opt/proxyx 等)"
echo ""

read -p "⚠️  确认要执行彻底卸载吗？(输入 y 确认): " confirm
if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
    echo "操作已取消。"
    exit 0
fi

echo ""

# =========================================================
# 1. 清理 Docker 部署
# =========================================================
echo -e "${BOLD}1. 正在扫描 Docker 环境...${PLAIN}"

if command -v docker &> /dev/null; then
    # --- 容器清理 ---
    CONTAINERS=("proxyx" "proxy-vps")
    for CON in "${CONTAINERS[@]}"; do
        print_check "容器: $CON"
        if docker ps -a --format '{{.Names}}' | grep -q "^${CON}$"; then
            print_found
            
            print_action "停止容器"
            docker stop "$CON" &> /dev/null
            print_success
            
            print_action "移除容器"
            docker rm "$CON" &> /dev/null
            print_success
        else
            print_not_found
        fi
    done

    # --- 镜像清理 ---
    print_check "相关 Docker 镜像"
    # 获取 ID，排除掉 grep 自身的干扰
    IMAGES=$(docker images --format "{{.ID}} {{.Repository}}" | grep "proxyx\|proxy-server-vps" | awk '{print $1}')
    
    if [ -n "$IMAGES" ]; then
        print_found
        # 转换为数组
        IMG_LIST=($IMAGES)
        for IMG in "${IMG_LIST[@]}"; do
            print_action "删除镜像 ($IMG)"
            docker rmi -f "$IMG" &> /dev/null
            print_success
        done
    else
        print_not_found
    fi
else
    print_info "未检测到 Docker，跳过 Docker 清理。"
fi

echo ""

# =========================================================
# 2. 清理 Systemd 服务
# =========================================================
echo -e "${BOLD}2. 正在扫描 Systemd 服务...${PLAIN}"

SERVICES=("proxyx" "proxy-bin" "proxy-node" "proxy-server")

for SVC in "${SERVICES[@]}"; do
    print_check "服务: ${SVC}.service"
    
    # 检查服务文件是否存在
    if [ -f "/etc/systemd/system/${SVC}.service" ] || systemctl list-unit-files | grep -q "^${SVC}.service"; then
        print_found
        
        # 检查是否正在运行
        if systemctl is-active --quiet "$SVC"; then
            print_action "停止运行中服务"
            systemctl stop "$SVC"
            print_success
        fi

        print_action "取消开机自启"
        systemctl disable "$SVC" &> /dev/null
        print_success

        print_action "删除 .service 文件"
        rm -f "/etc/systemd/system/${SVC}.service"
        print_success
    else
        print_not_found
    fi
done

# 重载 Systemd 防止报错
if [ -d "/run/systemd/system" ]; then
    systemctl daemon-reload &> /dev/null
fi

echo ""

# =========================================================
# 3. 清理文件系统
# =========================================================
echo -e "${BOLD}3. 正在扫描安装文件与残留...${PLAIN}"

# 定义要检查的目录和文件
TARGETS=(
    "/opt/proxyx" 
    "/opt/proxy-server"
    "/usr/local/bin/proxyx"
)

for TARGET in "${TARGETS[@]}"; do
    print_check "路径: $TARGET"
    
    if [ -e "$TARGET" ]; then
        print_found
        print_action "永久删除"
        rm -rf "$TARGET"
        print_success
    else
        print_not_found
    fi
done

echo ""

# =========================================================
# 4. 结束汇总
# =========================================================
echo -e "${GREEN}=============================================${PLAIN}"
echo -e "${GREEN}      🎉 卸载流程结束！清理完毕。             ${PLAIN}"
echo -e "${GREEN}=============================================${PLAIN}"
