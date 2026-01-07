#!/bin/bash

# =========================================================
# ProxyX 全能卸载脚本
# 兼容: Docker / Binary / Source (Node.js)
# =========================================================

# 定义颜色
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${RED}====================================================${NC}"
echo -e "${RED}       ProxyX 全能卸载脚本 (Docker/Binary/Source)    ${NC}"
echo -e "${RED}====================================================${NC}"
echo "此脚本将执行以下操作："
echo "1. 停止并删除 ProxyX 相关的 Docker 容器。"
echo "2. 停止并删除 Systemd 后台服务 (proxyx, proxy-bin, proxy-node)。"
echo "3. 永久删除安装目录 (/opt/proxyx) 和配置文件。"
echo ""

read -p "⚠️  确认要执行卸载吗？(y/n): " confirm
if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
    echo "操作已取消。"
    exit 0
fi

echo ""

# =========================================================
# 1. 清理 Docker 部署
# =========================================================
if command -v docker &> /dev/null; then
    echo -e "${CYAN}🐳 正在检查 Docker 容器...${NC}"
    
    # 定义可能存在的容器名 (新旧版本)
    CONTAINERS=("proxyx" "proxy-vps")
    
    for CON in "${CONTAINERS[@]}"; do
        if docker ps -a --format '{{.Names}}' | grep -q "^${CON}$"; then
            echo -e "${YELLOW}   发现容器: ${CON}${NC}"
            echo "   正在停止..."
            docker stop "$CON" &> /dev/null
            echo "   正在删除..."
            docker rm "$CON" &> /dev/null
            echo -e "${GREEN}   ✅ 容器 ${CON} 已移除。${NC}"
        fi
    done

    # 检查并清理相关镜像
    echo -e "${CYAN}🐳 正在检查 Docker 镜像...${NC}"
    # 匹配包含 proxyx 或 proxy-server-vps 的镜像
    IMAGES=$(docker images | grep "proxyx\|proxy-server-vps" | awk '{print $3}')
    
    if [ -n "$IMAGES" ]; then
        echo -e "${YELLOW}   发现相关镜像 ID (可能会有多个):${NC}"
        echo "$IMAGES"
        docker rmi -f $IMAGES &> /dev/null
        echo -e "${GREEN}   ✅ 相关 Docker 镜像已清理。${NC}"
    else
        echo "   未发现相关镜像，跳过。"
    fi
else
    echo "未检测到 Docker 环境，跳过 Docker 清理步骤。"
fi

echo ""

# =========================================================
# 2. 清理 Systemd 服务 (二进制/源码版)
# =========================================================
echo -e "${CYAN}⚙️  正在检查 Systemd 服务...${NC}"

# 定义可能存在的服务名 (涵盖所有历史版本: proxyx, proxy-bin, proxy-node, proxy-server)
SERVICES=("proxyx" "proxy-bin" "proxy-node" "proxy-server")

for SVC in "${SERVICES[@]}"; do
    if systemctl list-unit-files | grep -q "^${SVC}.service"; then
        echo -e "${YELLOW}   发现服务: ${SVC}.service${NC}"
        
        echo "   正在停止服务..."
        systemctl stop "$SVC"
        
        echo "   正在禁用开机自启..."
        systemctl disable "$SVC" &> /dev/null
        
        echo "   正在删除服务文件..."
        rm -f "/etc/systemd/system/${SVC}.service"
        
        echo -e "${GREEN}   ✅ 服务 ${SVC} 已卸载。${NC}"
    fi
done

# 重载 Systemd 配置
systemctl daemon-reload

echo ""

# =========================================================
# 3. 清理文件系统
# =========================================================
echo -e "${CYAN}📂 正在清理安装文件...${NC}"

# 定义可能存在的安装目录 (新旧路径)
DIRS=("/opt/proxyx" "/opt/proxy-server")

for DIR in "${DIRS[@]}"; do
    if [ -d "$DIR" ]; then
        echo -e "${YELLOW}   发现目录: ${DIR}${NC}"
        rm -rf "$DIR"
        echo -e "${GREEN}   ✅ 目录已永久删除。${NC}"
    fi
done

# =========================================================
# 4. 结束
# =========================================================
echo ""
echo -e "${GREEN}=============================================${NC}"
echo -e "${GREEN}      🎉 卸载完成！ProxyX 已彻底清除。        ${NC}"
echo -e "${GREEN}=============================================${NC}"