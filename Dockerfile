# 使用 Node.js 18 的 Alpine 轻量级镜像
FROM node:18-alpine

# 设置工作目录
WORKDIR /app

# [新增] 安装编译 SQLite 必须的系统依赖 (python3, make, g++)
RUN apk add --no-cache python3 make g++

# 1. 复制依赖文件
COPY package.json ./

# 2. 安装依赖 (此时会自动编译 better-sqlite3)
RUN npm install --production

# 3. 复制源代码
COPY src/server.js ./src/server.js

# [新增] 显式创建数据目录，防止权限问题
RUN mkdir -p /app/data

# 暴露端口
EXPOSE 21011

# 启动
CMD ["npm", "start"]
