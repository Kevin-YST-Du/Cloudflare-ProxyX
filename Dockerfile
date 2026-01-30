# 使用 Node.js 18 Alpine
FROM node:18-alpine

# 设置工作目录
WORKDIR /app

# [新增] 安装构建 SQLite 必须的依赖 (Python3, Make, G++)
RUN apk add --no-cache python3 make g++

# 1. 复制依赖文件
COPY package.json ./

# 2. 安装依赖 (会自动编译 SQLite)
RUN npm install --production

# 3. 复制源代码
COPY src/server.js ./src/server.js

# [新增] 创建数据持久化目录
RUN mkdir -p /app/data

# 暴露端口
EXPOSE 21011

# 启动
CMD ["npm", "start"]
