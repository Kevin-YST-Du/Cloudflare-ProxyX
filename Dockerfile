# 使用 Node.js 18 的 Alpine 轻量级镜像
FROM node:18-alpine

# 设置工作目录
WORKDIR /app

# 1. 先复制依赖描述文件 (利用 Docker 缓存层加速构建)
COPY package.json ./

# 2. 安装生产环境依赖
RUN npm install --production

# 3. 复制源代码
# [关键点] 必须复制到 src 目录，因为 package.json 里写的是 "src/server.js"
COPY src/server.js ./src/server.js

# 暴露端口 21011
EXPOSE 21011

# 启动命令 (这会调用 package.json 中的 "start": "node src/server.js")
CMD ["npm", "start"]
