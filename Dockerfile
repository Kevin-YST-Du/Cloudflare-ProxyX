# 使用 Node.js 18 的 Alpine 轻量级镜像
FROM node:18-alpine

# 设置工作目录
WORKDIR /app

# 复制项目依赖描述文件
COPY package.json ./

# 安装生产环境依赖
RUN npm install --production

# 复制源代码 (假设代码在 src 目录)
COPY src/server.js ./src/server.js

# 暴露端口 21011
EXPOSE 21011

# 启动容器时运行的命令
CMD ["node", "src/server.js"]
