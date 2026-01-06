/**
 * -----------------------------------------------------------------------------------------
 * VPS Node.js 版: 终极 Docker & Linux 代理 (v4.5 - 全配置动态版)
 * -----------------------------------------------------------------------------------------
 * 运行环境: Node.js v18+
 * 功能:
 * 1. 自动加载同目录下的 .env 配置文件 (支持二进制/脚本/Docker)。
 * 2. 包含你要求的所有配置项 (黑白名单、管理员IP、额度限制等)。
 * 3. 递归模式强制文本处理 + 缓存。
 * 4. 仪表盘 UI 样式统一。
 * -----------------------------------------------------------------------------------------
 */

const path = require('path');
const fs = require('fs');

// --- 1. 智能加载 .env 配置文件 ---
// 逻辑: 优先查找可执行文件同级目录下的 .env，如果没有则查找当前目录
const envPath = process.pkg 
    ? path.join(path.dirname(process.execPath), '.env') 
    : path.join(__dirname, '.env');

if (fs.existsSync(envPath)) {
    console.log(`[Config] Loading config from: ${envPath}`);
    require('dotenv').config({ path: envPath });
} else {
    // 兼容 Docker (环境变量直接注入) 或普通 Node 运行
    require('dotenv').config(); 
}

const express = require('express');
const NodeCache = require('node-cache');
const http = require('http');
const https = require('https');

// --- 初始化 Express 和 缓存 ---
const app = express();
// 读取 CACHE_TTL 环境变量，默认 3600 秒
const cacheTTL = parseInt(process.env.CACHE_TTL || "3600");
const myCache = new NodeCache({ stdTTL: cacheTTL }); 
const PORT = process.env.PORT || 21011; 

// --- 内存级频率限制存储 ---
const rateLimitStore = new Map();

// ==============================================================================
// 2. 全局配置 (严格映射你要求的所有字段)
// ==============================================================================

// 辅助函数: 将字符串按逗号或换行符分割成数组，并去空
const parseList = (val, defaultVal) => {
    const source = val || defaultVal || "";
    return source.split(/[\n,]/).map(s => s.trim()).filter(s => s.length > 0);
};

const CONFIG = {
    // --- 基础配置 ---
    // 访问密码
    PASSWORD: process.env.PASSWORD || "123456",
    
    // 最大重定向次数
    MAX_REDIRECTS: parseInt(process.env.MAX_REDIRECTS || "5"),
    
    // 是否开启缓存 (字符串转布尔)
    ENABLE_CACHE: (process.env.ENABLE_CACHE || "true") === "true",
    
    // 缓存时间 (秒)
    CACHE_TTL: cacheTTL,
    
    // --- 访问控制 (安全设置) ---
    // 域名黑名单
    BLACKLIST: parseList(process.env.BLACKLIST, ""),
    
    // 域名白名单 (若不为空，则只允许白名单内的域名)
    WHITELIST: parseList(process.env.WHITELIST, ""),
    
    // 允许访问的客户端 IP
    ALLOW_IPS: parseList(process.env.ALLOW_IPS, ""),
    
    // 允许访问的国家代码
    ALLOW_COUNTRIES: parseList(process.env.ALLOW_COUNTRIES, ""),
    
    // --- 额度限制 ---
    // 每日最大请求次数
    DAILY_LIMIT_COUNT: parseInt(process.env.DAILY_LIMIT_COUNT || "200"),
    
    // --- 权限管理 ---
    // 管理员 IP (拥有重置、统计权限)
    ADMIN_IPS: parseList(process.env.ADMIN_IPS, "127.0.0.1"),
    
    // 免额度 IP 白名单 (不计入每日限制)
    IP_LIMIT_WHITELIST: parseList(process.env.IP_LIMIT_WHITELIST, "127.0.0.1"),
};

// 打印当前生效的关键配置 (调试用)
console.log("---------------------------------------");
console.log("Current Configuration:");
console.log(`PORT: ${PORT}`);
console.log(`PASSWORD: ${CONFIG.PASSWORD}`);
console.log(`ENABLE_CACHE: ${CONFIG.ENABLE_CACHE}`);
console.log(`ADMIN_IPS: ${JSON.stringify(CONFIG.ADMIN_IPS)}`);
console.log("---------------------------------------");

// Docker 上游配置
const REGISTRY_MAP = {
    'ghcr.io': 'https://ghcr.io',
    'quay.io': 'https://quay.io',
    'gcr.io': 'https://gcr.io',
    'k8s.gcr.io': 'https://k8s.gcr.io',
    'registry.k8s.io': 'https://registry.k8s.io',
    'docker.cloudsmith.io': 'https://docker.cloudsmith.io',
    'nvcr.io': 'https://nvcr.io'
};

// Linux 镜像源配置
const LINUX_MIRRORS = {
    'ubuntu': 'http://archive.ubuntu.com/ubuntu',
    'ubuntu-security': 'http://security.ubuntu.com/ubuntu',
    'debian': 'http://deb.debian.org/debian',
    'debian-security': 'http://security.debian.org/debian-security',
    'centos': 'https://vault.centos.org',
    'centos-stream': 'http://mirror.stream.centos.org',
    'rockylinux': 'https://download.rockylinux.org/pub/rocky',
    'almalinux': 'https://repo.almalinux.org/almalinux',
    'fedora': 'https://download.fedoraproject.org/pub/fedora/linux',
    'alpine': 'http://dl-cdn.alpinelinux.org/alpine',
    'kali': 'http://http.kali.org/kali',
    'archlinux': 'https://geo.mirror.pkgbuild.com',
    'termux': 'https://packages.termux.org/apt/termux-main'
};

const LIGHTNING_SVG = `<svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M13 2L3 14H12L11 22L21 10H12L13 2Z" stroke="#F59E0B" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>`;

// ==============================================================================
// 3. 中间件
// ==============================================================================

const getClientIP = (req) => {
    return req.headers['x-forwarded-for'] || req.socket.remoteAddress || '0.0.0.0';
};

const getDate = () => new Date(new Date().getTime() + 28800000).toISOString().split('T')[0];

const checkRateLimit = (req, res, next) => {
    const ip = getClientIP(req);
    if (CONFIG.IP_LIMIT_WHITELIST.includes(ip)) return next();
    if (req.path === '/' || req.path === '/favicon.ico' || req.path === '/robots.txt') return next();

    const today = getDate();
    const key = `${ip}:${today}`;
    const count = rateLimitStore.get(key) || 0;

    if (count >= CONFIG.DAILY_LIMIT_COUNT) {
        return res.status(429).send(`⚠️ Daily Limit Exceeded: ${count}/${CONFIG.DAILY_LIMIT_COUNT}`);
    }
    
    rateLimitStore.set(key, count + 1);
    next();
};

app.use((req, res, next) => {
    res.header("Access-Control-Allow-Origin", "*");
    res.header("Access-Control-Allow-Methods", "GET, POST, OPTIONS, HEAD");
    res.header("Access-Control-Allow-Headers", "*");
    res.header("Docker-Distribution-API-Version", "registry/2.0");
    if (req.method === 'OPTIONS') return res.sendStatus(200);
    next();
});

app.use((req, res, next) => {
    const ip = getClientIP(req);
    if (CONFIG.ALLOW_IPS.length > 0 && !CONFIG.ALLOW_IPS.includes(ip)) {
        return res.status(403).send('Access Denied (IP Not Allowed)');
    }
    next();
});

app.use(checkRateLimit);
app.use(express.raw({ type: '*/*', limit: '50mb' }));

// ==============================================================================
// 4. 业务逻辑
// ==============================================================================

app.get('/robots.txt', (req, res) => res.type('text/plain').send("User-agent: *\nDisallow: /"));
app.get('/favicon.ico', (req, res) => res.type('image/svg+xml').send(LIGHTNING_SVG));

// --- Token ---
app.get('/token', async (req, res) => {
    const scope = req.query.scope;
    let upstreamAuthUrl = 'https://auth.docker.io/token';
    for (const [domain, _] of Object.entries(REGISTRY_MAP)) {
        if (scope && scope.includes(domain)) {
            upstreamAuthUrl = `https://${domain}/token`;
            break;
        }
    }
    const newUrl = new URL(upstreamAuthUrl);
    newUrl.search = new URLSearchParams(req.query).toString();
    if (upstreamAuthUrl === 'https://auth.docker.io/token') {
        newUrl.searchParams.set('service', 'registry.docker.io');
        if (scope && scope.startsWith('repository:')) {
            const parts = scope.split(':');
            if (parts.length >= 3 && !parts[1].includes('/') && !Object.keys(REGISTRY_MAP).some(d => parts[1].startsWith(d))) {
                parts[1] = 'library/' + parts[1];
                newUrl.searchParams.set('scope', parts.join(':'));
            }
        }
    }
    try {
        const upstreamRes = await fetch(newUrl, {
            headers: { 'User-Agent': 'Docker-Client/24.0.5 (linux)', 'Host': newUrl.hostname }
        });
        res.status(upstreamRes.status);
        upstreamRes.headers.forEach((v, k) => res.setHeader(k, v));
        const data = await upstreamRes.arrayBuffer();
        res.send(Buffer.from(data));
    } catch (e) { res.status(500).send(e.message); }
});

// --- Docker V2 ---
app.use('/v2', async (req, res) => {
    let path = req.path;
    if (path === '/') path = '';
    let targetDomain = 'registry-1.docker.io'; 
    let upstream = 'https://registry-1.docker.io';

    if (path === '' || path === '/') {
        try {
            const rootReq = await fetch('https://registry-1.docker.io/v2/', { method: req.method, headers: req.headers });
            if (rootReq.status === 401) {
                const wwwAuth = rootReq.headers.get('WWW-Authenticate');
                if (wwwAuth) {
                    const workerOrigin = `${req.protocol}://${req.get('host')}`;
                    res.setHeader('WWW-Authenticate', wwwAuth.replace(/realm="([^"]+)"/, `realm="${workerOrigin}/token"`));
                }
                return res.status(401).send(await rootReq.text());
            }
            return res.status(rootReq.status).send(await rootReq.text());
        } catch (e) { return res.status(500).send(e.message); }
    }

    const pathParts = path.replace(/^\//, '').split('/');
    if (REGISTRY_MAP[pathParts[0]]) {
        targetDomain = pathParts[0];
        upstream = REGISTRY_MAP[pathParts[0]];
        path = '/' + pathParts.slice(1).join('/');
    } else if (targetDomain === 'registry-1.docker.io') {
        const p0 = pathParts[0];
        if (pathParts.length > 1 && !p0.includes('.') && p0 !== 'manifests' && p0 !== 'blobs' && p0 !== 'tags' && !p0.startsWith('sha256:')) {
            if (p0 !== 'library') {
                 if (pathParts[1] === 'manifests' || pathParts[1] === 'blobs' || pathParts[1] === 'tags') {
                     path = '/library' + path;
                 }
            }
        }
    }

    const targetUrl = `${upstream}/v2${path}`;
    const headers = { ...req.headers };
    headers['Host'] = targetDomain;
    headers['User-Agent'] = 'Docker-Client/24.0.5 (linux)';
    delete headers['host']; 
    delete headers['connection'];

    try {
        const response = await fetch(targetUrl, {
            method: req.method,
            headers: headers,
            body: ['GET', 'HEAD'].includes(req.method) ? undefined : req.body,
            redirect: 'manual'
        });

        if (response.status === 401) {
            const wwwAuth = response.headers.get('WWW-Authenticate');
            if (wwwAuth) {
                const workerOrigin = `${req.protocol}://${req.get('host')}`;
                res.setHeader('WWW-Authenticate', wwwAuth.replace(/realm="([^"]+)"/, `realm="${workerOrigin}/token"`));
            }
            return res.status(401).send(await response.text());
        }

        if ([301, 302, 303, 307, 308].includes(response.status)) {
            const location = response.headers.get('Location');
            if (location) {
                const blobResp = await fetch(location, { method: 'GET', headers: { 'User-Agent': 'Docker-Client/24.0.5 (linux)' } });
                res.status(blobResp.status);
                blobResp.headers.forEach((v, k) => {
                    if (k !== 'content-encoding' && k !== 'transfer-encoding') res.setHeader(k, v);
                });
                const arrayBuffer = await blobResp.arrayBuffer();
                res.send(Buffer.from(arrayBuffer));
                return;
            }
        }

        res.status(response.status);
        response.headers.forEach((v, k) => res.setHeader(k, v));
        const arrayBuffer = await response.arrayBuffer();
        res.send(Buffer.from(arrayBuffer));
    } catch (e) { res.status(502).send(`Docker Proxy Error: ${e.message}`); }
});

// --- 通用代理 ---
// 支持 /密码 和 /密码/ 两种访问方式
app.all(['/:password', '/:password/*'], async (req, res) => {
    const password = req.params.password;
    // req.params[0] 是通配符 * 的内容，如果没有通配符则为 undefined
    let subPath = req.params[0] || ""; 

    if (password !== CONFIG.PASSWORD) {
        return res.status(404).send("404 Not Found");
    }

    const clientIP = getClientIP(req);

    if (subPath === "reset") {
        if (!CONFIG.ADMIN_IPS.includes(clientIP)) return res.status(403).send("Forbidden");
        rateLimitStore.delete(`${clientIP}:${getDate()}`);
        return res.json({ status: "success" });
    }
    if (subPath === "reset-all") {
        if (!CONFIG.ADMIN_IPS.includes(clientIP)) return res.status(403).send("Forbidden");
        rateLimitStore.clear();
        return res.json({ status: "success" });
    }
    if (subPath === "stats") {
        if (!CONFIG.ADMIN_IPS.includes(clientIP)) return res.status(403).send("Forbidden");
        const stats = [];
        const today = getDate();
        rateLimitStore.forEach((val, key) => {
            if(key.endsWith(today)) stats.push({ ip: key.split(':')[0], count: val });
        });
        stats.sort((a, b) => b.count - a.count);
        return res.json({ status: "success", data: { totalRequests: 0, uniqueIps: stats.length, details: stats } });
    }

    if (!subPath) {
        const count = rateLimitStore.get(`${clientIP}:${getDate()}`) || 0;
        return res.send(renderDashboard(req.hostname, CONFIG.PASSWORD, clientIP, count, CONFIG.DAILY_LIMIT_COUNT, CONFIG.ADMIN_IPS));
    }

    const sortedMirrors = Object.keys(LINUX_MIRRORS).sort((a, b) => b.length - a.length);
    const linuxDistro = sortedMirrors.find(k => subPath.startsWith(k + '/') || subPath === k);

    if (linuxDistro) {
        const realPath = subPath.replace(linuxDistro, '').replace(/^\//, '');
        const upstreamBase = LINUX_MIRRORS[linuxDistro];
        const targetUrl = upstreamBase.endsWith('/') ? upstreamBase + realPath : upstreamBase + '/' + realPath;
        try {
            const headers = { ...req.headers };
            delete headers['host'];
            const linuxRes = await fetch(targetUrl, { method: req.method, headers: headers, redirect: 'follow' });
            res.status(linuxRes.status);
            linuxRes.headers.forEach((v, k) => res.setHeader(k, v));
            const arrayBuffer = await linuxRes.arrayBuffer();
            res.send(Buffer.from(arrayBuffer));
            return;
        } catch (e) { return res.status(502).send(`Linux Mirror Error: ${e.message}`); }
    }

    let proxyMode = 'raw';
    let targetUrlStr = subPath;

    if (subPath.startsWith('r/') || subPath === 'r') {
        proxyMode = 'recursive';
        targetUrlStr = subPath.replace(/^r\/?/, "");
    }

    if (!targetUrlStr.startsWith("http")) {
        targetUrlStr = 'https://' + targetUrlStr.replace(/^(https?):\/+/, '$1://');
    }

    const cacheKey = req.originalUrl;
    if (proxyMode === 'recursive' && CONFIG.ENABLE_CACHE) {
        const cachedBody = myCache.get(cacheKey);
        if (cachedBody) {
            res.setHeader('X-Cache-Status', 'HIT');
            res.setHeader('X-Proxy-Mode', 'Recursive-Cached');
            return res.send(cachedBody);
        }
    }

    try {
        const headers = { ...req.headers };
        delete headers['host'];
        delete headers['connection'];
        if (!headers['user-agent']) headers['user-agent'] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";

        const upstreamRes = await fetch(targetUrlStr, {
            method: req.method,
            headers: headers,
            body: ['GET', 'HEAD'].includes(req.method) ? undefined : req.body,
            redirect: 'follow' 
        });

        res.status(upstreamRes.status);
        upstreamRes.headers.forEach((v, k) => {
            if (proxyMode === 'recursive' && (k === 'content-encoding' || k === 'content-length' || k === 'transfer-encoding')) return;
            res.setHeader(k, v);
        });

        res.setHeader('X-Proxy-Mode', proxyMode === 'recursive' ? 'Recursive-Force-Text' : 'Raw-Passthrough');
        res.removeHeader('content-security-policy');

        if (proxyMode === 'raw') {
            const arrayBuffer = await upstreamRes.arrayBuffer();
            res.send(Buffer.from(arrayBuffer));
            return;
        }

        if (proxyMode === 'recursive') {
            let text = await upstreamRes.text();
            const workerOrigin = `${req.protocol}://${req.get('host')}`;
            const proxyBase = `${workerOrigin}/${CONFIG.PASSWORD}/r/`;
            const regex = /(https?:\/\/[a-zA-Z0-9][-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*))/g;
            
            text = text.replace(regex, (match) => {
                if (match.includes(workerOrigin)) return match; 
                return proxyBase + match;
            });

            if (CONFIG.ENABLE_CACHE && upstreamRes.status === 200) {
                myCache.set(cacheKey, text);
            }
            res.send(text);
        }
    } catch (e) { res.status(502).send(`General Proxy Error: ${e.message}`); }
});

app.use((req, res) => res.status(404).send('404 Not Found - Powered by ProxyX'));

app.listen(PORT, () => {
    console.log(`ProxyX Server running on port ${PORT}`);
    console.log(`Config loaded with Password: ${CONFIG.PASSWORD}`);
});

// ==============================================================================
// 4. Dashboard 渲染 (CSS 未压缩)
// ==============================================================================
function renderDashboard(hostname, password, ip, count, limit, adminIps) {
    const percent = Math.min(Math.round((count / limit) * 100), 100);
    const isAdmin = adminIps.includes(ip);
    const linuxMirrorsJson = JSON.stringify(Object.keys(LINUX_MIRRORS));

    return `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>Cloudflare 加速通道</title>
    <link rel="icon" type="image/svg+xml" href="data:image/svg+xml,${encodeURIComponent(LIGHTNING_SVG)}">
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
      body { 
          min-height: 100vh; 
          display: flex; 
          align-items: center; 
          justify-content: center; 
          font-family: 'Inter', sans-serif; 
          transition: background-color 0.3s ease; 
          padding: 1rem; 
          margin: 0; 
      }
      /* Light Mode */
      .light-mode { background-color: #f3f4f6; color: #1f293b; }
      .light-mode .custom-content-wrapper { background: white; border: 1px solid #e5e7eb; box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.05); }
      .light-mode .section-box { background: #f8fafc; border: 1px solid #e2e8f0; }
      .light-mode input, .light-mode select { background: white; border: 1px solid #d1d5db; color: #1f293b; }
      .light-mode .code-area { background: #f1f5f9; border: 1px solid #e2e8f0; color: #334155; }
      .light-mode .reset-btn { background: #fee2e2; color: #ef4444; border: 1px solid #fca5a5; }

      /* Dark Mode */
      .dark-mode { background-color: #0f172a; color: #e2e8f0; }
      .dark-mode .custom-content-wrapper { background: transparent; border: none; box-shadow: none; }
      .dark-mode .section-box { background-color: #1e293b; border: 1px solid #334155; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.2); }
      .dark-mode input, .dark-mode select { background-color: #0f172a; border: 1px solid #3b82f6; color: #f1f5f9; }
      .dark-mode input::placeholder { color: #64748b; }
      .dark-mode .code-area { background-color: #020617; border: 1px solid #1e293b; color: #e2e8f0; }
      .dark-mode .reset-btn { background-color: white; color: #ef4444; border: none; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
      .dark-mode .reset-btn:hover { background-color: #f1f5f9; }

      /* Common */
      .code-area, pre, .select-all { user-select: text !important; -webkit-user-select: text !important; }
      .custom-content-wrapper { width: 80% !important; max-width: 1200px !important; min-width: 320px; margin: auto; padding: 1rem; border-radius: 1.5rem; }
      .section-box { border-radius: 1rem; padding: 2rem; margin-bottom: 1.5rem; transition: all 0.2s; position: relative; z-index: 1; }
      
      /* Navigation */
      .top-nav { position: fixed; top: 1.5rem; right: 1.5rem; z-index: 50; display: flex; gap: 0.75rem; }
      .nav-btn { width: 2.5rem; height: 2.5rem; border-radius: 9999px; background: rgba(255,255,255,0.5); backdrop-filter: blur(4px); border: 1px solid rgba(0,0,0,0.05); display: flex; align-items: center; justify-content: center; cursor: pointer; transition: all 0.2s; color: #64748b; }
      .nav-btn:hover { transform: scale(1.1); background: white; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); }
      .dark-mode .nav-btn { background: rgba(255,255,255,0.1); border: 1px solid rgba(255,255,255,0.1); color: #e2e8f0; }
      .dark-mode .nav-btn:hover { background: rgba(255,255,255,0.2); }

      /* Components */
      .toast { position: fixed; bottom: 3rem; left: 50%; transform: translateX(-50%) translateY(20px); padding: 0.75rem 1.5rem; border-radius: 0.5rem; z-index: 100; color: white; opacity: 0; transition: all 0.3s; pointer-events: none; font-weight: 500; font-size: 0.9rem; box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.3); display: flex; align-items: center; gap: 0.5rem; }
      .toast.show { opacity: 1; transform: translateX(-50%) translateY(0); }
      input, select { outline: none; transition: all 0.2s; }
      input:focus, select:focus { ring: 2px #3b82f6; ring-offset-2px; }
      .dark-mode input:focus, .dark-mode select:focus { ring: 0; border-color: #60a5fa; box-shadow: 0 0 0 2px rgba(59, 130, 246, 0.3); }
      
      /* Modal */
      .modal-overlay { position: fixed; inset: 0; z-index: 999; background: rgba(0, 0, 0, 0.6); backdrop-filter: blur(4px); display: flex; align-items: center; justify-content: center; opacity: 0; pointer-events: none; transition: opacity 0.2s; }
      .modal-overlay.open { opacity: 1; pointer-events: auto; }
      .modal-content { background: white; width: 95%; max-width: 400px; padding: 2rem; border-radius: 1.25rem; box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.25); transform: scale(0.9); transition: transform 0.2s; }
      .modal-overlay.open .modal-content { transform: scale(1); }
      .dark-mode .modal-content { background: #1e293b; border: 1px solid #334155; color: #f1f5f9; }

      @media (max-width: 768px) { 
          .custom-content-wrapper { width: 100% !important; padding: 0.5rem; } 
          .section-box { padding: 1.25rem !important; } 
          .flex-responsive { flex-direction: column !important; gap: 0.75rem !important; } 
          .flex-responsive button { width: 100% !important; } 
      }
    </style>
</head>
<body class="light-mode">
    <div class="top-nav">
       <button onclick="toggleTheme()" class="nav-btn" aria-label="Toggle Theme">
         <span class="sun text-lg">☀️</span><span class="moon hidden text-lg">🌙</span>
       </button>
    </div>
    
    <div class="custom-content-wrapper">
      <h1 class="text-3xl md:text-4xl font-extrabold text-center mb-8 tracking-tight">
        <span class="bg-clip-text text-transparent bg-gradient-to-r from-blue-600 to-indigo-600 dark:from-blue-400 dark:to-indigo-400">Cloudflare 加速通道 (VPS版)</span>
      </h1>
      
      <div class="section-box relative">
        <div class="flex flex-col md:flex-row justify-between items-center mb-4 gap-4">
          <div class="flex items-center gap-3">
             <div class="relative flex h-3 w-3">
                <span class="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75"></span>
                <span class="relative inline-flex rounded-full h-3 w-3 bg-green-500"></span>
             </div>
             <p class="text-sm font-bold opacity-90 tracking-wide">IP: <span class="font-mono text-blue-600 dark:text-blue-400">${ip}</span></p>
          </div>
          
          <div class="flex items-center gap-4 w-full md:w-auto justify-between md:justify-end">
              <div class="text-sm font-medium opacity-80">
                  今日额度: <span class="text-blue-600 dark:text-blue-400 font-bold">${count}</span> <span class="opacity-50">/ ${limit}</span>
              </div>
              <div class="flex gap-2">
                <button onclick="openModal('confirmModal')" class="reset-btn px-3 py-1.5 rounded-lg text-xs font-bold transition-transform hover:scale-105 flex items-center gap-1.5 shadow-sm">
                    <span>重置额度</span>
                </button>
              </div>
          </div>
        </div>
        
        <div class="w-full bg-gray-200 dark:bg-slate-700 rounded-full h-2.5 overflow-hidden mb-3">
          <div class="bg-blue-600 dark:bg-blue-500 h-full transition-all duration-1000 ease-out" style="width: ${percent}%"></div>
        </div>
        <p class="text-[11px] opacity-60 flex items-center gap-1">
          失败自动退还额度 · 短时重复请求不扣费。（10s）
        </p>
      </div>
      
      <div class="section-box">
        <h2 class="text-lg font-bold mb-4 flex items-center gap-2 opacity-90">
          GitHub 文件加速 (Raw 纯净模式)
        </h2>
        <div class="flex flex-responsive gap-3">
          <input id="github-url" type="text" placeholder="粘贴 https://github.com/... 链接" class="flex-grow p-3.5 rounded-lg text-sm">
          <button onclick="convertGithubUrl()" class="bg-blue-600 hover:bg-blue-700 text-white px-6 py-3.5 rounded-lg transition font-bold text-sm shadow-md whitespace-nowrap flex items-center justify-center gap-1">
              获取链接
          </button>
        </div>
        <div id="github-result-box" class="hidden mt-5">
          <div class="p-4 bg-emerald-50 dark:bg-emerald-900/20 border border-emerald-100 dark:border-emerald-800 rounded-lg mb-3">
               <p id="github-result" class="text-emerald-700 dark:text-emerald-400 font-mono text-xs break-all select-all"></p>
          </div>
          <div class="flex gap-3">
              <button id="btn-copy-github" onclick="copyGithubUrl()" class="flex-1 bg-gray-100 dark:bg-slate-700 hover:bg-gray-200 dark:hover:bg-slate-600 text-gray-700 dark:text-gray-200 py-2.5 rounded-lg text-xs font-bold transition">复制链接</button>
              <button onclick="openGithubUrl()" class="flex-1 bg-blue-50 dark:bg-blue-900/20 hover:bg-blue-100 dark:hover:bg-blue-900/40 text-blue-600 dark:text-blue-400 py-2.5 rounded-lg text-xs font-bold transition">立即访问</button>
          </div>
        </div>
      </div>

      <div class="section-box">
        <h2 class="text-lg font-bold mb-4 flex items-center gap-2 opacity-90">
          <span class="text-xl">🚀</span> 递归脚本加速 (Shell / Curl)
        </h2>
        <div class="flex flex-responsive gap-3">
          <input id="recursive-url" type="text" placeholder="如: https://get.docker.com" class="flex-grow p-3.5 rounded-lg text-sm">
          <button onclick="convertRecursiveUrl()" class="bg-blue-600 hover:bg-blue-700 text-white px-6 py-3.5 rounded-lg transition font-bold text-sm shadow-md whitespace-nowrap flex items-center justify-center gap-1">
               生成命令
          </button>
        </div>
        
        <div id="recursive-result-box" class="hidden mt-5">
             <div class="mb-6">
                 <p class="text-xs font-bold text-gray-500 dark:text-gray-400 mb-2 uppercase tracking-wide">1. 纯递归链接 (Raw URL):</p>
                 <div class="p-4 bg-emerald-50 dark:bg-emerald-900/20 border border-emerald-100 dark:border-emerald-800 rounded-lg mb-3">
                     <p id="recursive-result-url" class="text-emerald-700 dark:text-emerald-400 font-mono text-xs break-all select-all"></p>
                 </div>
                 <div class="flex gap-3">
                     <button onclick="copyRecursiveUrlOnly()" class="flex-1 bg-gray-100 dark:bg-slate-700 hover:bg-gray-200 dark:hover:bg-slate-600 text-gray-700 dark:text-gray-200 py-2.5 rounded-lg text-xs font-bold transition">复制链接</button>
                     <button onclick="openRecursiveUrl()" class="flex-1 bg-blue-50 dark:bg-blue-900/20 hover:bg-blue-100 dark:hover:bg-blue-900/40 text-blue-600 dark:text-blue-400 py-2.5 rounded-lg text-xs font-bold transition">立即访问</button>
                 </div>
             </div>
             <div>
                 <p class="text-xs font-bold text-gray-500 dark:text-gray-400 mb-2 uppercase tracking-wide">2. 终端命令 (Bash):</p>
                 <div class="p-4 bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg mb-3">
                    <p id="recursive-result-cmd" class="text-slate-700 dark:text-slate-300 font-mono text-xs break-all select-all"></p>
                 </div>
                 <button onclick="copyRecursiveCmd()" class="w-full bg-gray-100 dark:bg-slate-700 hover:bg-gray-200 dark:hover:bg-slate-600 text-gray-700 dark:text-gray-200 py-2.5 rounded-lg text-xs font-bold transition">复制命令</button>
             </div>
        </div>
      </div>

      <div class="section-box">
        <h2 class="text-lg font-bold mb-4 flex items-center gap-2 opacity-90">
          <span class="text-xl">🐳</span> Docker 镜像加速
        </h2>
        <div class="flex flex-responsive gap-3">
          <input id="docker-image" type="text" placeholder="如 nginx 或 library/redis" class="flex-grow p-3.5 rounded-lg text-sm">
          <button onclick="convertDockerImage()" class="bg-indigo-600 hover:bg-indigo-700 text-white px-6 py-3.5 rounded-lg transition font-bold text-sm shadow-md whitespace-nowrap flex items-center justify-center gap-1">
               获取命令
          </button>
        </div>
        <div id="docker-result-box" class="hidden mt-5">
           <div class="p-4 bg-emerald-50 dark:bg-emerald-900/20 border border-emerald-100 dark:border-emerald-800 rounded-lg mb-3">
               <p id="docker-result" class="text-emerald-700 dark:text-emerald-400 font-mono text-xs break-all select-all"></p>
          </div>
          <button onclick="copyDockerCommand()" class="w-full bg-gray-100 dark:bg-slate-700 hover:bg-gray-200 dark:hover:bg-slate-600 text-gray-700 dark:text-gray-200 py-2.5 rounded-lg text-xs font-bold transition">一键复制命令</button>
        </div>
      </div>

      <div id="confirmModal" class="modal-overlay">
        <div class="modal-content">
            <h3 class="text-lg font-bold mb-2">确认重置额度？</h3>
            <div class="flex gap-3 mt-4">
               <button onclick="closeModal('confirmModal')" class="flex-1 px-4 py-2 bg-gray-100 rounded">取消</button>
               <button onclick="confirmReset()" class="flex-1 px-4 py-2 bg-red-500 text-white rounded">确定</button>
            </div>
        </div>
      </div>
      <div id="toast" class="toast bg-slate-800 text-white"></div>

      <script>
        window.CURRENT_DOMAIN = window.location.hostname + (window.location.port ? ':' + window.location.port : '');
        window.WORKER_PASSWORD = "${password}"; 
        window.CURRENT_CLIENT_IP = "${ip}";
        window.LINUX_MIRRORS = ${linuxMirrorsJson};

        window.showToast = function(msg) {
            const t = document.getElementById('toast'); t.innerHTML = msg; t.classList.add('show');
            setTimeout(() => t.classList.remove('show'), 2000);
        }
        window.copyToClipboard = function(text) {
            navigator.clipboard.writeText(text).then(() => window.showToast('已复制'));
        }
        window.openModal = (id) => document.getElementById(id).classList.add('open');
        window.closeModal = (id) => document.getElementById(id).classList.remove('open');

        window.convertGithubUrl = function() {
            let input = document.getElementById('github-url').value.trim();
            if(!input) return;
            if(!input.startsWith('http')) input = 'https://' + input;
            const url = window.location.protocol + '//' + window.CURRENT_DOMAIN + '/' + window.WORKER_PASSWORD + '/' + input;
            document.getElementById('github-result').innerText = url;
            document.getElementById('github-result-box').classList.remove('hidden');
            window.githubUrl = url;
        }
        window.copyGithubUrl = () => window.copyToClipboard(window.githubUrl);
        window.openGithubUrl = () => window.open(window.githubUrl, '_blank');

        window.convertRecursiveUrl = function() {
            let input = document.getElementById('recursive-url').value.trim();
            if(!input) return;
            if(!input.startsWith('http')) input = 'https://' + input;
            const url = window.location.protocol + '//' + window.CURRENT_DOMAIN + '/' + window.WORKER_PASSWORD + '/r/' + input;
            document.getElementById('recursive-result-url').innerText = url;
            document.getElementById('recursive-result-cmd').innerText = 'bash <(curl -sL ' + url + ')';
            document.getElementById('recursive-result-box').classList.remove('hidden');
            window.recursiveUrl = url;
        }
        window.copyRecursiveUrlOnly = () => window.copyToClipboard(window.recursiveUrl);
        window.openRecursiveUrl = () => window.open(window.recursiveUrl, '_blank');
        window.copyRecursiveCmd = () => window.copyToClipboard(document.getElementById('recursive-result-cmd').innerText);

        window.convertDockerImage = function() {
            let input = document.getElementById('docker-image').value.trim();
            if(!input) return;
            const cmd = 'docker pull ' + window.CURRENT_DOMAIN + '/' + input;
            document.getElementById('docker-result').innerText = cmd;
            document.getElementById('docker-result-box').classList.remove('hidden');
        }
        window.copyDockerCommand = () => window.copyToClipboard(document.getElementById('docker-result').innerText);

        window.confirmReset = async () => {
            await fetch('/' + window.WORKER_PASSWORD + '/reset');
            window.location.reload();
        }
      </script>
</body>
</html>
    `;
}
