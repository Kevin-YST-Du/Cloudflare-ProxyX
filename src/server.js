/**
 * -----------------------------------------------------------------------------------------
 * ProxyX Server (VPS Node.js Edition)
 * 版本: v4.8 (GeoIP Integrated)
 * -----------------------------------------------------------------------------------------
 * 核心功能:
 * 1. Docker Hub/GHCR 等镜像仓库加速下载。
 * 2. 智能处理 Docker 的 library/ 命名空间补全。
 * 3. Linux 软件源加速，支持 debian-security 及 Range 断点续传。
 * 4. 双模式通用代理 (Raw / Recursive)。
 * 5. 递归模式集成 Cache API，极大提升脚本二次访问速度。
 * 6. Dashboard: 递归加速模块样式与 GitHub 文件加速模块完全一致。
 * 7. [新增] 集成 geoip-lite，支持 ALLOW_COUNTRIES 国家级访问控制。
 * 8. [新增] ALLOW_REFERER 免密访问 (支持域名/URL前缀匹配)。
 * 9. [新增] 管理员 IP (ADMIN_IPS) 免密访问 Dashboard 和代理路径。
 * 10. [优化] 自动修复浏览器合并斜杠问题 (https:/ip.sb -> https://ip.sb)。
 * -----------------------------------------------------------------------------------------
 */

const path = require('path');
const fs = require('fs');

// --- 1. 智能加载配置 (.env) ---
// 逻辑: 优先查找可执行文件同级目录下的 .env，如果没有则查找当前源码目录
const envPath = process.pkg 
    ? path.join(path.dirname(process.execPath), '.env') 
    : path.join(__dirname, '.env');

if (fs.existsSync(envPath)) {
    console.log(`[Config] Loading config from: ${envPath}`);
    require('dotenv').config({ path: envPath });
} else {
    // 兼容 Docker 环境 (环境变量直接注入)
    require('dotenv').config(); 
}

const express = require('express');
const NodeCache = require('node-cache');
const http = require('http');
const https = require('https');
// [新增] 引入 GeoIP 库，用于查询 IP 归属地
const geoip = require('geoip-lite');

// --- 初始化 Express 和 缓存 ---
const app = express();
// 读取 CACHE_TTL 环境变量，默认 3600 秒
const cacheTTL = parseInt(process.env.CACHE_TTL || "3600");
const myCache = new NodeCache({ stdTTL: cacheTTL }); 
const PORT = process.env.PORT || 21011; 

// --- 内存级频率限制存储 (替代 Cloudflare KV/D1) ---
const rateLimitStore = new Map();

// ==============================================================================
// 2. 全局配置定义
// ==============================================================================

// 辅助函数: 将逗号或换行符分隔的字符串解析为数组，并去空
const parseList = (val, defaultVal) => {
    const source = val || defaultVal || "";
    return source.split(/[\n,]/).map(s => s.trim()).filter(s => s.length > 0);
};

const CONFIG = {
    // --- 基础配置 ---
    PASSWORD: process.env.PASSWORD || "123456",
    MAX_REDIRECTS: parseInt(process.env.MAX_REDIRECTS || "5"),
    ENABLE_CACHE: (process.env.ENABLE_CACHE || "true") === "true",
    CACHE_TTL: cacheTTL,
    
    // --- 访问控制 (安全设置) ---
    BLACKLIST: parseList(process.env.BLACKLIST, ""),           // 黑名单域名
    WHITELIST: parseList(process.env.WHITELIST, ""),           // 白名单域名 (设置后仅允许这些)
    ALLOW_IPS: parseList(process.env.ALLOW_IPS, ""),           // 允许访问的客户端 IP (白名单)
    
    // [新增] 允许的国家代码 (如 CN, US, JP, HK)
    // 如果设置了此项，只有来自这些国家的 IP 才能访问
    ALLOW_COUNTRIES: parseList(process.env.ALLOW_COUNTRIES, ""), 
    
    // --- 免密访问增强 ---
    // 格式: "github.com" (域名) 或 "https://github.com/User" (完整前缀)
    // 允许特定的来源网站免密码调用本代理
    ALLOW_REFERER: process.env.ALLOW_REFERER || "",

    // --- 额度限制 ---
    DAILY_LIMIT_COUNT: parseInt(process.env.DAILY_LIMIT_COUNT || "200"),
    
    // --- 权限管理 ---
    // 管理员 IP: 拥有重置额度权限，且访问代理时免密码
    ADMIN_IPS: parseList(process.env.ADMIN_IPS, "127.0.0.1"),
    // 免限额 IP: 这些 IP 访问不计入每日限额
    IP_LIMIT_WHITELIST: parseList(process.env.IP_LIMIT_WHITELIST, "127.0.0.1"),
};

// 打印关键配置信息到控制台
console.log("---------------------------------------");
console.log(`ProxyX Server Starting on Port ${PORT}`);
console.log(`PASSWORD: ${CONFIG.PASSWORD}`);
console.log(`ADMIN_IPS: ${JSON.stringify(CONFIG.ADMIN_IPS)}`);
console.log(`GeoIP Check: ${CONFIG.ALLOW_COUNTRIES.length > 0 ? 'Enabled (' + CONFIG.ALLOW_COUNTRIES.join(',') + ')' : 'Disabled'}`);
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

// Linux 软件源镜像配置
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
// 3. 中间件与工具函数
// ==============================================================================

// 获取客户端真实 IP
const getClientIP = (req) => {
    // 优先从 CF-Connecting-IP 获取 (如果套了 Cloudflare CDN)
    // 否则用 X-Forwarded-For (反代)，最后用直连 IP
    const ip = req.headers['cf-connecting-ip'] || req.headers['x-forwarded-for'] || req.socket.remoteAddress || '0.0.0.0';
    // 处理 IPv6 映射格式 (::ffff:1.2.3.4 -> 1.2.3.4)
    return ip.replace(/^.*:/, ''); 
};

// 获取今日日期字符串 (用于限额 key)
const getDate = () => new Date(new Date().getTime() + 28800000).toISOString().split('T')[0];

// 中间件: 每日速率限制
const checkRateLimit = (req, res, next) => {
    const ip = getClientIP(req);
    
    // 白名单 IP 跳过检查
    if (CONFIG.IP_LIMIT_WHITELIST.includes(ip)) return next();
    
    // 静态资源跳过检查
    if (req.path === '/' || req.path === '/favicon.ico' || req.path === '/robots.txt') return next();

    const today = getDate();
    const key = `${ip}:${today}`;
    const count = rateLimitStore.get(key) || 0;

    // 超过限额
    if (count >= CONFIG.DAILY_LIMIT_COUNT) {
        return res.status(429).send(`⚠️ Daily Limit Exceeded: ${count}/${CONFIG.DAILY_LIMIT_COUNT}`);
    }
    
    // 简单计数 (每请求一次 +1，实际生产环境可优化为请求成功后计数)
    rateLimitStore.set(key, count + 1);
    next();
};

// 中间件: 设置 CORS 头
app.use((req, res, next) => {
    res.header("Access-Control-Allow-Origin", "*");
    res.header("Access-Control-Allow-Methods", "GET, POST, OPTIONS, HEAD");
    res.header("Access-Control-Allow-Headers", "*");
    res.header("Docker-Distribution-API-Version", "registry/2.0");
    if (req.method === 'OPTIONS') return res.sendStatus(200);
    next();
});

// [核心功能] 中间件: 访问控制 (IP 白名单 + GeoIP 国家限制)
app.use((req, res, next) => {
    const ip = getClientIP(req);

    // 1. IP 白名单检查 (优先级最高)
    // 如果设置了 ALLOW_IPS，不在列表中的 IP 直接拒绝
    if (CONFIG.ALLOW_IPS.length > 0) {
        if (!CONFIG.ALLOW_IPS.includes(ip)) {
            return res.status(403).send(`Access Denied (IP ${ip} Not Allowed)`);
        }
    }

    // 2. GeoIP 国家检查
    // 如果设置了 ALLOW_COUNTRIES，查询 IP 归属地并检查
    if (CONFIG.ALLOW_COUNTRIES.length > 0) {
        // 跳过内网 IP / 本地回环
        if (ip === '127.0.0.1' || ip === 'localhost' || ip.startsWith('192.168.') || ip.startsWith('10.')) {
            return next(); 
        }

        const geo = geoip.lookup(ip);
        const country = geo ? geo.country : "XX"; // 获取不到归属地则标记为 XX

        if (!CONFIG.ALLOW_COUNTRIES.includes(country)) {
            console.log(`[Block] IP: ${ip} | Country: ${country} | Not in allowed list: ${CONFIG.ALLOW_COUNTRIES}`);
            return res.status(403).send(`Access Denied (Country ${country} Not Allowed)`);
        }
    }

    next();
});

app.use(checkRateLimit);
// 解析 raw body，支持大文件流式传输，限制 50mb (主要针对上传，下载流不受此限)
app.use(express.raw({ type: '*/*', limit: '50mb' }));

// ==============================================================================
// 4. 路由逻辑
// ==============================================================================

app.get('/robots.txt', (req, res) => res.type('text/plain').send("User-agent: *\nDisallow: /"));
app.get('/favicon.ico', (req, res) => res.type('image/svg+xml').send(LIGHTNING_SVG));

// --- 4.1 Docker Token 认证 ---
// 处理 Docker 客户端的登录/拉取令牌请求
app.get('/token', async (req, res) => {
    const scope = req.query.scope;
    let upstreamAuthUrl = 'https://auth.docker.io/token';
    
    // 根据 scope 判断请求的是哪个 Registry (如 ghcr.io)
    for (const [domain, _] of Object.entries(REGISTRY_MAP)) {
        if (scope && scope.includes(domain)) {
            upstreamAuthUrl = `https://${domain}/token`;
            break;
        }
    }

    const newUrl = new URL(upstreamAuthUrl);
    newUrl.search = new URLSearchParams(req.query).toString();

    // Docker Hub 特殊处理：补全 library/
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
            headers: {
                'User-Agent': 'Docker-Client/24.0.5 (linux)',
                'Host': newUrl.hostname
            }
        });
        
        res.status(upstreamRes.status);
        upstreamRes.headers.forEach((v, k) => res.setHeader(k, v));
        const data = await upstreamRes.arrayBuffer();
        res.send(Buffer.from(data));
    } catch (e) {
        res.status(500).send(e.message);
    }
});

// --- 4.2 Docker V2 API ---
// 处理实际的 Docker 镜像层下载请求
app.use('/v2', async (req, res) => {
    let path = req.path;
    if (path === '/') path = '';
    
    let targetDomain = 'registry-1.docker.io'; 
    let upstream = 'https://registry-1.docker.io';

    // 根路径检查
    if (path === '' || path === '/') {
        try {
            const rootReq = await fetch('https://registry-1.docker.io/v2/', { 
                method: req.method, 
                headers: req.headers 
            });
            // 处理 401 认证跳转
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

    // 路径修正与 Registry 识别
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

        // 401 认证处理
        if (response.status === 401) {
            const wwwAuth = response.headers.get('WWW-Authenticate');
            if (wwwAuth) {
                const workerOrigin = `${req.protocol}://${req.get('host')}`;
                res.setHeader('WWW-Authenticate', wwwAuth.replace(/realm="([^"]+)"/, `realm="${workerOrigin}/token"`));
            }
            return res.status(401).send(await response.text());
        }

        // 302 重定向处理 (Blob 下载)
        if ([301, 302, 303, 307, 308].includes(response.status)) {
            const location = response.headers.get('Location');
            if (location) {
                const blobResp = await fetch(location, {
                    method: 'GET',
                    headers: { 'User-Agent': 'Docker-Client/24.0.5 (linux)' }
                });
                res.status(blobResp.status);
                blobResp.headers.forEach((v, k) => {
                    if (k !== 'content-encoding' && k !== 'transfer-encoding') {
                        res.setHeader(k, v);
                    }
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

    } catch (e) {
        res.status(502).send(`Docker Proxy Error: ${e.message}`);
    }
});

// --- 4.3 通用代理入口 (核心逻辑) ---
// 捕获所有其他请求，处理 Linux源、GitHub加速、通用文件代理
app.all('*', async (req, res) => {
    const clientIP = getClientIP(req);
    const referer = req.headers['referer'] || "";
    const path = req.path;

    // --- 认证与信任判断 ---
    // 1. 判断是否为管理员 IP (免密)
    const isAdminIp = CONFIG.ADMIN_IPS.includes(clientIP);

    // 2. 判断 Referer 是否在允许列表中 (免密)
    let isTrustedReferer = false;
    if (CONFIG.ALLOW_REFERER && referer) {
        const allowedRules = CONFIG.ALLOW_REFERER.split(/[\n,]/).map(s => s.trim()).filter(s => s);
        for (const rule of allowedRules) {
            // A. 完整 URL 前缀匹配 (如 https://github.com/User)
            if (rule.includes("://")) {
                if (referer.startsWith(rule)) { isTrustedReferer = true; break; }
            } 
            // B. 域名匹配 (如 github.com)
            else {
                try {
                    const refUrl = new URL(referer);
                    // 允许完全匹配或子域名
                    if (refUrl.hostname === rule || refUrl.hostname.endsWith("." + rule)) {
                        isTrustedReferer = true; break;
                    }
                } catch(e) {
                    // 容错：简单的字符串包含
                    if (referer.includes(rule)) { isTrustedReferer = true; break; }
                }
            }
        }
    }

    const isTrusted = isAdminIp || isTrustedReferer;

    // --- 路径解析 ---
    let subPath = "";
    let isAuthenticated = false;

    // 解析路径结构: /密码/目标URL
    const match = path.match(/^\/([^/]+)(?:\/(.*))?$/);

    // 认证方式 A: URL 携带正确密码
    if (match && match[1] === CONFIG.PASSWORD) {
        isAuthenticated = true;
        subPath = match[2] || ""; 
    } 
    // 认证方式 B: 信任来源 (免密)
    else if (isTrusted) {
        isAuthenticated = true;
        // 免密模式下，整个 Path 去掉开头的 / 就是目标路径
        subPath = path.substring(1); 
    }

    // 未通过认证 -> 404
    if (!isAuthenticated) {
        return res.status(404).send("404 Not Found - Powered by ProxyX");
    }

    // --- 4.3.1 管理员 API ---
    // 敏感操作仅允许管理员 IP，Referer 免密不授予此权限
    if (subPath === "reset") {
        if (!isAdminIp) return res.status(403).send("Forbidden: Admin IP Required");
        rateLimitStore.delete(`${clientIP}:${getDate()}`);
        return res.json({ status: "success" });
    }
    if (subPath === "reset-all") {
        if (!isAdminIp) return res.status(403).send("Forbidden: Admin IP Required");
        rateLimitStore.clear();
        return res.json({ status: "success" });
    }
    if (subPath === "stats") {
        if (!isAdminIp) return res.status(403).send("Forbidden: Admin IP Required");
        const stats = [];
        const today = getDate();
        rateLimitStore.forEach((val, key) => {
            if(key.endsWith(today)) stats.push({ ip: key.split(':')[0], count: val });
        });
        stats.sort((a, b) => b.count - a.count);
        return res.json({ status: "success", data: { totalRequests: 0, uniqueIps: stats.length, details: stats } });
    }

    // --- 4.3.2 仪表盘 ---
    if (!subPath) {
        const count = rateLimitStore.get(`${clientIP}:${getDate()}`) || 0;
        return res.send(renderDashboard(req.hostname, CONFIG.PASSWORD, clientIP, count, CONFIG.DAILY_LIMIT_COUNT, CONFIG.ADMIN_IPS));
    }

    // --- 4.3.3 Linux 源加速 ---
    const sortedMirrors = Object.keys(LINUX_MIRRORS).sort((a, b) => b.length - a.length);
    const linuxDistro = sortedMirrors.find(k => subPath.startsWith(k + '/') || subPath === k);

    if (linuxDistro) {
        const realPath = subPath.replace(linuxDistro, '').replace(/^\//, '');
        const upstreamBase = LINUX_MIRRORS[linuxDistro];
        const targetUrl = upstreamBase.endsWith('/') ? upstreamBase + realPath : upstreamBase + '/' + realPath;
        
        try {
            const headers = { ...req.headers };
            delete headers['host'];
            
            const linuxRes = await fetch(targetUrl, {
                method: req.method,
                headers: headers,
                redirect: 'follow'
            });
            
            res.status(linuxRes.status);
            linuxRes.headers.forEach((v, k) => res.setHeader(k, v));
            const arrayBuffer = await linuxRes.arrayBuffer();
            res.send(Buffer.from(arrayBuffer));
            return;
        } catch (e) {
            return res.status(502).send(`Linux Mirror Error: ${e.message}`);
        }
    }

    // --- 4.3.4 通用文件/递归加速 ---
    
    // [1] 递归模式判断
    let proxyMode = 'raw';
    let targetUrlStr = subPath;

    if (subPath.startsWith('r/') || subPath === 'r') {
        proxyMode = 'recursive';
        targetUrlStr = subPath.replace(/^r\/?/, "");
    }

    // [2] 自动修正 URL (核心修复：解决浏览器合并双斜杠问题)
    if (!targetUrlStr.startsWith("http")) {
        targetUrlStr = 'https://' + targetUrlStr;
    } else {
        // 将 https:/ip.sb 修复为 https://ip.sb
        targetUrlStr = targetUrlStr.replace(/^(https?):\/+(?!\/)/, '$1://');
    }

    // [3] 安全检查 (黑白名单)
    try {
        const parsedUrl = new URL(targetUrlStr);
        const domain = parsedUrl.hostname;
        
        if (CONFIG.BLACKLIST.length > 0 && CONFIG.BLACKLIST.some(k => domain.includes(k))) {
            return res.status(403).send("Blocked Domain");
        }
        if (CONFIG.WHITELIST.length > 0 && !CONFIG.WHITELIST.some(k => domain.includes(k))) {
            return res.status(403).send("Blocked (Not Whitelisted)");
        }
    } catch (e) {
        return res.status(400).send(`Invalid URL: ${targetUrlStr}`);
    }

    // [4] 递归模式缓存检查
    const cacheKey = req.originalUrl;
    if (proxyMode === 'recursive' && CONFIG.ENABLE_CACHE) {
        const cachedBody = myCache.get(cacheKey);
        if (cachedBody) {
            res.setHeader('X-Cache-Status', 'HIT');
            res.setHeader('X-Proxy-Mode', 'Recursive-Cached');
            return res.send(cachedBody);
        }
    }

    // [5] 发起请求
    try {
        const headers = { ...req.headers };
        delete headers['host'];
        delete headers['connection'];
        // 伪装 UA 防止被拒绝
        if (!headers['user-agent']) headers['user-agent'] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";

        const upstreamRes = await fetch(targetUrlStr, {
            method: req.method,
            headers: headers,
            body: ['GET', 'HEAD'].includes(req.method) ? undefined : req.body,
            redirect: 'follow' 
        });

        res.status(upstreamRes.status);
        upstreamRes.headers.forEach((v, k) => {
            // 递归模式下，这些头会导致修改后的 body 长度不匹配，必须删除
            if (proxyMode === 'recursive' && (k === 'content-encoding' || k === 'content-length' || k === 'transfer-encoding')) return;
            res.setHeader(k, v);
        });

        res.setHeader('X-Proxy-Mode', proxyMode === 'recursive' ? 'Recursive-Force-Text' : 'Raw-Passthrough');
        res.removeHeader('content-security-policy');

        // A. Raw 模式：直接透传二进制流
        if (proxyMode === 'raw') {
            const arrayBuffer = await upstreamRes.arrayBuffer();
            res.send(Buffer.from(arrayBuffer));
            return;
        }

        // B. 递归模式：文本替换
        if (proxyMode === 'recursive') {
            let text = await upstreamRes.text();
            
            const workerOrigin = `${req.protocol}://${req.get('host')}`;
            // 构造代理前缀：如果是免密访问且未使用密码路径，前缀就不带密码；否则带密码
            const prefixPath = (isTrusted && !path.startsWith('/' + CONFIG.PASSWORD)) ? '' : `/${CONFIG.PASSWORD}`;
            const proxyBase = `${workerOrigin}${prefixPath}/r/`;

            // 正则替换 http/https 链接，加上代理前缀
            const regex = /(https?:\/\/[a-zA-Z0-9][-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*))/g;
            
            text = text.replace(regex, (match) => {
                if (match.includes(workerOrigin)) return match; 
                return proxyBase + match;
            });

            // 写入缓存
            if (CONFIG.ENABLE_CACHE && upstreamRes.status === 200) {
                myCache.set(cacheKey, text);
            }

            res.send(text);
        }

    } catch (e) {
        res.status(502).send(`General Proxy Error: ${e.message}`);
    }
});

// 启动监听
app.listen(PORT, () => {
    console.log(`ProxyX Server running on port ${PORT}`);
});


// ==============================================================================
// 5. Dashboard HTML 渲染 (完整未压缩)
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
/* CSS: Uncompressed as requested */
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
.light-mode {
  background-color: #f3f4f6;
  color: #1f293b;
}

.light-mode .custom-content-wrapper {
  background: white;
  border: 1px solid #e5e7eb;
  box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.05);
}

.light-mode .section-box {
  background: #f8fafc;
  border: 1px solid #e2e8f0;
}

.light-mode input,
.light-mode select {
  background: white;
  border: 1px solid #d1d5db;
  color: #1f293b;
}

.light-mode .code-area {
  background: #f1f5f9;
  border: 1px solid #e2e8f0;
  color: #334155;
}

.light-mode .reset-btn {
  background: #fee2e2;
  color: #ef4444;
  border: 1px solid #fca5a5;
}

/* Dark Mode */
.dark-mode {
  background-color: #0f172a;
  color: #e2e8f0;
}

.dark-mode .custom-content-wrapper {
  background: transparent;
  border: none;
  box-shadow: none;
}

.dark-mode .section-box {
  background-color: #1e293b;
  border: 1px solid #334155;
  box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.2);
}

.dark-mode input,
.dark-mode select {
  background-color: #0f172a;
  border: 1px solid #3b82f6;
  color: #f1f5f9;
}

.dark-mode input::placeholder {
  color: #64748b;
}

.dark-mode .code-area {
  background-color: #020617;
  border: 1px solid #1e293b;
  color: #e2e8f0;
}

.dark-mode .reset-btn {
  background-color: white;
  color: #ef4444;
  border: none;
  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
}

.dark-mode .reset-btn:hover {
  background-color: #f1f5f9;
}

/* Common */
.code-area,
pre,
.select-all {
  user-select: text !important;
  -webkit-user-select: text !important;
}

.custom-content-wrapper {
  width: 80% !important;
  max-width: 1200px !important;
  min-width: 320px;
  margin: auto;
  padding: 1rem;
  border-radius: 1.5rem;
}

.section-box {
  border-radius: 1rem;
  padding: 2rem;
  margin-bottom: 1.5rem;
  transition: all 0.2s;
  position: relative;
  z-index: 1;
}

@media (max-width: 768px) {
  .custom-content-wrapper {
    width: 100% !important;
    padding: 0.5rem;
  }

  .section-box {
    padding: 1.25rem !important;
  }

  .flex-responsive {
    flex-direction: column !important;
    gap: 0.75rem !important;
  }

  .flex-responsive button {
    width: 100% !important;
  }
}

.top-nav {
  position: fixed;
  top: 1.5rem;
  right: 1.5rem;
  z-index: 50;
  display: flex;
  gap: 0.75rem;
}

.nav-btn {
  width: 2.5rem;
  height: 2.5rem;
  border-radius: 9999px;
  background: rgba(255, 255, 255, 0.5);
  backdrop-filter: blur(4px);
  border: 1px solid rgba(0, 0, 0, 0.05);
  display: flex;
  align-items: center;
  justify-content: center;
  cursor: pointer;
  transition: all 0.2s;
  color: #64748b;
}

.nav-btn:hover {
  transform: scale(1.1);
  background: white;
  box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
}

.dark-mode .nav-btn {
  background: rgba(255, 255, 255, 0.1);
  border: 1px solid rgba(255, 255, 255, 0.1);
  color: #e2e8f0;
}

.dark-mode .nav-btn:hover {
  background: rgba(255, 255, 255, 0.2);
}

.toast {
  position: fixed;
  bottom: 3rem;
  left: 50%;
  transform: translateX(-50%) translateY(20px);
  padding: 0.75rem 1.5rem;
  border-radius: 0.5rem;
  z-index: 100;
  color: white;
  opacity: 0;
  transition: all 0.3s;
  pointer-events: none;
  font-weight: 500;
  font-size: 0.9rem;
  box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.3);
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.toast.show {
  opacity: 1;
  transform: translateX(-50%) translateY(0);
}

input,
select {
  outline: none;
  transition: all 0.2s;
}

input:focus,
select:focus {
  ring: 2px #3b82f6;
  ring-offset: 2px;
}

.dark-mode input:focus,
.dark-mode select:focus {
  ring: 0;
  border-color: #60a5fa;
  box-shadow: 0 0 0 2px rgba(59, 130, 246, 0.3);
}

.modal-overlay {
  position: fixed;
  inset: 0;
  z-index: 999;
  background: rgba(0, 0, 0, 0.6);
  backdrop-filter: blur(4px);
  display: flex;
  align-items: center;
  justify-content: center;
  opacity: 0;
  pointer-events: none;
  transition: opacity 0.2s;
}

.modal-overlay.open {
  opacity: 1;
  pointer-events: auto;
}

.modal-content {
  background: white;
  width: 95%;
  max-width: 400px;
  padding: 2rem;
  border-radius: 1.25rem;
  box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.25);
  transform: scale(0.9);
  transition: transform 0.2s;
}

.modal-overlay.open .modal-content {
  transform: scale(1);
}

.dark-mode .modal-content {
  background: #1e293b;
  border: 1px solid #334155;
  color: #f1f5f9;
}
    </style>
</head>
<body class="light-mode">
    <div class="top-nav">
       <a href="https://github.com/Kevin-YST-Du/Cloudflare-ProxyX" target="_blank" class="nav-btn" aria-label="GitHub Repository">
         <svg class="w-5 h-5" fill="currentColor" viewBox="0 0 24 24"><path fill-rule="evenodd" d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z" clip-rule="evenodd"></path></svg>
       </a>
       <button onclick="toggleTheme()" class="nav-btn" aria-label="Toggle Theme">
         <span class="sun text-lg">☀️</span><span class="moon hidden text-lg">🌙</span>
       </button>
    </div>
    
    <div class="custom-content-wrapper">
      <h1 class="text-3xl md:text-4xl font-extrabold text-center mb-8 tracking-tight">
        <span class="bg-clip-text text-transparent bg-gradient-to-r from-blue-600 to-indigo-600 dark:from-blue-400 dark:to-indigo-400">Cloudflare 加速通道</span>
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
                <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
                    <span>重置额度</span>
                </button>
                ${isAdmin ? `
                <button onclick="viewAllStats()" class="px-3 py-1.5 rounded-lg text-xs font-bold bg-blue-100 text-blue-600 border border-blue-200 hover:bg-blue-200 transition-transform hover:scale-105 flex items-center gap-1.5 shadow-sm">
                    <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"></path></svg>
                    <span>全站统计</span>
                </button>
                ` : ''}
              </div>
          </div>
        </div>
        
        <div class="w-full bg-gray-200 dark:bg-slate-700 rounded-full h-2.5 overflow-hidden mb-3">
          <div class="bg-blue-600 dark:bg-blue-500 h-full transition-all duration-1000 ease-out" style="width: ${percent}%"></div>
        </div>
        <p class="text-[11px] opacity-60 flex items-center gap-1">
          <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
          失败自动退还额度 · 短时重复请求不扣费。（10s）
        </p>

        <div id="stats-panel" class="hidden mt-4 p-4 rounded-xl bg-gray-50 dark:bg-slate-800/50 border border-gray-200 dark:border-slate-700">
            <div class="flex justify-between items-center mb-2">
                <h4 class="text-xs font-bold opacity-70 uppercase tracking-wider">今日全站概况</h4>
                ${isAdmin ? `
                <button onclick="openModal('confirmResetAllModal')" class="text-[10px] text-red-500 hover:text-red-700 font-bold border border-red-200 hover:border-red-400 bg-red-50 hover:bg-red-100 px-2 py-0.5 rounded transition">
                清空全站数据
                </button>
                ` : ''}
            </div>
            
            <div class="mb-2 text-xs font-mono text-blue-600 dark:text-blue-400 border-b border-gray-200 dark:border-slate-700 pb-2">
                 <span id="stats-summary">正在加载...</span>
            </div>

            <div id="stats-list" class="max-h-40 overflow-y-auto text-[10px] font-mono divide-y divide-gray-100 dark:divide-slate-700 pr-2">
            </div>
        </div>
      </div>
      
      <div class="section-box">
        <h2 class="text-lg font-bold mb-4 flex items-center gap-2 opacity-90">
          <svg class="w-5 h-5 text-gray-700 dark:text-gray-300" fill="currentColor" viewBox="0 0 24 24"><path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/></svg>
          GitHub 文件 / 脚本命令加速 (智能识别)
        </h2>
        <div class="flex flex-responsive gap-3">
          <input id="github-url" type="text" placeholder="粘贴 链接 或 bash/curl/git 完整命令" class="flex-grow p-3.5 rounded-lg text-sm">
          <button onclick="convertGithubUrl()" class="bg-blue-600 hover:bg-blue-700 text-white px-6 py-3.5 rounded-lg transition font-bold text-sm shadow-md whitespace-nowrap flex items-center justify-center gap-1">
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"/></svg>
              获取链接
          </button>
        </div>
        
        <div id="github-result-box" class="hidden mt-5">
           <div class="mb-6">
               <p class="text-xs font-bold text-gray-500 dark:text-gray-400 mb-2 uppercase tracking-wide">1. 加速链接 (Raw URL):</p>
               <div class="p-4 bg-emerald-50 dark:bg-emerald-900/20 border border-emerald-100 dark:border-emerald-800 rounded-lg mb-3">
                   <p id="github-result-url" class="text-emerald-700 dark:text-emerald-400 font-mono text-xs break-all select-all"></p>
               </div>
               <div class="flex gap-3">
                   <button onclick="copyGithubUrlOnly()" class="flex-1 bg-gray-100 dark:bg-slate-700 hover:bg-gray-200 dark:hover:bg-slate-600 text-gray-700 dark:text-gray-200 py-2.5 rounded-lg text-xs font-bold transition">复制链接</button>
                   <button onclick="openGithubUrl()" class="flex-1 bg-blue-50 dark:bg-blue-900/20 hover:bg-blue-100 dark:hover:bg-blue-900/40 text-blue-600 dark:text-blue-400 py-2.5 rounded-lg text-xs font-bold transition">立即访问</button>
               </div>
           </div>
           <div>
               <p id="github-cmd-label" class="text-xs font-bold text-gray-500 dark:text-gray-400 mb-2 uppercase tracking-wide">2. 终端命令:</p>
               <div class="p-4 bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg mb-3">
                  <p id="github-result-cmd" class="text-slate-700 dark:text-slate-300 font-mono text-xs break-all select-all"></p>
               </div>
               <button onclick="copyGithubCmd()" class="w-full bg-gray-100 dark:bg-slate-700 hover:bg-gray-200 dark:hover:bg-slate-600 text-gray-700 dark:text-gray-200 py-2.5 rounded-lg text-xs font-bold transition">复制命令</button>
           </div>
        </div>
      </div>

      <div class="section-box">
        <h2 class="text-lg font-bold mb-4 flex items-center gap-2 opacity-90">
          <span class="text-xl">🚀</span> 递归脚本加速 (Shell / Curl)
        </h2>
        <p class="text-xs opacity-60 mb-3">适用于 <code>curl | bash</code> 脚本。系统会强制重写脚本内部的所有下载链接。</p>
        <div class="flex flex-responsive gap-3">
          <input id="recursive-url" type="text" placeholder="如: https://get.docker.com 或粘贴 bash <(curl ...)" class="flex-grow p-3.5 rounded-lg text-sm">
          <button onclick="convertRecursiveUrl()" class="bg-blue-600 hover:bg-blue-700 text-white px-6 py-3.5 rounded-lg transition font-bold text-sm shadow-md whitespace-nowrap flex items-center justify-center gap-1">
               <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19.428 15.428a2 2 0 00-1.022-.547l-2.384-.477a6 6 0 00-3.86.517l-.318.158a6 6 0 01-3.86.517L6.05 15.21a2 2 0 00-1.806.547M8 4h8l-1 1v5.172a2 2 0 00.586 1.414l5 5c1.26 1.26.367 3.414-1.415 3.414H4.828c-1.782 0-2.674-2.154-1.414-3.414l5-5A2 2 0 009 10.172V5L8 4z"/></svg>
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
                 <p id="recursive-cmd-label" class="text-xs font-bold text-gray-500 dark:text-gray-400 mb-2 uppercase tracking-wide">2. 终端命令 (Bash):</p>
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
               <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 19l9 2-9-18-9 18 9-2zm0 0v-8"/></svg>
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

      <div class="section-box">
        <h2 class="text-lg font-bold mb-4 flex items-center gap-2 opacity-90">
          <span class="text-xl">🐧</span> Linux 软件源加速 (Range 支持)
        </h2>
        <div class="flex flex-responsive gap-3">
          <select id="linux-distro" class="flex-none p-3.5 rounded-lg text-sm bg-gray-50 dark:bg-slate-800 border-r-8 border-transparent outline-none">
             </select>
          <button onclick="generateLinuxCommand()" class="bg-orange-600 hover:bg-orange-700 text-white px-6 py-3.5 rounded-lg transition font-bold text-sm shadow-md whitespace-nowrap flex items-center justify-center gap-1 w-full md:w-auto">
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/></svg>
              生成换源命令
          </button>
        </div>
        <div id="linux-result-box" class="hidden mt-5">
            <p class="text-xs opacity-70 mb-2">使用以下命令一键替换：</p>
            <div class="p-4 bg-orange-50 dark:bg-orange-900/20 border border-orange-100 dark:border-orange-800 rounded-lg mb-3">
                <p id="linux-result" class="text-orange-700 dark:text-orange-400 font-mono text-xs break-all select-all"></p>
            </div>
            <p class="text-[10px] opacity-60 mt-2 mb-2">
                * 注意：脚本仅替换官方默认源。若您已使用其他镜像源（如阿里云），请手动编辑文件。
            </p>
            <button onclick="copyLinuxCommand()" class="w-full bg-gray-100 dark:bg-slate-700 hover:bg-gray-200 dark:hover:bg-slate-600 text-gray-700 dark:text-gray-200 py-2.5 rounded-lg text-xs font-bold transition">复制命令</button>
        </div>
      </div>
 
      <div class="section-box">
          <h2 class="text-lg font-bold mb-4 flex items-center gap-2 opacity-90">
              <svg class="w-5 h-5 text-purple-600 dark:text-purple-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/></svg>
              镜像源配置 (Daemon.json)
          </h2>
          <div class="code-area rounded-lg p-4 overflow-x-auto text-sm">
              <p class="text-gray-500 dark:text-gray-500 mb-1"># 1. 编辑配置文件</p>
              <p class="font-mono text-blue-600 dark:text-blue-400 font-bold mb-4">nano /etc/docker/daemon.json</p>
              <p class="text-gray-500 dark:text-gray-500 mb-1"># 2. 填入以下内容</p>
              <pre id="daemon-json-content" class="font-mono text-emerald-600 dark:text-emerald-400 mb-4 bg-transparent p-0 border-0"></pre>
              <p class="text-gray-500 dark:text-gray-500 mb-1"># 3. 重启 Docker</p>
              <p class="font-mono text-blue-600 dark:text-blue-400 font-bold">sudo systemctl daemon-reload && sudo systemctl restart docker</p>
          </div>
          <button onclick="copyDaemonJson()" class="mt-4 px-4 py-2 bg-gray-800 dark:bg-white hover:bg-black dark:hover:bg-gray-200 text-white dark:text-black rounded-lg text-xs font-bold transition shadow-sm flex items-center gap-2">
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 5H6a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2v-1M8 5a2 2 0 002 2h2a2 2 0 002-2M8 5a2 2 0 012-2h2a2 2 0 012 2m0 0h2a2 2 0 012 2v3m2 4H10m0 0l3-3m-3 3l3 3"/></svg>
              复制配置
          </button>
      </div>
 
      <footer class="mt-12 text-center pb-8">
            <a href="https://github.com/Kevin-YST-Du/Cloudflare-ProxyX" target="_blank" class="text-[10px] text-blue-600 dark:text-blue-400 uppercase tracking-widest font-bold opacity-80 hover:opacity-100 hover:underline transition-all">Powered by Kevin-YST-Du/Cloudflare-ProxyX</a>
      </footer>
    </div>
 
    <div id="confirmModal" class="modal-overlay">
      <div class="modal-content">
         <div class="text-center">
            <div class="w-12 h-12 bg-blue-100 dark:bg-blue-900/30 rounded-full flex items-center justify-center mb-4 mx-auto text-blue-500">
               <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
            </div>
            <h3 class="text-lg font-bold mb-2">确认重置额度？</h3>
            <p class="text-sm opacity-70 mb-6 px-4">此操作将清空您当前 IP (${ip}) 在今日的请求记录记录。</p>
            <div class="flex gap-3">
               <button onclick="closeModal('confirmModal')" class="flex-1 px-4 py-2.5 bg-gray-100 hover:bg-gray-200 dark:bg-slate-700 dark:hover:bg-slate-600 rounded-lg text-sm font-bold transition">取消</button>
               <button onclick="confirmReset()" class="flex-1 px-4 py-2.5 bg-red-500 hover:bg-red-600 text-white rounded-lg text-sm font-bold transition shadow-lg shadow-red-500/30">确定重置</button>
            </div>
         </div>
      </div>
    </div>

    <div id="confirmResetAllModal" class="modal-overlay">
      <div class="modal-content">
         <div class="text-center">
            <div class="w-12 h-12 bg-red-100 dark:bg-red-900/30 rounded-full flex items-center justify-center mb-4 mx-auto text-red-500">
               <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path></svg>
            </div>
            <h3 class="text-2xl font-bold mb-2">⚠️ 高能预警</h3>
            <p class="text-1xl opacity-70 mb-2 px-4">确定要清空【所有用户】的统计数据吗？</p>
            <p class="text-1xl text-red-500 font-bold mb-6">此操作不可恢复！</p>
            <div class="flex gap-3">
               <button onclick="closeResetAllModal()" class="flex-1 px-4 py-2.5 bg-gray-100 hover:bg-gray-200 dark:bg-slate-700 dark:hover:bg-slate-600 rounded-lg text-sm font-bold transition">取消</button>
               <button onclick="confirmResetAll()" class="flex-1 px-4 py-2.5 bg-red-600 hover:bg-red-700 text-white rounded-lg text-sm font-bold transition shadow-lg shadow-red-600/30">确认清空</button>
            </div>
         </div>
      </div>
    </div>

    <div id="toast" class="toast bg-slate-800 text-white"></div>

    <script>
      try {
          // --- 初始化全局变量 ---
          window.CURRENT_DOMAIN = window.location.hostname + (window.location.port ? ':' + window.location.port : '');
          window.WORKER_PASSWORD = "${password}"; 
          window.CURRENT_CLIENT_IP = "${ip}";
          window.LINUX_MIRRORS = ${linuxMirrorsJson};
          
          let githubAcceleratedUrl = '';
          let githubOpenUrl = '';
          let githubCommand = ''; 

          let recursiveCommand = '';
          let recursiveUrlOnly = '';
          let dockerCommand = '';
          let linuxCommand = '';
          
          // --- 填充 Linux 发行版下拉框 ---
          const linuxSelect = document.getElementById('linux-distro');
          if (linuxSelect) {
              const mainMirrors = window.LINUX_MIRRORS.filter(m => !m.includes('-security'));
              mainMirrors.forEach(distro => {
                  const opt = document.createElement('option');
                  opt.value = distro;
                  opt.textContent = distro.charAt(0).toUpperCase() + distro.slice(1);
                  linuxSelect.appendChild(opt);
              });
          }
          
          // --- 自动生成 daemon.json 内容 ---
          const daemonJsonObj = { "registry-mirrors": ["https://" + window.CURRENT_DOMAIN] };
          const daemonJsonStr = JSON.stringify(daemonJsonObj, null, 2);
          const daemonEl = document.getElementById('daemon-json-content');
          if (daemonEl) daemonEl.textContent = daemonJsonStr;
 
          // --- 主题切换逻辑 ---
          window.toggleTheme = function() {
            try {
                const body = document.body;
                const sun = document.querySelector('.sun');
                const moon = document.querySelector('.moon');
                if (body.classList.contains('light-mode')) {
                  body.classList.remove('light-mode'); body.classList.add('dark-mode');
                  sun.classList.add('hidden'); moon.classList.remove('hidden');
                  localStorage.setItem('theme', 'dark');
                } else {
                  body.classList.remove('dark-mode'); body.classList.add('light-mode');
                  moon.classList.add('hidden'); sun.classList.remove('hidden');
                  localStorage.setItem('theme', 'light');
                }
            } catch(e) { console.error('Theme toggle error:', e); }
          }
          
          // 页面加载时恢复主题设置
          try { if (localStorage.getItem('theme') === 'dark') window.toggleTheme(); } catch(e) {}
 
          // --- 提示框 (Toast) 工具 ---
          window.showToast = function(message, isError = false) {
            const toast = document.getElementById('toast');
            toast.innerHTML = message;
            toast.className = 'toast ' + (isError ? 'bg-red-500' : 'bg-slate-800') + ' show';
            setTimeout(() => toast.classList.remove('show'), 3000);
          }
 
          // --- 模态框控制 ---
          window.openModal = function(id) { document.getElementById(id).classList.add('open'); }
          window.closeModal = function(id) { document.getElementById(id).classList.remove('open'); }
 
          // --- 剪贴板复制工具 ---
          window.copyToClipboard = function(text) {
            if (navigator.clipboard && window.isSecureContext) { 
                return navigator.clipboard.writeText(text); 
            }
            // 降级方案：HTTP 环境兼容
            const textArea = document.createElement("textarea");
            textArea.value = text; textArea.style.position = "fixed"; textArea.style.left = "-9999px";
            document.body.appendChild(textArea); textArea.focus(); textArea.select();
            try { 
                document.execCommand('copy'); 
                document.body.removeChild(textArea); 
                return Promise.resolve(); 
            } catch (err) { 
                document.body.removeChild(textArea); 
                return Promise.reject(err); 
            }
          }
 
          // ======================================================================
          // 核心逻辑: GitHub/通用加速 (智能识别 Git Clone vs Wget)
          // ======================================================================
          window.convertGithubUrl = function() {
            let input = document.getElementById('github-url').value.trim();
            if (!input) return window.showToast('❌ 请输入内容', true);

            const urlRegex = /(https?:\\/\\/[^\\s"'\)<>]+)/;
            const match = input.match(urlRegex);
            let originalUrl = "";

            if (match) {
                originalUrl = match[0];
            } else {
                if (!input.includes(' ')) {
                    originalUrl = 'https://' + input;
                } else {
                    return window.showToast('❌ 无法识别有效链接', true);
                }
            }
            
            // 修复双斜杠问题
            originalUrl = originalUrl.replace(/^(https?):\/+/, '$1://');

            const prefix = window.location.protocol + '//' + window.CURRENT_DOMAIN + '/' + window.WORKER_PASSWORD + '/';
            const proxiedUrl = prefix + originalUrl;

            let finalCommand = "";
            let label = "";

            // 判断是否为纯链接
            const isPureUrl = (input === match?.[0]) || (('https://' + input) === originalUrl);
            
            // 判断是否为 GitHub 仓库主页 (而非文件)
            const repoRegex = /^https?:\\/\\/(?:www\\.)?github\\.com\\/[^\\/]+\\/[^\\/]+(?:\\.git)?\\/?$/;

            if (isPureUrl) {
                if (repoRegex.test(originalUrl)) {
                    // 场景 A: 是仓库主页 -> Git Clone
                    finalCommand = 'git clone ' + proxiedUrl;
                    label = "终端命令 (Git Clone):";
                    window.showToast('✅ 已识别为仓库');
                } else {
                    // 场景 B: 是具体文件 -> Wget
                    const fileName = originalUrl.split('/').pop() || 'download';
                    finalCommand = 'wget -c -O "' + fileName + '" "' + proxiedUrl + '"';
                    label = "终端命令 (Wget):";
                    window.showToast('✅ 已生成 Wget 命令');
                }
            } else {
                // 场景 C: 是完整命令 -> 替换链接
                finalCommand = input.replace(originalUrl, proxiedUrl);
                label = "终端命令 (自动替换):";
                window.showToast('✅ 已替换命令中的链接');
            }

            githubAcceleratedUrl = proxiedUrl;
            githubOpenUrl = proxiedUrl;
            githubCommand = finalCommand; 

            document.getElementById('github-result-url').textContent = proxiedUrl;
            document.getElementById('github-cmd-label').textContent = "2. " + label;
            document.getElementById('github-result-cmd').textContent = finalCommand;
            
            document.getElementById('github-result-box').classList.remove('hidden');
          }
          
          window.copyGithubUrlOnly = function() { window.copyToClipboard(githubAcceleratedUrl).then(() => window.showToast('✅ 链接已复制')); }
          window.openGithubUrl = function() { window.open(githubOpenUrl, '_blank'); }
          window.copyGithubCmd = function() { window.copyToClipboard(githubCommand).then(() => window.showToast('✅ 命令已复制')); }

          // ======================================================================
          // 核心逻辑: 递归脚本加速 (Wget/Bash/Git Clone 智能三合一)
          // ======================================================================
          window.convertRecursiveUrl = function() {
            let input = document.getElementById('recursive-url').value.trim();
            if (!input) return window.showToast('❌ 请输入链接', true);
            
            // 1. 提取 URL
            const urlMatch = input.match(/(https?:\\/\\/[^\\s"'\)]+)/);
            let targetUrl = input;
            if (urlMatch) {
                targetUrl = urlMatch[0]; 
            } else {
                if (!targetUrl.startsWith('http')) { targetUrl = 'https://' + targetUrl; }
            }
            // 修复双斜杠
            targetUrl = targetUrl.replace(/^(https?):\/+/, '$1://');
            
            // 2. 构造两种代理路径
            const baseUrl = window.location.protocol + '//' + window.CURRENT_DOMAIN + '/' + window.WORKER_PASSWORD + '/';
            const rawProxyUrl = baseUrl + targetUrl;       // 不带 /r/
            const recursiveProxyUrl = baseUrl + 'r/' + targetUrl; // 带 /r/

            // 3. 智能判断生成模式
            const isCommand = input.includes('bash') || input.includes('curl') || input.includes('wget') || input.includes(' ');
            const repoRegex = /^https?:\\/\\/(?:www\\.)?github\\.com\\/[^\\/]+\\/[^\\/]+(?:\\.git)?\\/?$/;

            let label = "";
            let displayUrl = recursiveProxyUrl; // 默认显示递归链接

            if (isCommand && urlMatch) {
                 // 场景 A: 完整命令
                 if (input.includes('git clone') || repoRegex.test(targetUrl)) {
                     recursiveCommand = input.replace(targetUrl, rawProxyUrl);
                     displayUrl = rawProxyUrl;
                 } else {
                     recursiveCommand = input.replace(targetUrl, recursiveProxyUrl);
                 }
                 label = "终端命令 (自动替换):";
                 window.showToast('✅ 已替换命令中的链接');
            } else {
                 // 场景 B: 纯链接
                 if (repoRegex.test(targetUrl)) {
                     // B1: 是 GitHub 仓库 -> Git Clone -> 使用 Raw Path
                     recursiveCommand = 'git clone ' + rawProxyUrl;
                     displayUrl = rawProxyUrl; 
                     label = "终端命令 (Git Clone):";
                     window.showToast('✅ 已识别为仓库 (Raw模式)');
                 } else {
                     // B2: 是普通文件/脚本 -> Wget -> 使用 Recursive Path
                     const fileName = targetUrl.split('/').pop() || 'script';
                     recursiveCommand = 'wget -c -O "' + fileName + '" "' + recursiveProxyUrl + '"';
                     displayUrl = recursiveProxyUrl;
                     label = "终端命令 (Wget):";
                     window.showToast('✅ 已生成 Wget 命令');
                 }
            }
            
            recursiveUrlOnly = displayUrl; 
            
            document.getElementById('recursive-result-url').textContent = recursiveUrlOnly;
            document.getElementById('recursive-cmd-label').textContent = "2. " + label; 
            document.getElementById('recursive-result-cmd').textContent = recursiveCommand;
            document.getElementById('recursive-result-box').classList.remove('hidden');
          }
          
          window.copyRecursiveUrlOnly = function() { window.copyToClipboard(recursiveUrlOnly).then(() => window.showToast('✅ 链接已复制')); }
          window.openRecursiveUrl = function() { window.open(recursiveUrlOnly, '_blank'); }
          window.copyRecursiveCmd = function() { window.copyToClipboard(recursiveCommand).then(() => window.showToast('✅ 命令已复制')); }
 
          // --- 业务逻辑: Docker 镜像 ---
          window.convertDockerImage = function() {
            const input = document.getElementById('docker-image').value.trim();
            if (!input) return window.showToast('❌ 请输入镜像名', true);
            dockerCommand = 'docker pull ' + window.CURRENT_DOMAIN + '/' + input;
            document.getElementById('docker-result').textContent = dockerCommand;
            document.getElementById('docker-result-box').classList.remove('hidden');
            window.copyToClipboard(dockerCommand).then(() => window.showToast('✅ 已复制'));
          }
          window.copyDockerCommand = function() { window.copyToClipboard(dockerCommand).then(() => window.showToast('✅ 已复制')); }
          
          // --- 业务逻辑: Linux 换源 ---
          window.generateLinuxCommand = function() {
              const distro = document.getElementById('linux-distro').value;
              const baseUrl = window.location.protocol + '//' + window.CURRENT_DOMAIN + '/' + window.WORKER_PASSWORD + '/' + distro + '/';
              const securityUrl = window.location.protocol + '//' + window.CURRENT_DOMAIN + '/' + window.WORKER_PASSWORD + '/' + distro + '-security/';
              
              if (distro === 'ubuntu') {
                  linuxCommand = 'sudo sed -i "s|http://archive.ubuntu.com/ubuntu/|' + baseUrl + '|g" /etc/apt/sources.list && ' +
                                 'sudo sed -i "s|https://archive.ubuntu.com/ubuntu/|' + baseUrl + '|g" /etc/apt/sources.list && ' +
                                 'sudo sed -i "s|http://security.ubuntu.com/ubuntu/|' + securityUrl + '|g" /etc/apt/sources.list && ' +
                                 'sudo sed -i "s|https://security.ubuntu.com/ubuntu/|' + securityUrl + '|g" /etc/apt/sources.list';
              } else if (distro === 'debian') {
                  linuxCommand = 'sudo sed -i "s|http://deb.debian.org/debian|' + baseUrl + '|g" /etc/apt/sources.list && ' +
                                 'sudo sed -i "s|https://deb.debian.org/debian|' + baseUrl + '|g" /etc/apt/sources.list && ' +
                                 'sudo sed -i "s|http://security.debian.org/debian-security|' + securityUrl + '|g" /etc/apt/sources.list && ' +
                                 'sudo sed -i "s|https://security.debian.org/debian-security|' + securityUrl + '|g" /etc/apt/sources.list';
              } else if (distro === 'centos') {
                  linuxCommand = 'sudo sed -i "s/mirrorlist/#mirrorlist/g" /etc/yum.repos.d/*.repo && ' +
                                 'sudo sed -i "s|#baseurl=http://mirror.centos.org|baseurl=' + baseUrl + '|g" /etc/yum.repos.d/*.repo && ' +
                                 'sudo sed -i "s|baseurl=http://mirror.centos.org|baseurl=' + baseUrl + '|g" /etc/yum.repos.d/*.repo';
              } else if (distro === 'termux') {
                  linuxCommand = 'sed -i "s|https://[^ ]*termux[^ ]*|' + baseUrl + '|g" $PREFIX/etc/apt/sources.list';
              } else {
                  linuxCommand = '# 基础 URL:\\n' + baseUrl;
              }
              
              document.getElementById('linux-result').textContent = linuxCommand;
              document.getElementById('linux-result-box').classList.remove('hidden');
              window.copyToClipboard(linuxCommand).then(() => window.showToast('✅ 已复制换源命令'));
          }
          window.copyLinuxCommand = function() { window.copyToClipboard(linuxCommand).then(() => window.showToast('✅ 已复制')); }

          window.copyDaemonJson = function() { window.copyToClipboard(daemonJsonStr).then(() => window.showToast('✅ JSON 配置已复制')); }
 
          // --- 业务逻辑: 重置额度 ---
          window.confirmReset = async function() {
            window.closeModal('confirmModal');
            try {
              const res = await fetch('/' + window.WORKER_PASSWORD + '/reset');
              const data = await res.json();
              if (res.ok) { window.showToast('✅ 额度已重置'); setTimeout(() => location.reload(), 800); } 
              else { window.showToast('❌ ' + (data.message || '无权操作'), true); }
            } catch (e) { window.showToast('❌ 网络错误', true); }
          }

          window.openResetAllModal = function() { document.getElementById('confirmResetAllModal').classList.add('open'); }
          window.closeResetAllModal = function() { document.getElementById('confirmResetAllModal').classList.remove('open'); }

          window.confirmResetAll = async function() {
            window.closeResetAllModal(); 
            try {
              const res = await fetch('/' + window.WORKER_PASSWORD + '/reset-all');
              if (res.ok) { window.showToast('✅ 全站数据已清空'); window.viewAllStats(); setTimeout(() => location.reload(), 1000); } 
              else { window.showToast('❌ 操作失败', true); }
            } catch (e) { window.showToast('❌ 网络错误', true); }
          }

          window.viewAllStats = async function() {
                const panel = document.getElementById('stats-panel');
                panel.classList.toggle('hidden');
                if (panel.classList.contains('hidden')) return;
                try {
                    if (panel.innerHTML.includes('正在加载...')) window.showToast('正在获取全站数据...');
                    const res = await fetch('/' + window.WORKER_PASSWORD + '/stats');
                    const result = await res.json();
                    if (res.ok && result.status === "success") {
                        const { totalRequests, uniqueIps, details } = result.data;
                        document.getElementById('stats-summary').textContent = '总请求: ' + totalRequests + ' | 活跃IP: ' + uniqueIps;
                        const listContainer = document.getElementById('stats-list');
                        let html = '';
                        if (details && details.length > 0) {
                            for (let i = 0; i < details.length; i++) {
                                const item = details[i];
                                const isMe = item.ip === window.CURRENT_CLIENT_IP;
                                const ipClass = isMe ? 'text-blue-500 font-bold' : 'opacity-70';
                                html += '<div class="flex justify-between py-1.5 hover:bg-gray-100 dark:hover:bg-slate-700/50 px-2 rounded cursor-default">';
                                html +=   '<span class="' + ipClass + '">' + item.ip + '</span>';
                                html +=   '<span class="font-bold">' + item.count + ' 次</span>';
                                html += '</div>';
                            }
                        } else { html = '<div class="text-center py-2 opacity-50">暂无数据</div>'; }
                        listContainer.innerHTML = html;
                    } else { window.showToast('❌ 获取失败', true); }
                } catch (e) { console.error(e); window.showToast('❌ 网络错误', true); }
            }
      } catch(err) { console.error("Dashboard Script Error:", err); }
    </script>
</body>
</html>
    `;
}