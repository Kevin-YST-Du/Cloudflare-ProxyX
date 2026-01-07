/**
 * -----------------------------------------------------------------------------------------
 * Cloudflare Worker: 终极 Docker & Linux 代理 (v4.3 - 递归缓存增强版)
 * -----------------------------------------------------------------------------------------
 * 核心功能：
 * 1. Docker Hub/GHCR 等镜像仓库加速下载。
 * 2. 智能处理 Docker 的 library/ 命名空间补全。
 * 3. Linux 软件源加速，支持 debian-security 及 Range 断点续传。
 * 4. 双模式通用代理 (Raw / Recursive)。
 * 5. [增强] 递归模式集成 Cache API，极大提升脚本二次访问速度。
 * 6. Dashboard: 递归加速模块样式与 GitHub 文件加速模块完全一致。
 * -----------------------------------------------------------------------------------------
 */

// ==============================================================================
// 1. 全局配置与常量定义
// ==============================================================================

const DEFAULT_CONFIG = {
    // --- 基础配置 ---
    PASSWORD: "123456",               // 访问密码 (用于 Web 界面登录和通用代理的路径验证)
    MAX_REDIRECTS: 5,                 // 代理请求时允许的最大重定向次数 (防止死循环)
    ENABLE_CACHE: true,               // 是否开启 Worker 级缓存 (减少回源请求，重点优化递归模式)
    CACHE_TTL: 3600,                  // 缓存存活时间 (单位: 秒，默认1小时)
    
    // --- 访问控制 (安全设置) ---
    BLACKLIST: "",                    // 域名黑名单 (逗号分隔，禁止代理这些域名的内容)
    WHITELIST: "",                    // 域名白名单 (逗号分隔，如果不为空，则只允许代理这些域名)
    ALLOW_IPS: "",                    // 允许访问本 Worker 的客户端 IP (空则允许所有)
    ALLOW_COUNTRIES: "",              // 允许访问的国家代码 (如 CN, US)
    
    // --- 额度限制 (依赖 KV 存储) ---
    DAILY_LIMIT_COUNT: 200,           // 每个 IP 每日最大请求次数 (防滥用)
    
    // --- 权限管理 ---
    // 管理员 IP 列表 (拥有重置额度、查看统计、清空全站数据的权限)
    ADMIN_IPS: `
    127.0.0.1
    `,                    
    
    // 免额度 IP 白名单 (这些 IP 的请求不计入每日限额，例如你自己的服务器 IP)
    IP_LIMIT_WHITELIST: `
    127.0.0.1
    `, 
};

// 支持的 Docker Registry 上游列表 (用于判断请求是否指向已知的 Registry)
const DOCKER_REGISTRIES = [
    'docker.io', 'registry-1.docker.io', 'quay.io', 'gcr.io', 
    'k8s.gcr.io', 'registry.k8s.io', 'ghcr.io', 'docker.cloudsmith.io'
];

// Docker 简写映射：将用户输入的 registry 别名映射到完整的 HTTPS URL
const REGISTRY_MAP = {
    'ghcr.io': 'https://ghcr.io',
    'quay.io': 'https://quay.io',
    'gcr.io': 'https://gcr.io',
    'k8s.gcr.io': 'https://k8s.gcr.io',
    'registry.k8s.io': 'https://registry.k8s.io',
    'docker.cloudsmith.io': 'https://docker.cloudsmith.io',
    'nvcr.io': 'https://nvcr.io'
};

// Linux 软件源镜像映射 (Key: URL路径前缀, Value: 上游官方源地址)
const LINUX_MIRRORS = {
    'ubuntu': 'http://archive.ubuntu.com/ubuntu',
    'ubuntu-security': 'http://security.ubuntu.com/ubuntu', // Ubuntu 安全源单独处理
    'debian': 'http://deb.debian.org/debian',
    'debian-security': 'http://security.debian.org/debian-security', // Debian 安全源单独处理
    'centos': 'https://vault.centos.org',
    'centos-stream': 'http://mirror.stream.centos.org',
    'rockylinux': 'https://download.rockylinux.org/pub/rocky', // Rocky Linux (CentOS 替代品)
    'almalinux': 'https://repo.almalinux.org/almalinux', // AlmaLinux (CentOS 替代品)
    'fedora': 'https://download.fedoraproject.org/pub/fedora/linux', 
    'alpine': 'http://dl-cdn.alpinelinux.org/alpine',
    'kali': 'http://http.kali.org/kali',
    'archlinux': 'https://geo.mirror.pkgbuild.com',
    'termux': 'https://packages.termux.org/apt/termux-main'      
};

// 网站图标 (一个简单的闪电 SVG)
const LIGHTNING_SVG = `<svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M13 2L3 14H12L11 22L21 10H12L13 2Z" stroke="#F59E0B" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>`;

// ==============================================================================
// 2. Worker 主入口 (Main Handler)
// ==============================================================================

export default {
    async fetch(request, env, ctx) {
        // 工具函数：将环境变量中的逗号/换行符分割的字符串转为数组
        const parseList = (v, d) => (v || d).split(/[\n,]/).map(s => s.trim()).filter(s => s.length > 0);
        
        // --- 初始化配置 ---
        // 优先读取 Cloudflare 环境变量 (env)，如果不存在则使用代码顶部的默认值
        const CONFIG = {
            PASSWORD: env.PASSWORD || DEFAULT_CONFIG.PASSWORD,
            ADMIN_IPS: parseList(env.ADMIN_IPS, DEFAULT_CONFIG.ADMIN_IPS),
            MAX_REDIRECTS: parseInt(env.MAX_REDIRECTS || DEFAULT_CONFIG.MAX_REDIRECTS),
            ENABLE_CACHE: (env.ENABLE_CACHE || "true") === "true",
            CACHE_TTL: parseInt(env.CACHE_TTL || DEFAULT_CONFIG.CACHE_TTL),
            BLACKLIST: parseList(env.BLACKLIST, DEFAULT_CONFIG.BLACKLIST),
            WHITELIST: parseList(env.WHITELIST, DEFAULT_CONFIG.WHITELIST),
            ALLOW_IPS: parseList(env.ALLOW_IPS, DEFAULT_CONFIG.ALLOW_IPS),
            ALLOW_COUNTRIES: parseList(env.ALLOW_COUNTRIES, DEFAULT_CONFIG.ALLOW_COUNTRIES),
            DAILY_LIMIT_COUNT: parseInt(env.DAILY_LIMIT_COUNT || DEFAULT_CONFIG.DAILY_LIMIT_COUNT),
            IP_LIMIT_WHITELIST: parseList(env.IP_LIMIT_WHITELIST, DEFAULT_CONFIG.IP_LIMIT_WHITELIST),
        };

        const url = new URL(request.url);
        const clientIP = request.headers.get("CF-Connecting-IP") || "0.0.0.0"; // 获取客户端真实IP
        const userAgent = (request.headers.get("User-Agent") || "").toLowerCase();
        
        // --- 2.0 处理静态资源请求 ---
        if (url.pathname === '/robots.txt') return new Response("User-agent: *\nDisallow: /", { headers: { "Content-Type": "text/plain" } });
        if (url.pathname === '/favicon.ico') return new Response(LIGHTNING_SVG, { headers: { "Content-Type": "image/svg+xml" } });

        // --- 2.1 处理 Docker 认证 Token 请求 ---
        // Docker 客户端在 pull 镜像前会先请求 /token 获取权限
        if (url.pathname === '/token') {
            return handleTokenRequest(request, url);
        }

        // --- 2.2 处理 CORS 预检请求 (OPTIONS) ---
        // 允许浏览器跨域访问 API
        if (request.method === "OPTIONS") {
            return new Response(null, {
                headers: {
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Methods": "GET, POST, OPTIONS, HEAD",
                    "Access-Control-Allow-Headers": "*",
                    "Access-Control-Max-Age": "86400",
                    "Docker-Distribution-API-Version": "registry/2.0"
                },
            });
        }

        // --- 2.3 安全与地区检查 ---
        // 如果配置了允许的 IP 或国家，则拒绝其他请求
        if (CONFIG.ALLOW_IPS.length > 0 || CONFIG.ALLOW_COUNTRIES.length > 0) {
            const country = request.cf ? request.cf.country : "XX";
            let allow = false;
            if (CONFIG.ALLOW_IPS.includes(clientIP)) allow = true;
            if (!allow && CONFIG.ALLOW_COUNTRIES.includes(country)) allow = true;
            if (!allow) return new Response(`Access Denied`, { status: 403 });
        }

        // --- 2.4 计费与限额检查 (Rate Limiting) ---
        const isWhitelisted = CONFIG.IP_LIMIT_WHITELIST.includes(clientIP);
        let currentUsage = 0;
        
        // 如果未加白名单且绑定了 KV 数据库，则读取当前 IP 的用量
        if (!isWhitelisted && env.IP_LIMIT_KV) {
             currentUsage = await getIpUsageCount(clientIP, env);
             if (currentUsage >= CONFIG.DAILY_LIMIT_COUNT) {
                 return new Response(`⚠️ Daily Limit Exceeded: ${currentUsage}/${CONFIG.DAILY_LIMIT_COUNT}`, { status: 429 });
             }
        }

        // 判断是否为 Docker 镜像下载请求 (用于决定是否扣除额度)
        // 只有获取 manifest (元数据) 或 blobs (层文件) 才计费
        const isDockerV2 = url.pathname.startsWith("/v2/");
        const isDockerCharge = isDockerV2 
            && (userAgent.includes("docker") || userAgent.includes("go-http") || userAgent.includes("containerd"))
            && (url.pathname.includes("/manifests/") || url.pathname.includes("/blobs/")) 
            && request.method === "GET";

        let shouldCharge = false;
        if (isDockerCharge && !isWhitelisted) {
            // 使用 Cache API 进行短时间去重 (防止同一个文件请求多次扣费)
            const isDuplicate = await checkIsDuplicate(clientIP, url.pathname);
            if (!isDuplicate) {
                shouldCharge = true;
                // 异步写入去重标记
                ctx.waitUntil(setDuplicateFlag(clientIP, url.pathname)); 
            }
        }

        // --- 2.5 核心业务路由分发 ---
        let response;
        try {
            if (isDockerV2) {
                // [分支 1] Docker 镜像加速逻辑
                response = await handleDockerRequest(request, url);
            } else {
                // [分支 2] 通用代理 / Dashboard / Linux 源
                const path = url.pathname;
                // 解析路径结构: /密码/目标URL
                const match = path.match(/^\/([^/]+)(?:\/(.*))?$/);
                
                // 密码验证：如果路径格式不对或密码错误，返回 404 (隐藏入口)
                if (!match || match[1] !== CONFIG.PASSWORD) {
                    return new Response("404 Not Found", { status: 404 });
                }

                const subPath = match[2];

                // --- 2.5.1 管理员 API 命令 ---
                // 重置当前 IP 额度
                if (subPath === "reset") {
                    if (!CONFIG.ADMIN_IPS.includes(clientIP)) return new Response("Forbidden", { status: 403 });
                    ctx.waitUntil(resetIpUsage(clientIP, env));
                    return new Response(JSON.stringify({ status: "success" }), { status: 200 });
                }
                // 清空全站数据 (危险操作)
                if (subPath === "reset-all") {
                    if (!CONFIG.ADMIN_IPS.includes(clientIP)) return new Response("Forbidden", { status: 403 });
                    ctx.waitUntil(resetAllIpStats(env));
                    return new Response(JSON.stringify({ status: "success" }), { status: 200 });
                }
                // 获取全站统计数据
                if (subPath === "stats") {
                    if (!CONFIG.ADMIN_IPS.includes(clientIP)) return new Response("Forbidden", { status: 403 });
                    const stats = await getAllIpStats(env);
                    return new Response(JSON.stringify({ status: "success", data: stats }), { status: 200 });
                }

                // --- 2.5.2 渲染 Dashboard ---
                // 如果没有提供子路径 (例如只访问 /密码)，则显示 Web 界面
                if (!subPath) {
                    return new Response(renderDashboard(url.hostname, CONFIG.PASSWORD, clientIP, currentUsage, CONFIG.DAILY_LIMIT_COUNT, CONFIG.ADMIN_IPS), {
                        status: 200, headers: { "Content-Type": "text/html;charset=UTF-8" }
                    });
                }

                // --- 2.5.3 Linux 软件源加速 ---
                // 检查子路径是否匹配 Linux 发行版名称 (如 ubuntu, centos)
                const sortedMirrors = Object.keys(LINUX_MIRRORS).sort((a, b) => b.length - a.length);
                const linuxDistro = sortedMirrors.find(k => subPath.startsWith(k + '/') || subPath === k);

                // --- 2.5.4 代理模式识别 (Raw vs Recursive) ---
                let proxyMode = 'raw'; // 默认为纯净模式 (不修改内容)
                let targetUrlPart = subPath;

                // 如果路径以 'r/' 开头，切换到递归模式 (自动重写内容中的链接)
                if (subPath.startsWith('r/') || subPath === 'r') {
                    proxyMode = 'recursive'; 
                    targetUrlPart = subPath.replace(/^r\/?/, ""); // 移除前缀，获取真实 URL
                }

                if (linuxDistro) {
                    // 进入 Linux 源加速逻辑
                    const realPath = subPath.replace(linuxDistro, '').replace(/^\//, '');
                    const upstreamBase = LINUX_MIRRORS[linuxDistro];
                    response = await handleLinuxMirrorRequest(request, upstreamBase, realPath);
                } else {
                    // 进入通用文件代理逻辑 (传入模式参数和 ctx 用于缓存)
                    response = await handleGeneralProxy(request, targetUrlPart + (url.search || ""), CONFIG, proxyMode, ctx);
                }
            }

            // --- 2.6 异步计费执行 ---
            // 如果请求成功且需要计费，则在后台更新 KV，不阻塞响应
            if (shouldCharge && response && response.status >= 200 && response.status < 400) {
                ctx.waitUntil(incrementIpUsage(clientIP, env));
            }

            return response;

        } catch (e) {
            // 全局错误捕获
            return new Response(JSON.stringify({ error: e.message }), { status: 500 });
        }
    }
};

// ==============================================================================
// 3. 辅助功能函数 (Token, Docker, Linux, KV)
// ==============================================================================

// --- 3.1 Docker 认证 Token 处理 ---
// 处理 /token 请求，将其转发给正确的上游 (Docker Hub 或其他 Registry)
async function handleTokenRequest(request, url) {
    const scope = url.searchParams.get('scope');
    let upstreamAuthUrl = 'https://auth.docker.io/token'; // 默认 Docker Hub
    
    // 根据 scope 参数判断上游是哪个 Registry
    for (const [domain, _] of Object.entries(REGISTRY_MAP)) {
        if (scope && scope.includes(domain)) {
            upstreamAuthUrl = `https://${domain}/token`;
            break;
        }
    }

    const newUrl = new URL(upstreamAuthUrl);
    newUrl.search = url.search;

    // Docker Hub 特殊处理：自动补全 library/ 前缀
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

    const newHeaders = new Headers(request.headers);
    newHeaders.set('Host', newUrl.hostname);
    // 伪装 User-Agent，防止被上游屏蔽
    newHeaders.set('User-Agent', 'Docker-Client/24.0.5 (linux)');
    newHeaders.delete('Cf-Connecting-Ip');
    newHeaders.delete('Cf-Worker');

    return fetch(new Request(newUrl, {
        method: request.method,
        headers: newHeaders,
        redirect: 'follow'
    }));
}

// --- 3.2 Docker 核心 V2 API 处理 ---
async function handleDockerRequest(request, url) {
    let path = url.pathname.replace(/^\/v2\//, '');
    let targetDomain = 'registry-1.docker.io'; 
    let upstream = 'https://registry-1.docker.io';
    
    // 根路径检查 (Docker Client 的连通性测试)
    if (path === '' || path === '/') {
        const rootReq = new Request('https://registry-1.docker.io/v2/', { method: 'GET', headers: request.headers });
        const resp = await fetch(rootReq);
        // 如果返回 401，需要重写 Auth 头，让 Client 向 Worker 请求 Token
        if (resp.status === 401) {
            return rewriteAuthHeader(resp, new URL(request.url).origin);
        }
        return resp;
    }

    // 路由识别：是 Docker Hub 还是 ghcr.io 等其他仓库
    const pathParts = path.split('/');
    if (REGISTRY_MAP[pathParts[0]]) {
        targetDomain = pathParts[0];
        upstream = REGISTRY_MAP[pathParts[0]];
        path = pathParts.slice(1).join('/');
    } else if (targetDomain === 'registry-1.docker.io') {
        // Docker Hub 智能补全 library/
        const p0 = pathParts[0];
        if (pathParts.length > 1 && !p0.includes('.') && p0 !== 'manifests' && p0 !== 'blobs' && p0 !== 'tags' && !p0.startsWith('sha256:')) {
            if (p0 !== 'library') {
                 if (pathParts[1] === 'manifests' || pathParts[1] === 'blobs' || pathParts[1] === 'tags') {
                     path = 'library/' + path;
                 }
            }
        }
    }

    const targetUrl = `${upstream}/v2/${path}` + url.search;
    const newHeaders = new Headers(request.headers);
    newHeaders.set('Host', targetDomain);
    newHeaders.set('User-Agent', 'Docker-Client/24.0.5 (linux)');
    newHeaders.delete('Cf-Connecting-Ip');
    
    // 手动处理重定向 (manual)，以便捕获 302 跳转到 S3 的链接
    const response = await fetch(targetUrl, {
        method: request.method,
        headers: newHeaders,
        body: request.body,
        redirect: 'manual' 
    });

    // 处理 401 认证挑战
    if (response.status === 401) {
        return rewriteAuthHeader(response, new URL(request.url).origin);
    }

    // 处理 302 重定向 (Blob 层文件下载)
    if ([301, 302, 303, 307, 308].includes(response.status)) {
        const location = response.headers.get('Location');
        if (location) {
            return handleBlobProxy(location, request);
        }
    }

    // 透传其他响应
    const finalResponse = new Response(response.body, response);
    finalResponse.headers.set('Access-Control-Allow-Origin', '*');
    finalResponse.headers.set('Docker-Distribution-API-Version', 'registry/2.0');
    return finalResponse;
}

// 辅助：重写 WWW-Authenticate 头，将 Realm 指向 Worker 自己的 /token
function rewriteAuthHeader(response, workerOrigin) {
    const newResp = new Response(response.body, response);
    const auth = response.headers.get('WWW-Authenticate');
    if (auth) {
        newResp.headers.set("Www-Authenticate", auth.replace(/realm="([^"]+)"/, `realm="${workerOrigin}/token"`));
        newResp.headers.set('Access-Control-Allow-Origin', '*');
    }
    return newResp;
}

// --- 3.3 Docker Blob 代理 (S3 中转) ---
// 代理下载实际的镜像层文件，支持 Range 断点续传
async function handleBlobProxy(targetUrl, originalRequest) {
    const newHeaders = new Headers();
    newHeaders.set('User-Agent', 'Docker-Client/24.0.5 (linux)');
    const range = originalRequest.headers.get('Range');
    if (range) newHeaders.set('Range', range);

    const upstreamResponse = await fetch(targetUrl, { 
        method: 'GET', 
        headers: newHeaders 
    });
    
    const proxyHeaders = new Headers(upstreamResponse.headers);
    proxyHeaders.set('Access-Control-Allow-Origin', '*');
    // 删除可能导致客户端校验失败的压缩头
    proxyHeaders.delete('Content-Encoding'); 
    proxyHeaders.delete('Transfer-Encoding');

    return new Response(upstreamResponse.body, {
        status: upstreamResponse.status,
        headers: proxyHeaders
    });
}

// --- 3.4 KV 计数与工具函数 ---
function getDate() { return new Date(new Date().getTime() + 28800000).toISOString().split('T')[0]; } // UTC+8

// 使用 Cache API 实现短时间去重 (Dedup)
async function checkIsDuplicate(ip, path) {
    const cache = caches.default;
    const key = `http://dedup.local/${ip}${path}`; 
    return !!(await cache.match(key)); 
}

async function setDuplicateFlag(ip, path) {
    const cache = caches.default;
    const key = `http://dedup.local/${ip}${path}`;
    await cache.put(key, new Response("1", { headers: { "Cache-Control": "max-age=5" } }));
}

// 新增 D1数据库 KV 读取/写入/重置逻辑 
async function getIpUsageCount(ip, env) {
    // 优先使用 D1 数据库
    if (env.DB) {
        try {
            const today = getDate();
            // 只需要读取 count 字段，节省读取行成本
            const result = await env.DB.prepare("SELECT count FROM ip_limits WHERE ip = ? AND date = ?")
                .bind(ip, today)
                .first();
            return result ? result.count : 0;
        } catch (e) {
            console.error("D1 Read Error:", e); // 出错降级到 KV
        }
    }

    // 降级使用 KV
    if (!env.IP_LIMIT_KV) return 0;
    const val = await env.IP_LIMIT_KV.get(`limit:${ip}:${getDate()}`);
    return parseInt(val || "0");
}

async function incrementIpUsage(ip, env) {
    // 优先使用 D1
    if (env.DB) {
        try {
            const today = getDate();
            const time = Date.now();
            // 【省额度核心】Upsert 语法：如果不存在则插入 1，如果存在则 +1。
            // 这是一个原子操作，且只消耗一次 D1 写入额度。
            await env.DB.prepare(`
                INSERT INTO ip_limits (ip, date, count, updated_at) 
                VALUES (?, ?, 1, ?) 
                ON CONFLICT(ip, date) 
                DO UPDATE SET count = count + 1, updated_at = ?
            `).bind(ip, today, time, time).run();
            return;
        } catch (e) {
            console.error("D1 Write Error:", e);
        }
    }

    // 降级使用 KV
    if (!env.IP_LIMIT_KV) return;
    const key = `limit:${ip}:${getDate()}`;
    // 注意：KV 并没有原子加操作，高并发下其实是不准的，D1 解决了这个问题
    const val = await env.IP_LIMIT_KV.get(key);
    await env.IP_LIMIT_KV.put(key, (parseInt(val || "0") + 1).toString(), { expirationTtl: 86400 });
}

async function resetIpUsage(ip, env) {
    if (env.DB) {
        try {
            await env.DB.prepare("DELETE FROM ip_limits WHERE ip = ? AND date = ?")
                .bind(ip, getDate())
                .run();
        } catch(e) { console.error(e); }
    }
    
    // 同时尝试删除 KV (保持数据同步，防止切回 KV 时数据错乱)
    if (env.IP_LIMIT_KV) {
        await env.IP_LIMIT_KV.delete(`limit:${ip}:${getDate()}`);
    }
}

async function resetAllIpStats(env) {
    if (env.DB) {
        // D1 清空非常快，直接 Truncate 或 Delete All
        try {
            await env.DB.prepare("DELETE FROM ip_limits").run();
        } catch(e) { console.error(e); }
    }

    // 同时也清空 KV
    if (env.IP_LIMIT_KV) {
        let cursor = null;
        do {
            const list = await env.IP_LIMIT_KV.list({ prefix: `limit:`, limit: 1000, cursor });
            cursor = list.cursor;
            for (const key of list.keys) {
                await env.IP_LIMIT_KV.delete(key.name);
            }
        } while (cursor); // 循环删除直到清空
    }
}

// 获取全站统计
async function getAllIpStats(env) {
    // 优先使用 D1 (性能极高)
    if (env.DB) {
        try {
            const today = getDate();
            
            // 1. 获取总请求数 (聚合查询)
            const sumResult = await env.DB.prepare("SELECT SUM(count) as total, COUNT(*) as unique_ips FROM ip_limits WHERE date = ?").bind(today).first();
            const total = sumResult.total || 0;
            const uniqueIps = sumResult.unique_ips || 0;

            // 2. 获取前 100 名详情 (排序查询)
            const listResult = await env.DB.prepare("SELECT ip, count FROM ip_limits WHERE date = ? ORDER BY count DESC LIMIT 100").bind(today).all();
            
            return { 
                totalRequests: total, 
                uniqueIps: uniqueIps, 
                details: listResult.results 
            };
        } catch (e) {
            console.error("D1 Stats Error:", e);
            // 出错不返回空，尝试走 KV
        }
    }

    // 降级 KV 逻辑 (保持原样，用于兼容)
    if (!env.IP_LIMIT_KV) return { totalRequests: 0, uniqueIps: 0, details: [] };
    const today = getDate();
    let total = 0;
    let details = [];
    // 注意：KV list 默认一次最多 1000 个，如果量大这里其实显示不全，这是 KV 的劣势
    const list = await env.IP_LIMIT_KV.list({ prefix: `limit:`, limit: 1000 }); 
    for (const key of list.keys) {
        const parts = key.name.split(':');
        // 过滤掉非今天的 key (如果有历史残留)
        if (parts.length === 3 && parts[2] === today) {
            // 这里有个性能坑：KV list 不返回 value，需要再次 get。
            // 为了不卡死，这里我们只在 KV 模式下做一个简单的近似统计，或者你接受慢一点
            // 优化：limit.metadata 可以存 count，但这里代码没存，所以只能读
            const val = await env.IP_LIMIT_KV.get(key.name);
            const count = parseInt(val || "0");
            total += count;
            details.push({ ip: parts[1], count: count });
        }
    }
    // 内存排序
    details.sort((a, b) => b.count - a.count);
    // 截取前 100
    return { totalRequests: total, uniqueIps: details.length, details: details.slice(0, 100) };
}

// --- 3.5 Linux 软件源加速逻辑 ---
async function handleLinuxMirrorRequest(request, upstreamBase, path) {
    const targetUrl = upstreamBase.endsWith('/') 
        ? upstreamBase + path 
        : upstreamBase + '/' + path;

    const newHeaders = new Headers(request.headers);
    newHeaders.delete('Cf-Connecting-Ip');
    newHeaders.delete('Cf-Worker');
    newHeaders.delete('Host'); 
    
    // 支持 Range 请求 (apt/yum 可能用到)
    const range = request.headers.get('Range');
    if (range) {
        newHeaders.set('Range', range);
    }

    try {
        const response = await fetch(targetUrl, {
            method: request.method,
            headers: newHeaders,
            redirect: 'follow'
        });

        const responseHeaders = new Headers(response.headers);
        responseHeaders.set('Access-Control-Allow-Origin', '*');
        
        // 透传 Range 相关头
        if (response.headers.has('Content-Range')) {
            responseHeaders.set('Content-Range', response.headers.get('Content-Range'));
        }
        if (response.headers.has('Accept-Ranges')) {
            responseHeaders.set('Accept-Ranges', response.headers.get('Accept-Ranges'));
        }

        return new Response(response.body, {
            status: response.status,
            headers: responseHeaders
        });

    } catch (e) {
        return new Response(`Linux Mirror Proxy Error: ${e.message}`, { status: 502 });
    }
}

// ==============================================================================
// 3.6 通用代理逻辑 (核心: Raw vs Recursive)
// ==============================================================================
async function handleGeneralProxy(request, targetUrlStr, CONFIG, mode = 'raw', ctx) {
    let currentUrlStr = targetUrlStr;
    
    // [修改] 容错增强：处理 Cloudflare 合并斜杠问题 (https:/ -> https://) 及补全协议
    if (currentUrlStr.startsWith("http")) {
        // 如果自带协议，强制修正斜杠数量为2个
        currentUrlStr = currentUrlStr.replace(/^(https?):\/+/, '$1://');
    } else {
        // 如果没带协议，补全 https://
        currentUrlStr = 'https://' + currentUrlStr;
    }

    // --- 缓存检查 (仅针对递归模式) ---
    // 递归模式涉及正则替换，消耗 CPU，且结果是纯文本，非常适合缓存。
    // 使用 request.url 作为缓存键。
    const cache = caches.default;
    const cacheKey = request.url; 
    
    if (mode === 'recursive' && CONFIG.ENABLE_CACHE) {
        // 尝试从缓存中获取响应
        const cachedResponse = await cache.match(cacheKey);
        if (cachedResponse) {
            // 命中缓存，直接返回 (Response 需要 clone 吗？match 返回的通常可以直接用)
            return cachedResponse;
        }
    }

    let finalResponse = null;
    const originalHeaders = new Headers(request.headers);

    try {
        // --- 1. 手动处理重定向循环 ---
        // 我们手动跟踪重定向，而不是让 fetch 自动处理，是为了更好地控制 Header 和流程
        let redirectCount = 0;
        while (redirectCount < CONFIG.MAX_REDIRECTS) {
            let currentTargetUrl;
            try { currentTargetUrl = new URL(currentUrlStr); } catch(e) { return new Response("Invalid URL: " + currentUrlStr, {status: 400}); }
            
            // 黑白名单检查
            const domain = currentTargetUrl.hostname;
            if (CONFIG.BLACKLIST.some(k => domain.includes(k))) return new Response("Blocked Domain", { status: 403 });
            if (CONFIG.WHITELIST.length > 0 && !CONFIG.WHITELIST.some(k => domain.includes(k))) return new Response("Blocked (Not Whitelisted)", { status: 403 });

            // 构造请求头
            const newHeaders = new Headers(originalHeaders);
            newHeaders.set("Host", currentTargetUrl.hostname);
            newHeaders.set("Referer", currentTargetUrl.origin + "/"); 
            newHeaders.set("Origin", currentTargetUrl.origin);
            
            // 伪装 User-Agent (许多脚本服务器会拒绝无 UA 的请求或 curl)
            if (!newHeaders.get("User-Agent")) {
                newHeaders.set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36");
            }
            
            // 传递 Range 头 (Raw 模式下下载大文件需要)
            const range = request.headers.get('Range');
            if (range) newHeaders.set('Range', range);

            // 清理 Cloudflare 自身产生的头，避免循环或被上游识别
            newHeaders.delete("Cf-Worker"); newHeaders.delete("Cf-Ray"); newHeaders.delete("Cookie"); newHeaders.delete("X-Forwarded-For");
            newHeaders.delete("Cf-Connecting-Ip");

            // 发起请求 (redirect: manual)
            const response = await fetch(currentUrlStr, {
                method: request.method, headers: newHeaders, body: request.body, redirect: "manual"
            });

            // 如果是重定向，提取 Location 并继续循环
            if ([301, 302, 303, 307, 308].includes(response.status)) {
                const location = response.headers.get("Location");
                if (location) {
                    currentUrlStr = new URL(location, currentUrlStr).href;
                    redirectCount++;
                    continue;
                }
            }
            finalResponse = response;
            break;
        }

        if (!finalResponse) throw new Error("Too many redirects");

        // --- 2. 构造响应头 ---
        const responseHeaders = new Headers(finalResponse.headers);
        // 清理安全策略头，允许我们在 Dashboard 中嵌入 (如果有需要) 或跨域使用
        responseHeaders.delete("Content-Security-Policy"); 
        responseHeaders.delete("Content-Security-Policy-Report-Only");
        responseHeaders.delete("Clear-Site-Data");
        responseHeaders.set("Access-Control-Allow-Origin", "*");
        
        // 调试头：标识当前的代理模式
        responseHeaders.set("X-Proxy-Mode", mode === 'recursive' ? "Recursive-Force-Text" : "Raw-Passthrough");

        // ==========================================
        // 模式 A: Raw (纯净模式)
        // ==========================================
        // 直接透传流，不修改内容，保持二进制完整性，适合 zip/iso/exe
        if (mode === 'raw') {
            return new Response(finalResponse.body, { status: finalResponse.status, headers: responseHeaders });
        }

        // ==========================================
        // 模式 B: Recursive (递归模式)
        // ==========================================
        // 强制读取文本，正则替换所有 http(s) 链接
        if (mode === 'recursive') {
            // [关键修复] 删除可能导致客户端解析错误的头
            // 如果上游返回了 Content-Encoding: gzip，Cloudflare 会自动解压
            // 如果我们不删除这个头，客户端会以为body还是压缩的，导致报错或乱码
            responseHeaders.delete("Content-Encoding");
            responseHeaders.delete("Content-Length"); // 内容长度会变，必须删掉让浏览器重新计算
            responseHeaders.delete("Transfer-Encoding");
            responseHeaders.delete("Content-Disposition"); // 防止强制下载

            // 强制读取文本 (Cloudflare 会自动解压 gzip)
            let text = await finalResponse.text();

            const workerOrigin = new URL(request.url).origin;
            const proxyBase = `${workerOrigin}/${CONFIG.PASSWORD}/r/`; 

            // 全局正则替换：匹配所有 http:// 或 https:// 开头的链接
            // 这是一个比较宽泛的正则，能匹配到大多数 URL
            const regex = /(https?:\/\/[a-zA-Z0-9][-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*))/g;
            
            text = text.replace(regex, (match) => {
                // 如果链接已经是本站域名的，则不替换，防止多重嵌套 (proxy of proxy)
                if (match.includes(workerOrigin)) return match;
                // 添加 /r/ 前缀，实现递归代理
                return proxyBase + match;
            });

            // 构造新的响应对象
            const modifiedResponse = new Response(text, { status: finalResponse.status, headers: responseHeaders });

            // --- 写入缓存 (仅在开启且处理成功时) ---
            if (CONFIG.ENABLE_CACHE && finalResponse.status === 200) {
                // 克隆响应，因为 body 只能被读取一次
                const responseToCache = modifiedResponse.clone();
                // 必须设置 Cache-Control 头，否则 Cloudflare Cache API 不会存储
                responseToCache.headers.set("Cache-Control", `public, max-age=${CONFIG.CACHE_TTL}`);
                // 异步写入缓存
                ctx.waitUntil(cache.put(cacheKey, responseToCache));
            }

            return modifiedResponse;
        }

    } catch (e) { return new Response(`Proxy Error: ${e.message}`, { status: 502 }); }
}

// ==============================================================================
// 4. Dashboard 渲染 (UI 界面)
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

/* ========== Light Mode ========== */
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

/* ========== Dark Mode ========== */
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

/* ========== Common Styles ========== */
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

/* ========== Responsive ========== */
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

/* ========== Top Navigation ========== */
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

/* ========== Toast ========== */
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

/* ========== Inputs ========== */
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

/* ========== Modal ========== */
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
          GitHub 文件加速 (Raw 纯净模式)
        </h2>
        <div class="flex flex-responsive gap-3">
          <input id="github-url" type="text" placeholder="粘贴 https://github.com/... 链接" class="flex-grow p-3.5 rounded-lg text-sm">
          <button onclick="convertGithubUrl()" class="bg-blue-600 hover:bg-blue-700 text-white px-6 py-3.5 rounded-lg transition font-bold text-sm shadow-md whitespace-nowrap flex items-center justify-center gap-1">
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"/></svg>
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
        <p class="text-xs opacity-60 mb-3">适用于 <code>curl | bash</code> 脚本。系统会强制重写脚本内部的所有下载链接。</p>
        <div class="flex flex-responsive gap-3">
          <input id="recursive-url" type="text" placeholder="如: https://get.docker.com" class="flex-grow p-3.5 rounded-lg text-sm">
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
              <svg class="w-5 h-5 text-purple-600 dark:text-purple-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/></svg>
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
          window.CURRENT_DOMAIN = window.location.hostname;
          window.WORKER_PASSWORD = "${password}"; 
          window.CURRENT_CLIENT_IP = "${ip}";
          window.LINUX_MIRRORS = ${linuxMirrorsJson};
          
          let githubAcceleratedUrl = '';
          let githubOpenUrl = '';
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
            if (navigator.clipboard && window.isSecureContext) { return navigator.clipboard.writeText(text); }
            const textArea = document.createElement("textarea");
            textArea.value = text; textArea.style.position = "fixed";
            document.body.appendChild(textArea); textArea.focus(); textArea.select();
            try { document.execCommand('copy'); document.body.removeChild(textArea); return Promise.resolve(); } 
            catch (err) { document.body.removeChild(textArea); return Promise.reject(err); }
          }
  
          // --- 业务逻辑: GitHub 加速 ---
          window.convertGithubUrl = function() {
            let input = document.getElementById('github-url').value.trim();
            if (!input) return window.showToast('❌ 请输入链接', true);
            if (!input.startsWith('http')) { input = 'https://' + input; }
            
            const prefix = window.location.origin + '/' + window.WORKER_PASSWORD + '/';
            const copyBtn = document.getElementById('btn-copy-github');
            
            const repoRegex = /^https?:\\/\\/(?:www\\.)?github\\.com\\/[^/]+\\/[^/]+(?:\\.git)?\\/?$/;
            
            if (input.endsWith('.git') || repoRegex.test(input)) {
                const accUrl = prefix + input;
                const gitCmd = 'git clone ' + accUrl;
                document.getElementById('github-result').innerHTML = 
                    '<span class="block mb-1 font-bold text-indigo-600">终端拉取命令:</span>' + gitCmd + 
                    '<br><br><span class="block mb-1 font-bold text-indigo-600">加速链接 (Raw):</span>' + accUrl;
                githubAcceleratedUrl = gitCmd; 
                githubOpenUrl = accUrl;        
                copyBtn.textContent = '复制命令';
                window.showToast('✅ 已识别为仓库');
            } else {
                githubAcceleratedUrl = prefix + input;
                githubOpenUrl = githubAcceleratedUrl;
                document.getElementById('github-result').textContent = githubAcceleratedUrl;
                copyBtn.textContent = '复制链接';
                window.copyToClipboard(githubAcceleratedUrl).then(() => window.showToast('✅ 已复制到剪贴板'));
            }
            document.getElementById('github-result-box').classList.remove('hidden');
          }
          
          window.copyGithubUrl = function() { window.copyToClipboard(githubAcceleratedUrl).then(() => window.showToast('✅ 已复制')); }
          window.openGithubUrl = function() { window.open(githubOpenUrl, '_blank'); }

          // --- 业务逻辑: 递归脚本加速 ---
          window.convertRecursiveUrl = function() {
            let input = document.getElementById('recursive-url').value.trim();
            if (!input) return window.showToast('❌ 请输入链接', true);
            if (!input.startsWith('http')) { input = 'https://' + input; }
            
            const prefix = window.location.origin + '/' + window.WORKER_PASSWORD + '/r/';
            const fullUrl = prefix + input;
            
            recursiveUrlOnly = fullUrl;
            recursiveCommand = 'bash <(curl -sL ' + fullUrl + ')';
            
            document.getElementById('recursive-result-url').textContent = recursiveUrlOnly;
            document.getElementById('recursive-result-cmd').textContent = recursiveCommand;
            document.getElementById('recursive-result-box').classList.remove('hidden');
          }
          
          window.copyRecursiveUrlOnly = function() { window.copyToClipboard(recursiveUrlOnly).then(() => window.showToast('✅ 链接已复制')); }
          window.openRecursiveUrl = function() { window.open(recursiveUrlOnly, '_blank'); }
          window.copyRecursiveCommand = function() { window.copyToClipboard(recursiveCommand).then(() => window.showToast('✅ 命令已复制')); }
  
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
              const baseUrl = window.location.origin + '/' + window.WORKER_PASSWORD + '/' + distro + '/';
              const securityUrl = window.location.origin + '/' + window.WORKER_PASSWORD + '/' + distro + '-security/';
              
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
              } else if (distro === 'rockylinux') {
                  linuxCommand = 'sudo sed -i "s/mirrorlist/#mirrorlist/g" /etc/yum.repos.d/rocky*.repo && ' +
                                 'sudo sed -i "s|#baseurl=http://dl.rockylinux.org/$contentdir|baseurl=' + baseUrl + '|g" /etc/yum.repos.d/rocky*.repo && ' +
                                 'sudo sed -i "s|baseurl=http://dl.rockylinux.org/$contentdir|baseurl=' + baseUrl + '|g" /etc/yum.repos.d/rocky*.repo';
              } else if (distro === 'almalinux') {
                  linuxCommand = 'sudo sed -i "s/mirrorlist/#mirrorlist/g" /etc/yum.repos.d/almalinux*.repo && ' +
                                 'sudo sed -i "s|#baseurl=https://repo.almalinux.org/almalinux|baseurl=' + baseUrl + '|g" /etc/yum.repos.d/almalinux*.repo && ' +
                                 'sudo sed -i "s|baseurl=https://repo.almalinux.org/almalinux|baseurl=' + baseUrl + '|g" /etc/yum.repos.d/almalinux*.repo';
              } else if (distro === 'fedora') {
                  linuxCommand = 'sudo sed -i "s/metalink/#metalink/g" /etc/yum.repos.d/fedora*.repo && ' +
                                 'sudo sed -i "s|#baseurl=http://download.example/pub/fedora/linux|baseurl=' + baseUrl + '|g" /etc/yum.repos.d/fedora*.repo && ' +
                                 'sudo sed -i "s|baseurl=http://download.example/pub/fedora/linux|baseurl=' + baseUrl + '|g" /etc/yum.repos.d/fedora*.repo';
              } else if (distro === 'alpine') {
                  linuxCommand = 'sudo sed -i "s|http://dl-cdn.alpinelinux.org/alpine|' + baseUrl + '|g" /etc/apk/repositories && ' +
                                 'sudo sed -i "s|https://dl-cdn.alpinelinux.org/alpine|' + baseUrl + '|g" /etc/apk/repositories';
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