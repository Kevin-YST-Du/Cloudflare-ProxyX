/**
 * -----------------------------------------------------------------------------------------
 * Cloudflare Worker: 终极 Docker & Linux 代理 (v5.3.0 - 随机伪装增强版)
 * -----------------------------------------------------------------------------------------
 * 核心功能：
 * 1. Docker Hub/GHCR 等镜像仓库加速下载。
 * 2. 智能处理 Docker 的 library/ 命名空间补全。
 * 3. Linux 软件源加速，支持 debian-security 及 Range 断点续传。
 * 4. 双模式通用代理 (Raw / Recursive)。
 * 5. [增强] 递归模式集成 Cache API，极大提升脚本二次访问速度。
 * 6. Dashboard: 递归加速模块样式与 GitHub 文件加速模块完全一致。
 * 7. [新增] 管理员 IP 免密访问 Dashboard 和代理服务。
 * 8. [升级] ALLOW_REFERER 支持多条规则，兼容纯域名和完整 URL 路径匹配。
 * 9. [新增] ALLOW_USER_AGENT 支持自定义 UA 免密。
 * 10.[新增] 免额度 IP (IP_LIMIT_WHITELIST) 自动获得免密访问权限。
 * 11.[兼容] 完美支持 D1 数据库进行额度统计，自动降级兼容 KV。
 * 12.[增强] 详细访问日志记录 (IP, URL, 时间, 状态码, 耗时, 上游)，仅管理员可见。
 * 13.[新增] 免费路径配置 (FREE_PATHS)，指定的路径不消耗每日额度。
 * 14.[新增 v5.0] HMAC 签名免密链接 (/s/过期时间/签名/目标)，支持过期控制与分享。
 * 15.[新增 v5.0] 递归模式智能识别 Content-Type，支持 HTML 相对路径重写。
 * 16.[新增 v5.0] 管理员专属 Debug 响应头与 CSV 日志导出。
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
    
    // [新增 v5.0] HMAC 签名密钥 (务必修改此值以确保安全)
    // 用于生成 /s/<exp>/<sig>/<target> 的免密链接
    SIGN_SECRET: "change-me-to-a-secure-random-string",

    // --- 访问控制 (安全设置) ---
    BLACKLIST: "",                    // 域名黑名单 (逗号分隔，禁止代理这些域名的内容)
    WHITELIST: "",                    // 域名白名单 (逗号分隔，如果不为空，则只允许代理这些域名)
    ALLOW_IPS: "",                    // 允许访问本 Worker 的客户端 IP (空则允许所有)
    ALLOW_COUNTRIES: "",              // 允许访问的国家代码 (如 CN, US)
    
    // --- 免密访问增强 ---
    // [修改] 指定允许免密访问的来源 Referer。支持逗号分隔多个。
    // 格式支持两种：
    // 1. 仅域名 (如 "github.com") -> 只要来源是该域名(或子域名)即通过。
    // 2. 完整 URL 前缀 (如 "https://github.com/Kevin-YST-Du") -> 必须以该路径开头才通过。
    ALLOW_REFERER: `
    github.com
    nodeseek.com
    `,                              
    
    // [新增] 指定允许免密访问的 User-Agent (浏览器/客户端标识)。
    // 只要请求头中的 User-Agent 包含此字符串，即允许免密下载/访问。
    // 例如设置为 "MySecretKey"，则 curl -A "MySecretKey" 即可直接访问。
    ALLOW_USER_AGENT: "", 

    // --- 额度限制 (依赖 KV 或 D1 存储) ---
    DAILY_LIMIT_COUNT: 200,           // 每个 IP 每日最大请求次数 (防滥用)
    
    // [新增] 免费路径列表 (不消耗额度的路径前缀)
    // 访问以下开头的路径将不会计入每日限制，通常用于 Linux 软件源
    FREE_PATHS: `
    ubuntu
    debian
    centos
    rockylinux
    almalinux
    fedora
    alpine
    kali
    termux
    `,

    // --- 权限管理 ---
    // 管理员 IP 列表 (拥有以下权限：
    // 1. 免密码直接访问 Dashboard 和代理路径
    // 2. 重置额度、查看统计、清空全站数据
    // 3. [新增] 查看详细的访问日志)
    ADMIN_IPS: `
    127.0.0.1
    `,                        
    
    // 免额度 IP 白名单 (这些 IP 的请求不计入每日限额，且自动免密访问)
    IP_LIMIT_WHITELIST: `
    127.0.0.1
    `, 

    // [新增] 伪装域名
    // 当访问没有带正确密码，且不是 Admin/白名单 IP 时，跳转到此地址。
    // 如果留空 ""，则保持原来的 404 Not Found 行为。
    // [新增] 伪装内容地址 (反向代理)
    // 1. 完整 URL: "https://www.baidu.com"
    // 2. 纯域名: "www.baidu.com" (自动使用 https)
    // 3. 带路径: "example.com/about"
    CAMOUFLAGE_URL: "blog.spacenb.com,blog.2055555.xyz,www.baidu.com,www.bing.com",
    // [新增] 伪装模式: random (每次随机洗牌) 或 failover (按顺序尝试)
    CAMOUFLAGE_MODE: "random",
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
    'nvcr.io': 'https://nvcr.io',
    
    // [新增] 常用扩充源
    'mcr.microsoft.com': 'https://mcr.microsoft.com',        // Microsoft
    'public.ecr.aws': 'https://public.ecr.aws',              // Amazon ECR Public
    'registry.access.redhat.com': 'https://registry.access.redhat.com', // RedHat
    'registry.gitlab.com': 'https://registry.gitlab.com',    // GitLab
    'ccr.ccs.tencentyun.com': 'https://ccr.ccs.tencentyun.com', // 腾讯云个人/公共
    'registry.cn-hangzhou.aliyuncs.com': 'https://registry.cn-hangzhou.aliyuncs.com', // 阿里云(示例)
    'docker.elastic.co': 'https://docker.elastic.co'         // Elastic
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
        const startTime = Date.now();

        const parseList = (v, d) => (v || d).split(/[\n,]/).map(s => s.trim()).filter(s => s.length > 0);

        const CONFIG = {
            PASSWORD: env.PASSWORD || DEFAULT_CONFIG.PASSWORD,
            ADMIN_IPS: parseList(env.ADMIN_IPS, DEFAULT_CONFIG.ADMIN_IPS),
            ALLOW_REFERER: env.ALLOW_REFERER || DEFAULT_CONFIG.ALLOW_REFERER,
            ALLOW_USER_AGENT: env.ALLOW_USER_AGENT || DEFAULT_CONFIG.ALLOW_USER_AGENT,
            MAX_REDIRECTS: parseInt(env.MAX_REDIRECTS || DEFAULT_CONFIG.MAX_REDIRECTS),
            ENABLE_CACHE: (env.ENABLE_CACHE || "true") === "true",
            CACHE_TTL: parseInt(env.CACHE_TTL || DEFAULT_CONFIG.CACHE_TTL),
            BLACKLIST: parseList(env.BLACKLIST, DEFAULT_CONFIG.BLACKLIST),
            WHITELIST: parseList(env.WHITELIST, DEFAULT_CONFIG.WHITELIST),
            ALLOW_IPS: parseList(env.ALLOW_IPS, DEFAULT_CONFIG.ALLOW_IPS),
            ALLOW_COUNTRIES: parseList(env.ALLOW_COUNTRIES, DEFAULT_CONFIG.ALLOW_COUNTRIES),
            DAILY_LIMIT_COUNT: parseInt(env.DAILY_LIMIT_COUNT || DEFAULT_CONFIG.DAILY_LIMIT_COUNT),
            IP_LIMIT_WHITELIST: parseList(env.IP_LIMIT_WHITELIST, DEFAULT_CONFIG.IP_LIMIT_WHITELIST),
            FREE_PATHS: parseList(env.FREE_PATHS, DEFAULT_CONFIG.FREE_PATHS),
            CAMOUFLAGE_URLS: parseList(env.CAMOUFLAGE_URL, DEFAULT_CONFIG.CAMOUFLAGE_URL),
            CAMOUFLAGE_MODE: (env.CAMOUFLAGE_MODE || DEFAULT_CONFIG.CAMOUFLAGE_MODE).toLowerCase(),
            SIGN_SECRET: env.SIGN_SECRET || DEFAULT_CONFIG.SIGN_SECRET,
        };

        const url = new URL(request.url);
        const clientIP = request.headers.get("CF-Connecting-IP") || "0.0.0.0";
        const userAgent = (request.headers.get("User-Agent") || "").toLowerCase();
        const referer = request.headers.get("Referer") || "";

        // ✅ 新增：自动懒建表（确保后面任何 D1 读写都不会因为表不存在而报错）
        // 说明：这里用 await 是为了“首个请求就可用”，不然 waitUntil 可能首个请求仍然报表不存在
        await ensureD1Schema(env);

        const cleanPath = url.pathname.replace(/^\//, '');
        const isFreePath = CONFIG.FREE_PATHS.some(fp => cleanPath.startsWith(fp));

        let response;
        let finalUpstream = "Internal";
        let isCacheHit = false;

        let currentUsage = 0;
        let shouldCharge = false;

        try {
            // --- 2.0 静态资源 ---
            if (url.pathname === '/robots.txt') {
                response = new Response("User-agent: *\nDisallow: /", { headers: { "Content-Type": "text/plain" } });
            } else if (url.pathname === '/favicon.ico') {
                response = new Response(LIGHTNING_SVG, { headers: { "Content-Type": "image/svg+xml" } });
            }

            // --- 2.1 Docker Token ---
            if (!response && url.pathname === '/token') {
                response = await handleTokenRequest(request, url);
                finalUpstream = "Docker Auth";
            }

            // --- 2.2 OPTIONS ---
            if (!response && request.method === "OPTIONS") {
                response = new Response(null, {
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
            if (!response && (CONFIG.ALLOW_IPS.length > 0 || CONFIG.ALLOW_COUNTRIES.length > 0)) {
                const country = request.cf ? request.cf.country : "XX";
                let allow = false;
                if (CONFIG.ALLOW_IPS.includes(clientIP)) allow = true;
                if (!allow && CONFIG.ALLOW_COUNTRIES.includes(country)) allow = true;
                if (!allow) {
                    response = new Response(`Access Denied`, { status: 403 });
                    finalUpstream = "AccessControl";
                }
            }

            // --- 2.4 计费与限额检查 ---
            const isWhitelisted = CONFIG.IP_LIMIT_WHITELIST.includes(clientIP);

            if (!response && !isWhitelisted && !isFreePath && (env.IP_LIMIT_KV || env.DB)) {
                currentUsage = await getIpUsageCount(clientIP, env);
                if (currentUsage >= CONFIG.DAILY_LIMIT_COUNT) {
                    response = new Response(`⚠️ Daily Limit Exceeded: ${currentUsage}/${CONFIG.DAILY_LIMIT_COUNT}`, { status: 429 });
                    finalUpstream = "RateLimit";
                }
            }

            const isDockerV2 = url.pathname.startsWith("/v2/");
            const isDockerCharge = isDockerV2
                && (userAgent.includes("docker") || userAgent.includes("go-http") || userAgent.includes("containerd"))
                && (url.pathname.includes("/manifests/") || url.pathname.includes("/blobs/"))
                && request.method === "GET";

            if (!response && isDockerCharge && !isWhitelisted && !isFreePath) {
                const isDuplicate = await checkIsDuplicate(clientIP, url.pathname);
                if (!isDuplicate) {
                    shouldCharge = true;
                    ctx.waitUntil(setDuplicateFlag(clientIP, url.pathname));
                }
            }

            // --- 2.5 核心业务路由 ---
            if (!response) {
                if (isDockerV2) {
                    response = await handleDockerRequest(request, url);
                    finalUpstream = "Docker Hub/Registry";
                } else {
                    const path = url.pathname;
                    const isAdminIp = CONFIG.ADMIN_IPS.includes(clientIP);

                    let isTrustedReferer = false;
                    if (CONFIG.ALLOW_REFERER && referer) {
                        const allowedRules = CONFIG.ALLOW_REFERER.split(/[\n,]/).map(s => s.trim()).filter(s => s);
                        for (const rule of allowedRules) {
                            if (rule.includes("://") ? referer.startsWith(rule) : (referer.includes(rule))) {
                                isTrustedReferer = true;
                                break;
                            }
                        }
                    }

                    let isTrustedUA = false;
                    if (CONFIG.ALLOW_USER_AGENT && userAgent.includes(CONFIG.ALLOW_USER_AGENT.toLowerCase())) {
                        isTrustedUA = true;
                    }

                    let isTrusted = isAdminIp || isWhitelisted || isTrustedReferer || isTrustedUA;

                    let subPath = "";
                    let isAuthenticated = false;

                    if (path.startsWith('/s/')) {
                        const parts = path.split('/');
                        if (parts.length >= 5) {
                            const exp = parts[2];
                            const sig = parts[3];
                            const target = parts.slice(4).join('/');

                            const now = Math.floor(Date.now() / 1000);
                            if (parseInt(exp) > now) {
                                const isValid = await verifyHmac(CONFIG.SIGN_SECRET, `${exp}\n${target}`, sig);
                                if (isValid) {
                                    isAuthenticated = true;
                                    subPath = target;
                                    isTrusted = true;
                                }
                            }
                        }
                    }

                    if (!isAuthenticated) {
                        const match = path.match(/^\/([^/]+)(?:\/(.*))?$/);
                        if (match && match[1] === CONFIG.PASSWORD) {
                            isAuthenticated = true;
                            subPath = match[2] || "";
                        } else if (isTrusted) {
                            isAuthenticated = true;
                            subPath = path.substring(1);
                        }
                    }

                    // --- 伪装逻辑 (调用 unified function) ---
                    if (!isAuthenticated) {
                        const camoResult = await tryCamouflage(request, CONFIG);
                        if (camoResult) {
                            response = camoResult.response;
                            finalUpstream = camoResult.upstream;
                        } else {
                            response = new Response("404 Not Found", { status: 404 });
                            finalUpstream = "NotAuthenticated";
                        }
                    }

                    // --- 管理员 API：全部 response=，不 return ---
                    if (!response && subPath === "reset") {
                        if (!isAdminIp) {
                            response = new Response("Forbidden: Admin IP Required", { status: 403 });
                            finalUpstream = "AdminAPI";
                        } else {
                            ctx.waitUntil(resetIpUsage(clientIP, env));
                            response = new Response(JSON.stringify({ status: "success" }), { status: 200 });
                            finalUpstream = "AdminAPI";
                        }
                    }

                    if (!response && subPath === "reset-all") {
                        if (!isAdminIp) {
                            response = new Response("Forbidden: Admin IP Required", { status: 403 });
                            finalUpstream = "AdminAPI";
                        } else {
                            ctx.waitUntil(resetAllIpStats(env));
                            response = new Response(JSON.stringify({ status: "success" }), { status: 200 });
                            finalUpstream = "AdminAPI";
                        }
                    }

                    if (!response && subPath === "stats") {
                        if (!isAdminIp) {
                            response = new Response("Forbidden: Admin IP Required", { status: 403 });
                            finalUpstream = "AdminAPI";
                        } else {
                            const stats = await getAllIpStats(env);
                            response = new Response(JSON.stringify({ status: "success", data: stats }), { status: 200 });
                            finalUpstream = "AdminAPI";
                        }
                    }

                    if (!response && subPath === "logs") {
                        if (!isAdminIp) {
                            response = new Response("Forbidden: Admin IP Required", { status: 403 });
                            finalUpstream = "AdminAPI";
                        } else {
                            const logs = await getAccessLogs(env);
                            response = new Response(JSON.stringify({ status: "success", data: logs }), { status: 200 });
                            finalUpstream = "AdminAPI";
                        }
                    }

                    if (!response && subPath === "delete-logs") {
                        if (!isAdminIp) {
                            response = new Response("Forbidden: Admin IP Required", { status: 403 });
                            finalUpstream = "AdminAPI";
                        } else {
                            const params = await request.json();
                            await deleteLogs(env, params);
                            response = new Response(JSON.stringify({ status: "success" }), { status: 200 });
                            finalUpstream = "AdminAPI";
                        }
                    }

                    if (!response && subPath === "sign-url") {
                        if (!isAdminIp) {
                            response = new Response("Forbidden: Admin IP Required", { status: 403 });
                            finalUpstream = "AdminAPI";
                        } else {
                            const params = await request.json();
                            const { target, seconds } = params;
                            const exp = Math.floor(Date.now() / 1000) + (parseInt(seconds) || 3600);
                            const sig = await generateHmac(CONFIG.SIGN_SECRET, `${exp}\n${target}`);
                            const signedPath = `/s/${exp}/${sig}/${target}`;
                            response = new Response(JSON.stringify({ status: "success", url: signedPath }), { status: 200 });
                            finalUpstream = "AdminAPI";
                        }
                    }

                    // --- Dashboard ---
                    if (!response && !subPath) {
                        response = new Response(
                            renderDashboard(url.hostname, CONFIG.PASSWORD, clientIP, currentUsage, CONFIG.DAILY_LIMIT_COUNT, CONFIG.ADMIN_IPS),
                            { status: 200, headers: { "Content-Type": "text/html;charset=UTF-8" } }
                        );
                        finalUpstream = "Dashboard";
                    }

                    // --- Linux / Proxy ---
                    if (!response && subPath) {
                        const sortedMirrors = Object.keys(LINUX_MIRRORS).sort((a, b) => b.length - a.length);
                        const linuxDistro = sortedMirrors.find(k => subPath.startsWith(k + '/') || subPath === k);

                        let proxyMode = 'raw';
                        let targetUrlPart = subPath;

                        if (subPath.startsWith('rt/') || subPath === 'rt') {
                            proxyMode = 'recursive_text';
                            targetUrlPart = subPath.replace(/^rt\/?/, "");
                        } else if (subPath.startsWith('r/') || subPath === 'r') {
                            proxyMode = 'recursive_all';
                            targetUrlPart = subPath.replace(/^r\/?/, "");
                        }

                        if (linuxDistro) {
                            const realPath = subPath.replace(linuxDistro, '').replace(/^\//, '');
                            const upstreamBase = LINUX_MIRRORS[linuxDistro];
                            finalUpstream = upstreamBase;
                            response = await handleLinuxMirrorRequest(request, upstreamBase, realPath);
                        } else {
                            finalUpstream = targetUrlPart;
                            const proxyResult = await handleGeneralProxy(
                                request,
                                targetUrlPart + (url.search || ""),
                                CONFIG,
                                proxyMode,
                                ctx
                            );
                            response = proxyResult.response;
                            isCacheHit = proxyResult.cacheHit;

                            if (response && response.status === 200 && !isWhitelisted && !isFreePath) {
                                const isDuplicate = await checkIsDuplicate(clientIP, subPath);
                                if (!isDuplicate) {
                                    shouldCharge = true;
                                    ctx.waitUntil(setDuplicateFlag(clientIP, subPath));
                                }
                            }
                        }
                    }
                }
            }

        } catch (e) {
            response = new Response(JSON.stringify({ error: e.message }), { status: 500 });
            finalUpstream = "Exception";
        } finally {
            try {
                if (!response) {
                    response = new Response(JSON.stringify({ error: "No response generated" }), { status: 500 });
                    finalUpstream = finalUpstream || "NoResponse";
                }

                const duration = Date.now() - startTime;

                const cl = response.headers && response.headers.get ? response.headers.get("content-length") : null;
                const parsed = parseInt(cl || "", 10);
                const bytes = Number.isFinite(parsed) ? parsed : -1;

                if (shouldCharge && !isFreePath) {
                    ctx.waitUntil(incrementIpUsage(clientIP, env));
                }

                ctx.waitUntil(
                    logRequest(
                        clientIP,
                        url.pathname,
                        response.status || 0,
                        finalUpstream || "",
                        duration,
                        bytes,
                        isCacheHit,
                        env
                    )
                );

                if (CONFIG.ADMIN_IPS.includes(clientIP)) {
                    const newHeaders = new Headers(response.headers);
                    newHeaders.set("X-Debug-Upstream", finalUpstream || "");
                    newHeaders.set("X-Debug-Duration", duration + "ms");
                    newHeaders.set("X-Debug-Cache", isCacheHit ? "HIT" : "MISS");
                    response = new Response(response.body, {
                        status: response.status,
                        statusText: response.statusText,
                        headers: newHeaders
                    });
                }
            } catch (logErr) {
                console.error("Log finally error:", logErr);
            }
        }

        return response;
    }
};

// ==============================================================================
// 3.x D1 懒建表（自动执行一次，不再需要你手动跑 CREATE TABLE）
// ==============================================================================

// ✅ 同一个 Worker isolate 内只会做一次（冷启动后会再做一次也没事，IF NOT EXISTS 是幂等的）
let __D1_SCHEMA_READY = false;
let __D1_SCHEMA_PROMISE = null;

async function ensureD1Schema(env) {
    if (!env || !env.DB) return;                // 没绑定 D1 就跳过
    if (__D1_SCHEMA_READY) return;              // 已经初始化过
    if (__D1_SCHEMA_PROMISE) return __D1_SCHEMA_PROMISE; // 避免并发重复建表

    __D1_SCHEMA_PROMISE = (async () => {
        const stmts = [
            `CREATE TABLE IF NOT EXISTS access_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT,
                url TEXT,
                created_at TEXT,
                status INTEGER,
                upstream TEXT,
                duration INTEGER,
                bytes INTEGER,
                cache_hit INTEGER
            );`,
            `CREATE TABLE IF NOT EXISTS ip_limits (
                ip TEXT,
                date TEXT,
                count INTEGER DEFAULT 0,
                updated_at INTEGER,
                PRIMARY KEY (ip, date)
            );`,

            // ✅ 可选索引：不想要就删掉这三句（不影响功能）
            `CREATE INDEX IF NOT EXISTS idx_access_logs_created_at ON access_logs(created_at);`,
            `CREATE INDEX IF NOT EXISTS idx_access_logs_ip ON access_logs(ip);`,
            `CREATE INDEX IF NOT EXISTS idx_ip_limits_date ON ip_limits(date);`
        ];

        // D1 batch 执行更快
        await env.DB.batch(stmts.map(sql => env.DB.prepare(sql)));

        __D1_SCHEMA_READY = true;
    })();

    return __D1_SCHEMA_PROMISE;
}

// ==============================================================================
// 3. 辅助功能函数 (HMAC, Token, Docker, Linux, KV, Logging)
// ==============================================================================

// --- [新增 v5.0] HMAC 签名相关函数 ---
async function generateHmac(secret, message) {
    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey("raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    const signature = await crypto.subtle.sign("HMAC", key, encoder.encode(message));
    return Array.from(new Uint8Array(signature)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function verifyHmac(secret, message, sigHex) {
    try {
        const encoder = new TextEncoder();
        const key = await crypto.subtle.importKey("raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
        const sigBuf = new Uint8Array(sigHex.match(/[\da-f]{2}/gi).map(h => parseInt(h, 16)));
        return await crypto.subtle.verify("HMAC", key, sigBuf, encoder.encode(message));
    } catch (e) { return false; }
}

const pickCamouflageOrder = (urls, mode) => {
    const list = [...urls];
    if (list.length <= 1) return list;
    if (mode === "random") {
        for (let i = list.length - 1; i > 0; i--) {
            const j = Math.floor(Math.random() * (i + 1));
            [list[i], list[j]] = [list[j], list[i]];
        }
    }
    return list;
};

const tryCamouflage = async (req, CONFIG) => {
    const urls = CONFIG.CAMOUFLAGE_URLS || [];
    if (!urls.length) return null;

    const ordered = pickCamouflageOrder(urls, CONFIG.CAMOUFLAGE_MODE);
    
    for (const raw of ordered) {
        try {
            let u = raw.trim();
            if (!u) continue;
            if (!u.startsWith("http://") && !u.startsWith("https://")) u = "https://" + u;

            const targetUrl = new URL(u);
            const headers = new Headers();
            
            const ua = req.headers.get("User-Agent") || "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
            headers.set("User-Agent", ua);
            headers.set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
            headers.set("Referer", targetUrl.origin);

            const camoRes = await fetch(targetUrl.toString(), {
                method: "GET",
                headers: headers,
                redirect: "follow",
            });

            const outHeaders = new Headers(camoRes.headers);
            outHeaders.delete("Content-Security-Policy");
            outHeaders.delete("X-Frame-Options");
            // [关键修复]
            outHeaders.delete("content-encoding");
            outHeaders.delete("content-length");
            outHeaders.delete("transfer-encoding");
            // [关键修复] 禁用缓存，强制刷新
            outHeaders.set("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
            outHeaders.set("Pragma", "no-cache");
            outHeaders.set("Expires", "0");

            return {
                response: new Response(camoRes.body, {
                    status: camoRes.status,
                    statusText: camoRes.statusText,
                    headers: outHeaders
                }),
                upstream: targetUrl.origin
            };
        } catch (e) {
            // console.error(`Camouflage failed for ${raw}:`, e.message);
        }
    }
    return null;
};

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

// --- 3.4 KV/D1 计数与日志工具函数 ---

// 获取当前日期 UTC+8
function getDate() { return new Date(new Date().getTime() + 28800000).toISOString().split('T')[0]; }
function getTime() { return new Date(new Date().getTime() + 28800000).toISOString().replace('T', ' ').substring(0, 19); }

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

// [增强 v5.0] 记录访问日志 (兼容 D1 和 KV)
async function logRequest(ip, url, status, upstream, duration, bytes, cache_hit, env) {
    const time = getTime();
    
    // 优先使用 D1 存储详细日志
    if (env.DB) {
        try {
            // D1 建表建议:
            // CREATE TABLE IF NOT EXISTS access_logs (
            //   id INTEGER PRIMARY KEY AUTOINCREMENT, 
            //   ip TEXT, url TEXT, created_at TEXT, 
            //   status INTEGER, upstream TEXT, duration INTEGER, bytes INTEGER, cache_hit INTEGER
            // );
            await env.DB.prepare("INSERT INTO access_logs (ip, url, created_at, status, upstream, duration, bytes, cache_hit) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
                .bind(ip, url, time, status, upstream, duration, bytes, cache_hit ? 1 : 0).run();
        } catch (e) { console.error("D1 Log Error:", e); }
    } 
    // 降级使用 KV 存储最近的日志 (List 模式)
    else if (env.IP_LIMIT_KV) {
        try {
            const key = "recent_logs";
            let logs = await env.IP_LIMIT_KV.get(key, { type: "json" }) || [];
            // [修改 v5.0] 存储更完整的对象
            logs.unshift({ ip, url, time, status, upstream, duration, bytes, cache_hit: !!cache_hit });
            if (logs.length > 50) logs = logs.slice(0, 50);
            await env.IP_LIMIT_KV.put(key, JSON.stringify(logs));
        } catch (e) { console.error("KV Log Error:", e); }
    }
}

// [增强 v5.0] 获取访问日志
async function getAccessLogs(env) {
    // 优先 D1
    if (env.DB) {
        try {
            // ✅ 对历史 NULL 字段做兜底，避免返回 null
            const sql = `
              SELECT 
                id,
                COALESCE(ip, '') as ip,
                COALESCE(url, '') as url,
                COALESCE(created_at, '') as time,
                COALESCE(status, 0) as status,
                COALESCE(upstream, '') as upstream,
                COALESCE(duration, 0) as duration,
                COALESCE(bytes, -1) as bytes,
                COALESCE(cache_hit, 0) as cache_hit
              FROM access_logs
              ORDER BY id DESC
              LIMIT 500
            `;
            const result = await env.DB.prepare(sql).all();
            return result.results;
        } catch (e) {
            return [{
                id: 0,
                ip: "System",
                url: "D1 Error or Table Missing: " + e.message,
                time: getTime(),
                status: 0,
                upstream: "",
                duration: 0,
                bytes: -1,
                cache_hit: 0
            }];
        }
    }

    // 降级 KV
    if (env.IP_LIMIT_KV) {
        const logs = await env.IP_LIMIT_KV.get("recent_logs", { type: "json" }) || [];
        // ✅ KV 也补全字段，避免某些旧日志对象缺字段
        return logs.map((log, index) => ({
            id: (log && typeof log.id !== 'undefined') ? log.id : index,
            ip: log?.ip || '',
            url: log?.url || '',
            time: log?.time || '',
            status: (typeof log?.status === 'number') ? log.status : 0,
            upstream: log?.upstream || '',
            duration: (typeof log?.duration === 'number') ? log.duration : 0,
            bytes: (typeof log?.bytes === 'number') ? log.bytes : -1,
            cache_hit: log?.cache_hit ? 1 : 0
        }));
    }

    return [];
}

// [新增] 删除日志逻辑 (支持 ID 列表删除和日期范围删除)
async function deleteLogs(env, params) {
    // 优先处理 D1 数据库
    if (env.DB) {
        try {
            // 模式 1: 按 ID 列表删除 (手动勾选)
            if (params.ids && Array.isArray(params.ids) && params.ids.length > 0) {
                // 构造 SQL 占位符
                const placeholders = params.ids.map(() => '?').join(',');
                await env.DB.prepare(`DELETE FROM access_logs WHERE id IN (${placeholders})`)
                    .bind(...params.ids)
                    .run();
            }
            // 模式 2: 按天数清理 (清理 X 天前的日志)
            if (params.days) {
                const days = parseInt(params.days);
                if (!isNaN(days) && days >= 0) {
                    // 使用 SQLite 的 datetime 函数计算截止时间
                    await env.DB.prepare("DELETE FROM access_logs WHERE created_at < datetime('now', '-' || ? || ' days', 'localtime')")
                        .bind(days)
                        .run();
                }
            }
        } catch (e) {
            console.error("Delete Logs Error:", e);
        }
    }
    // 处理 KV (KV 只能简单过滤重写，暂只支持清空或保留最近 N 条，此处仅做简单适配)
    else if (env.IP_LIMIT_KV) {
        // KV 模式不支持复杂 SQL，这里简单实现：如果是清理操作，保留最近 50 条
        if (params.ids || params.days) {
             // 重新读取并过滤逻辑较为复杂且不推荐 KV 做日志，此处略过具体实现，建议使用 D1
        }
    }
}

async function getIpUsageCount(ip, env) {
    // 优先使用 D1 数据库
    if (env.DB) {
        try {
            const today = getDate();
            const result = await env.DB.prepare("SELECT count FROM ip_limits WHERE ip = ? AND date = ?")
                .bind(ip, today)
                .first();
            return result ? result.count : 0;
        } catch (e) {
            console.error("D1 Read Error:", e); 
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
    
    if (env.IP_LIMIT_KV) {
        await env.IP_LIMIT_KV.delete(`limit:${ip}:${getDate()}`);
    }
}

async function resetAllIpStats(env) {
    if (env.DB) {
        try {
            await env.DB.prepare("DELETE FROM ip_limits").run();
             // 可选：是否清空日志？暂不清空日志，只清空额度
        } catch(e) { console.error(e); }
    }

    if (env.IP_LIMIT_KV) {
        let cursor = null;
        do {
            const list = await env.IP_LIMIT_KV.list({ prefix: `limit:`, limit: 1000, cursor });
            cursor = list.cursor;
            for (const key of list.keys) {
                await env.IP_LIMIT_KV.delete(key.name);
            }
        } while (cursor); 
    }
}

// 获取全站统计
async function getAllIpStats(env) {
    if (env.DB) {
        try {
            const today = getDate();
            const sumResult = await env.DB.prepare("SELECT SUM(count) as total, COUNT(*) as unique_ips FROM ip_limits WHERE date = ?").bind(today).first();
            const total = sumResult.total || 0;
            const uniqueIps = sumResult.unique_ips || 0;

            const listResult = await env.DB.prepare("SELECT ip, count FROM ip_limits WHERE date = ? ORDER BY count DESC LIMIT 100").bind(today).all();
            
            return { 
                totalRequests: total, 
                uniqueIps: uniqueIps, 
                details: listResult.results 
            };
        } catch (e) {
            console.error("D1 Stats Error:", e);
        }
    }

    if (!env.IP_LIMIT_KV) return { totalRequests: 0, uniqueIps: 0, details: [] };
    const today = getDate();
    let total = 0;
    let details = [];
    const list = await env.IP_LIMIT_KV.list({ prefix: `limit:`, limit: 1000 }); 
    for (const key of list.keys) {
        const parts = key.name.split(':');
        if (parts.length === 3 && parts[2] === today) {
            const val = await env.IP_LIMIT_KV.get(key.name);
            const count = parseInt(val || "0");
            total += count;
            details.push({ ip: parts[1], count: count });
        }
    }
    details.sort((a, b) => b.count - a.count);
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
    
        if ((mode === 'recursive_all' || mode === 'recursive_text') && CONFIG.ENABLE_CACHE) {
        const cachedResponse = await cache.match(cacheKey);
        if (cachedResponse) {
            return { response: cachedResponse, cacheHit: true }; // [修改 v5.0] 返回对象以传递 hit 状态
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
            try { currentTargetUrl = new URL(currentUrlStr); } catch(e) { return { response: new Response("Invalid URL: " + currentUrlStr, {status: 400}), cacheHit: false }; }
            
            // 黑白名单检查
            const domain = currentTargetUrl.hostname;
            if (CONFIG.BLACKLIST.some(k => domain.includes(k))) return { response: new Response("Blocked Domain", { status: 403 }), cacheHit: false };
            if (CONFIG.WHITELIST.length > 0 && !CONFIG.WHITELIST.some(k => domain.includes(k))) return { response: new Response("Blocked (Not Whitelisted)", { status: 403 }), cacheHit: false };

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
        
        // ==========================================
        // 模式 A: Raw (纯净模式)
        // ==========================================
        // 直接透传流，不修改内容，保持二进制完整性，适合 zip/iso/exe
        if (mode === 'raw') {
            responseHeaders.set("X-Proxy-Mode", "Raw-Passthrough");
            return { response: new Response(finalResponse.body, { status: finalResponse.status, headers: responseHeaders }), cacheHit: false };
        }

                // ==========================================
        // 模式 B1: Recursive-All (递归模式 - 强制重写所有)
        // ==========================================
        // /r/ 对任何 Content-Type 都强制按文本读取并重写链接（恢复你之前的“重写所有”行为）
        if (mode === 'recursive_all') {
            responseHeaders.set("X-Proxy-Mode", "Recursive-All-ForceText");
            responseHeaders.delete("Content-Encoding");
            responseHeaders.delete("Content-Length");
            responseHeaders.delete("Transfer-Encoding");
            responseHeaders.delete("Content-Disposition");

            let text = await finalResponse.text();

            const workerOrigin = new URL(request.url).origin;
            const proxyBase = `${workerOrigin}/${CONFIG.PASSWORD}/r/`;

            const absRegex = /(https?:\/\/[a-zA-Z0-9][-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*))/g;
            text = text.replace(absRegex, (match) => {
                if (match.includes(workerOrigin)) return match;
                return proxyBase + match;
            });

            const modifiedResponse = new Response(text, { status: finalResponse.status, headers: responseHeaders });

            if (CONFIG.ENABLE_CACHE && finalResponse.status === 200) {
                const responseToCache = modifiedResponse.clone();
                responseToCache.headers.set("Cache-Control", `public, max-age=${CONFIG.CACHE_TTL}`);
                ctx.waitUntil(cache.put(cacheKey, responseToCache));
            }

            return { response: modifiedResponse, cacheHit: false };
        }

        // ==========================================
        // 模式 B2: Recursive-Text (递归模式 - 仅文本递归)
        // ==========================================
        // /rt/ 只对文本类型进行递归替换，二进制文件直接透传（更安全）
        if (mode === 'recursive_text') {
            const contentType = (responseHeaders.get("content-type") || "").toLowerCase();
            const isText = contentType.includes("text/")
                || contentType.includes("application/javascript")
                || contentType.includes("application/json")
                || contentType.includes("application/xml");

            if (!isText) {
                responseHeaders.set("X-Proxy-Mode", "Recursive-Text-Fallback-Binary");
                return { response: new Response(finalResponse.body, { status: finalResponse.status, headers: responseHeaders }), cacheHit: false };
            }

            responseHeaders.set("X-Proxy-Mode", "Recursive-Text-Rewrite");
            responseHeaders.delete("Content-Encoding");
            responseHeaders.delete("Content-Length");
            responseHeaders.delete("Transfer-Encoding");
            responseHeaders.delete("Content-Disposition");

            let text = await finalResponse.text();

            const workerOrigin = new URL(request.url).origin;
            const proxyBase = `${workerOrigin}/${CONFIG.PASSWORD}/rt/`;

            const absRegex = /(https?:\/\/[a-zA-Z0-9][-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*))/g;
            text = text.replace(absRegex, (match) => {
                if (match.includes(workerOrigin)) return match;
                return proxyBase + match;
            });

            // HTML 情况下，额外做相对路径补全
            if (contentType.includes("html")) {
                const currentBase = new URL(currentUrlStr).origin;
                const rootRelRegex = /(href|src|action)=["'](\/[^"']+)["']/g;

                text = text.replace(rootRelRegex, (match, attr, path) => {
                    return `${attr}="${proxyBase}${currentBase}${path}"`;
                });
            }

            const modifiedResponse = new Response(text, { status: finalResponse.status, headers: responseHeaders });

            if (CONFIG.ENABLE_CACHE && finalResponse.status === 200) {
                const responseToCache = modifiedResponse.clone();
                responseToCache.headers.set("Cache-Control", `public, max-age=${CONFIG.CACHE_TTL}`);
                ctx.waitUntil(cache.put(cacheKey, responseToCache));
            }

            return { response: modifiedResponse, cacheHit: false };
        }

    } catch (e) { return { response: new Response(`Proxy Error: ${e.message}`, { status: 502 }), cacheHit: false }; }
}

// ==============================================================================
// 4. Dashboard 渲染 (UI 界面 - 独立 UI 部分 - 自定义时间增强版 - 双语版)
// ==============================================================================

function renderDashboard(hostname, password, ip, count, limit, adminIps) {
    const percent = Math.min(Math.round((count / limit) * 100), 100);
    const isAdmin = adminIps.includes(ip);
    
    // 服务端直接生成 Linux 选项 HTML (保持原有逻辑)
    let linuxOptionsHtml = '<option value="" disabled selected data-i18n="linux_select">请选择系统 (Select OS)...</option>';
    
    if (typeof LINUX_MIRRORS !== 'undefined') {
        const mirrors = Object.keys(LINUX_MIRRORS);
        mirrors.forEach(distro => {
            if (!distro.includes('-security')) {
                const displayName = distro.charAt(0).toUpperCase() + distro.slice(1);
                linuxOptionsHtml += `<option value="${distro}">${displayName}</option>`;
            }
        });
    } else {
        ['Ubuntu', 'Debian', 'CentOS', 'Alpine', 'Kali'].forEach(d => {
            linuxOptionsHtml += `<option value="${d.toLowerCase()}">${d}</option>`;
        });
    }

    const linuxMirrorsJson = (typeof LINUX_MIRRORS !== 'undefined') ? JSON.stringify(Object.keys(LINUX_MIRRORS)) : '[]';

    return `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta name="referrer" content="no-referrer">
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>Cloudflare Proxy</title>
    <link rel="icon" type="image/svg+xml" href="data:image/svg+xml,${encodeURIComponent(LIGHTNING_SVG)}">
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
body {
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  font-family: "Inter", sans-serif;
  transition: background-color 0.3s ease;
  padding: 1rem;
  margin: 0;
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

/* ---------------------------
   Light Mode
---------------------------- */
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

/* ---------------------------
   Dark Mode
---------------------------- */
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

/* ---------------------------
   Elements
---------------------------- */
input,
select {
  outline: none;
  transition: all 0.2s;
  appearance: none;
  -webkit-appearance: none;
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

.code-area,
pre,
.select-all {
  user-select: text !important;
  -webkit-user-select: text !important;
}

/* ---------------------------
   Nav
---------------------------- */
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
  font-weight: bold;
  font-size: 0.8rem;
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

/* ---------------------------
   Toast & Modals
---------------------------- */
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

.modal-content-lg {
  max-width: 1000px;
}

.modal-overlay.open .modal-content {
  transform: scale(1);
}

.dark-mode .modal-content {
  background: #1e293b;
  border: 1px solid #334155;
  color: #f1f5f9;
}

/* ---------------------------
   Logs Table
---------------------------- */
.log-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.75rem;
  table-layout: fixed !important;
  min-width: 700px;
}

.log-table th {
  text-align: left;
  padding: 0.5rem;
  border-bottom: 1px solid #e2e8f0;
  opacity: 0.7;
}

.log-table td {
  padding: 0.5rem;
  border-bottom: 1px solid #f1f5f9;
  font-family: monospace;
  word-break: break-all;
  cursor: pointer;
}

.log-table td:hover {
  background-color: rgba(59, 130, 246, 0.1);
}

.dark-mode .log-table th,
.dark-mode .log-table td {
  border-color: #334155;
}

.dark-mode .log-table td:hover {
  background-color: rgba(59, 130, 246, 0.2);
}

.log-table td > div.truncate {
  width: 100% !important;
  max-width: 100% !important;
  white-space: nowrap !important;
  overflow: hidden !important;
  text-overflow: ellipsis !important;
}

.log-toolbar {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
  margin-bottom: 15px;
  padding-bottom: 15px;
  border-bottom: 1px solid #e2e8f0;
  align-items: center;
}

.dark-mode .log-toolbar {
  border-bottom-color: #334155;
}

.log-btn {
  padding: 6px 12px;
  border-radius: 6px;
  font-size: 0.75rem;
  font-weight: bold;
  cursor: pointer;
  border: 1px solid transparent;
  transition: all 0.2s;
}

.btn-red {
  background: #fee2e2;
  color: #ef4444;
  border-color: #fca5a5;
}

.btn-blue {
  background: #dbeafe;
  color: #2563eb;
  border-color: #bfdbfe;
}

.dark-mode .btn-red {
  background: #7f1d1d;
  color: #fca5a5;
  border-color: #991b1b;
}

.dark-mode .btn-blue {
  background: #1e3a8a;
  color: #93c5fd;
  border-color: #1e40af;
}

/* ---------------------------
   Responsive
---------------------------- */
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

  .log-table th:nth-child(6),
  .log-table td:nth-child(6),
  .log-table th:nth-child(7),
  .log-table td:nth-child(7) {
    display: none !important;
  }

  #sign-custom-container:not(.hidden) {
    width: 100%;
    justify-content: center;
  }
}

#log-detail-modal-content {
  word-wrap: break-word;
  white-space: pre-wrap;
  font-family: monospace;
  max-height: 60vh;
  overflow-y: auto;
}

#logDetailModal {
  z-index: 1000 !important;
}

/* ---------------------------
   Custom Time Input
---------------------------- */
#sign-custom-container:not(.hidden) {
  display: flex !important;
  align-items: center;
  height: 46px;
  padding: 0 0.5rem !important;
  background-color: white;
  border: 1px solid #e5e7eb;
  border-radius: 0.5rem;
}

.dark-mode #sign-custom-container:not(.hidden) {
  background-color: #1e293b;
  border-color: #334155;
  color: #f1f5f9;
}

#sign-custom-container input {
  background: transparent !important;
  border: none !important;
  text-align: center;
  font-weight: 600;
  padding: 0 !important;
  margin: 0 2px;
  width: 2.5rem;
  outline: none !important;
  box-shadow: none !important;
  color: inherit;
}
body {
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  font-family: "Inter", sans-serif;
  transition: background-color 0.3s ease;
  padding: 1rem;
  margin: 0;
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

/* ---------------------------
   Light Mode
---------------------------- */
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

/* ---------------------------
   Dark Mode
---------------------------- */
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

/* ---------------------------
   Elements
---------------------------- */
input,
select {
  outline: none;
  transition: all 0.2s;
  appearance: none;
  -webkit-appearance: none;
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

.code-area,
pre,
.select-all {
  user-select: text !important;
  -webkit-user-select: text !important;
}

/* ---------------------------
   Nav
---------------------------- */
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
  font-weight: bold;
  font-size: 0.8rem;
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

/* ---------------------------
   Toast & Modals
---------------------------- */
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

.modal-content-lg {
  max-width: 1000px;
}

.modal-overlay.open .modal-content {
  transform: scale(1);
}

.dark-mode .modal-content {
  background: #1e293b;
  border: 1px solid #334155;
  color: #f1f5f9;
}

/* ---------------------------
   Logs Table
---------------------------- */
.log-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.75rem;
  table-layout: fixed !important;
  min-width: 700px;
}

.log-table th {
  text-align: left;
  padding: 0.5rem;
  border-bottom: 1px solid #e2e8f0;
  opacity: 0.7;
}

.log-table td {
  padding: 0.5rem;
  border-bottom: 1px solid #f1f5f9;
  font-family: monospace;
  word-break: break-all;
  cursor: pointer;
}

.log-table td:hover {
  background-color: rgba(59, 130, 246, 0.1);
}

.dark-mode .log-table th,
.dark-mode .log-table td {
  border-color: #334155;
}

.dark-mode .log-table td:hover {
  background-color: rgba(59, 130, 246, 0.2);
}

.log-table td > div.truncate {
  width: 100% !important;
  max-width: 100% !important;
  white-space: nowrap !important;
  overflow: hidden !important;
  text-overflow: ellipsis !important;
}

.log-toolbar {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
  margin-bottom: 15px;
  padding-bottom: 15px;
  border-bottom: 1px solid #e2e8f0;
  align-items: center;
}

.dark-mode .log-toolbar {
  border-bottom-color: #334155;
}

.log-btn {
  padding: 6px 12px;
  border-radius: 6px;
  font-size: 0.75rem;
  font-weight: bold;
  cursor: pointer;
  border: 1px solid transparent;
  transition: all 0.2s;
}

.btn-red {
  background: #fee2e2;
  color: #ef4444;
  border-color: #fca5a5;
}

.btn-blue {
  background: #dbeafe;
  color: #2563eb;
  border-color: #bfdbfe;
}

.dark-mode .btn-red {
  background: #7f1d1d;
  color: #fca5a5;
  border-color: #991b1b;
}

.dark-mode .btn-blue {
  background: #1e3a8a;
  color: #93c5fd;
  border-color: #1e40af;
}

/* ---------------------------
   Responsive
---------------------------- */
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

  .log-table th:nth-child(6),
  .log-table td:nth-child(6),
  .log-table th:nth-child(7),
  .log-table td:nth-child(7) {
    display: none !important;
  }

  #sign-custom-container:not(.hidden) {
    width: 100%;
    justify-content: center;
  }
}

#log-detail-modal-content {
  word-wrap: break-word;
  white-space: pre-wrap;
  font-family: monospace;
  max-height: 60vh;
  overflow-y: auto;
}

#logDetailModal {
  z-index: 1000 !important;
}

/* ---------------------------
   Custom Time Input
---------------------------- */
#sign-custom-container:not(.hidden) {
  display: flex !important;
  align-items: center;
  height: 46px;
  padding: 0 0.5rem !important;
  background-color: white;
  border: 1px solid #e5e7eb;
  border-radius: 0.5rem;
}

.dark-mode #sign-custom-container:not(.hidden) {
  background-color: #1e293b;
  border-color: #334155;
  color: #f1f5f9;
}

#sign-custom-container input {
  background: transparent !important;
  border: none !important;
  text-align: center;
  font-weight: 600;
  padding: 0 !important;
  margin: 0 2px;
  width: 2.5rem;
  outline: none !important;
  box-shadow: none !important;
  color: inherit;
}
    </style>
</head>
<body class="light-mode">
    <div class="top-nav">
       <button onclick="toggleLanguage()" class="nav-btn" aria-label="Toggle Language">
         <span id="lang-text">CN</span>
       </button>
       <a href="https://github.com/Kevin-YST-Du/Cloudflare-ProxyX" target="_blank" class="nav-btn" aria-label="GitHub Repository">
         <svg class="w-5 h-5" fill="currentColor" viewBox="0 0 24 24"><path fill-rule="evenodd" d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z" clip-rule="evenodd"></path></svg>
       </a>
       <button onclick="toggleTheme()" class="nav-btn" aria-label="Toggle Theme">
         <span class="sun text-lg">☀️</span><span class="moon hidden text-lg">🌙</span>
       </button>
    </div>
    
    <div class="custom-content-wrapper">
      <h1 class="text-3xl md:text-4xl font-extrabold text-center mb-8 tracking-tight">
        <span class="bg-clip-text text-transparent bg-gradient-to-r from-blue-600 to-indigo-600 dark:from-blue-400 dark:to-indigo-400" data-i18n="main_title">Cloudflare 加速通道</span>
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
                  <span data-i18n="daily_limit">今日额度</span>: <span class="text-blue-600 dark:text-blue-400 font-bold">${count}</span> <span class="opacity-50">/ ${limit}</span>
              </div>
              <div class="flex gap-2">
                <button onclick="openModal('confirmModal')" class="reset-btn px-3 py-1.5 rounded-lg text-xs font-bold transition-transform hover:scale-105 flex items-center gap-1.5 shadow-sm">
                <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
                    <span data-i18n="reset_limit">重置额度</span>
                </button>
                ${isAdmin ? `
                <button onclick="viewAllStats()" class="px-3 py-1.5 rounded-lg text-xs font-bold bg-blue-100 text-blue-600 border border-blue-200 hover:bg-blue-200 transition-transform hover:scale-105 flex items-center gap-1.5 shadow-sm">
                    <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"></path></svg>
                    <span data-i18n="admin_stats">全站统计</span>
                </button>
                <button onclick="openLogsModal()" class="px-3 py-1.5 rounded-lg text-xs font-bold bg-purple-100 text-purple-600 border border-purple-200 hover:bg-purple-200 transition-transform hover:scale-105 flex items-center gap-1.5 shadow-sm">
                    <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 6V4m0 2a2 2 0 100 4m0-4a2 2 0 110 4m-6 8a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4m6 6v10m6-2a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4"></path></svg>
                    <span data-i18n="access_logs">访问日志</span>
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
          <span data-i18n="limit_desc">失败自动退还额度 · 短时重复请求不扣费 · <span class="text-green-600 dark:text-green-400 font-bold">软件源镜像 (Ubuntu 等) 免费不限量</span></span>
        </p>

        <div id="stats-panel" class="hidden mt-4 p-4 rounded-xl bg-gray-50 dark:bg-slate-800/50 border border-gray-200 dark:border-slate-700">
            <div class="flex justify-between items-center mb-2">
                <h4 class="text-xs font-bold opacity-70 uppercase tracking-wider" data-i18n="stats_overview">今日全站概况</h4>
                ${isAdmin ? `
                <button onclick="openModal('confirmResetAllModal')" class="text-[10px] text-red-500 hover:text-red-700 font-bold border border-red-200 hover:border-red-400 bg-red-50 hover:bg-red-100 px-2 py-0.5 rounded transition" data-i18n="reset_all_data">
                清空全站数据
                </button>
                ` : ''}
            </div>
            
            <div class="mb-2 text-xs font-mono text-blue-600 dark:text-blue-400 border-b border-gray-200 dark:border-slate-700 pb-2">
                 <span id="stats-summary" data-i18n="loading">正在加载...</span>
            </div>

            <div id="stats-list" class="max-h-40 overflow-y-auto text-[10px] font-mono divide-y divide-gray-100 dark:divide-slate-700 pr-2">
            </div>
        </div>
      </div>
      
      ${isAdmin ? `
      <div class="section-box">
        <h2 class="text-lg font-bold mb-4 flex items-center gap-2 opacity-90">
          <svg class="w-5 h-5 text-indigo-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z"></path></svg>
          <span data-i18n="hmac_title">签名链接生成 (免密分享)</span>
        </h2>
        <div class="flex flex-col md:flex-row gap-3 mb-2">
          <input id="sign-target" type="text" placeholder="目标 URL (如 https://github.com/...)" data-i18n-placeholder="hmac_placeholder" class="flex-grow p-3.5 rounded-lg text-sm w-full">
          
          <div class="flex gap-2 w-full md:w-auto">
              <select id="sign-ttl" onchange="toggleSignTtl()" class="flex-1 md:flex-none p-3.5 rounded-lg text-sm bg-gray-50 dark:bg-slate-800 border border-gray-200 dark:border-slate-700">
                  <option value="3600" data-i18n="1_hour">1 小时</option>
                  <option value="86400" data-i18n="24_hours">24 小时</option>
                  <option value="600" data-i18n="10_mins">10 分钟</option>
                  <option value="custom" data-i18n="custom_time">自定义...</option>
              </select>
              
              <div id="sign-custom-container" class="hidden flex items-center gap-1 bg-white dark:bg-slate-900 border border-indigo-200 dark:border-indigo-800 rounded-lg px-2">
                  <input id="ttl-days" type="number" placeholder="天" class="w-12 p-2 text-center text-sm bg-transparent outline-none" min="0">
                  <span class="text-xs opacity-50">d</span>
                  <input id="ttl-hours" type="number" placeholder="时" class="w-12 p-2 text-center text-sm bg-transparent outline-none" min="0">
                  <span class="text-xs opacity-50">h</span>
                  <input id="ttl-minutes" type="number" placeholder="分" class="w-12 p-2 text-center text-sm bg-transparent outline-none" min="0">
                  <span class="text-xs opacity-50">m</span>
              </div>

              <button onclick="generateSignedUrl()" class="flex-none bg-indigo-600 hover:bg-indigo-700 text-white px-6 py-3.5 rounded-lg transition font-bold text-sm shadow-md whitespace-nowrap">
                  <span data-i18n="gen_link">生成链接</span>
              </button>
          </div>
        </div>
        <div id="sign-result-box" class="hidden">
           <div class="p-3 bg-indigo-50 dark:bg-indigo-900/20 border border-indigo-100 dark:border-indigo-800 rounded-lg mb-2 cursor-pointer" onclick="copySignedUrl()">
               <p id="sign-result" class="text-indigo-700 dark:text-indigo-400 font-mono text-xs break-all"></p>
           </div>
           <p class="text-[10px] opacity-60" data-i18n="hmac_note">* 此链接包含签名，有效期内可免密访问，请妥善保管。</p>
        </div>
      </div>
      ` : ''}

      <div class="section-box">
        <h2 class="text-lg font-bold mb-4 flex items-center gap-2 opacity-90">
          <svg class="w-5 h-5 text-gray-700 dark:text-gray-300" fill="currentColor" viewBox="0 0 24 24"><path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/></svg>
          <span data-i18n="github_title">GitHub 文件 / 脚本命令加速</span>
        </h2>
        <div class="flex flex-responsive gap-3">
          <input id="github-url" type="text" placeholder="粘贴 链接 或 bash/curl/git 完整命令" data-i18n-placeholder="github_placeholder" class="flex-grow p-3.5 rounded-lg text-sm">
          <button onclick="convertGithubUrl()" class="bg-blue-600 hover:bg-blue-700 text-white px-6 py-3.5 rounded-lg transition font-bold text-sm shadow-md whitespace-nowrap flex items-center justify-center gap-1">
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"/></svg>
              <span data-i18n="get_link">获取链接</span>
          </button>
        </div>
        
        <div id="github-result-box" class="hidden mt-5">
           <div class="mb-6">
               <p class="text-xs font-bold text-gray-500 dark:text-gray-400 mb-2 uppercase tracking-wide" data-i18n="raw_url_label">1. 加速链接 (Raw URL):</p>
               <div class="p-4 bg-emerald-50 dark:bg-emerald-900/20 border border-emerald-100 dark:border-emerald-800 rounded-lg mb-3">
                   <p id="github-result-url" class="text-emerald-700 dark:text-emerald-400 font-mono text-xs break-all select-all"></p>
               </div>
               <div class="flex gap-3">
                   <button onclick="copyGithubUrlOnly()" class="flex-1 bg-gray-100 dark:bg-slate-700 hover:bg-gray-200 dark:hover:bg-slate-600 text-gray-700 dark:text-gray-200 py-2.5 rounded-lg text-xs font-bold transition" data-i18n="copy_link">复制链接</button>
                   <button onclick="openGithubUrl()" class="flex-1 bg-blue-50 dark:bg-blue-900/20 hover:bg-blue-100 dark:hover:bg-blue-900/40 text-blue-600 dark:text-blue-400 py-2.5 rounded-lg text-xs font-bold transition" data-i18n="visit_now">立即访问</button>
               </div>
           </div>
           <div>
               <p id="github-cmd-label" class="text-xs font-bold text-gray-500 dark:text-gray-400 mb-2 uppercase tracking-wide" data-i18n="terminal_cmd_label">2. 终端命令:</p>
               <div class="p-4 bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg mb-3">
                  <p id="github-result-cmd" class="text-slate-700 dark:text-slate-300 font-mono text-xs break-all select-all"></p>
               </div>
               <button onclick="copyGithubCmd()" class="w-full bg-gray-100 dark:bg-slate-700 hover:bg-gray-200 dark:hover:bg-slate-600 text-gray-700 dark:text-gray-200 py-2.5 rounded-lg text-xs font-bold transition" data-i18n="copy_cmd">复制命令</button>
           </div>
        </div>
      </div>

      <div class="section-box">
        <h2 class="text-lg font-bold mb-4 flex items-center gap-2 opacity-90">
          <span class="text-xl">🚀</span> <span data-i18n="recursive_title">递归脚本加速 (Shell / Curl)</span>
        </h2>
        <p class="text-xs opacity-60 mb-3" data-i18n="recursive_desc">适用于 curl | bash 脚本。可选择强制重写所有 (/r/) 或仅文本递归 (/rt/)。</p>

        <div class="flex flex-responsive gap-3">
          <select id="recursive-mode" class="flex-none p-3.5 rounded-lg text-sm bg-gray-50 dark:bg-slate-800 border-r-8 border-transparent outline-none">
              <option value="r" data-i18n="mode_r">/r/ 强制重写所有</option>
              <option value="rt" data-i18n="mode_rt">/rt/ 仅文本递归</option>
          </select>

          <input id="recursive-url" type="text" placeholder="如: https://get.docker.com" data-i18n-placeholder="recursive_placeholder" class="flex-grow p-3.5 rounded-lg text-sm">

          <button onclick="convertRecursiveUrl()" class="bg-blue-600 hover:bg-blue-700 text-white px-6 py-3.5 rounded-lg transition font-bold text-sm shadow-md whitespace-nowrap flex items-center justify-center gap-1">
               <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19.428 15.428a2 2 0 00-1.022-.547l-2.384-.477a6 6 0 00-3.86.517l-.318.158a6 6 0 01-3.86.517L6.05 15.21a2 2 0 00-1.806.547M8 4h8l-1 1v5.172a2 2 0 00.586 1.414l5 5c1.26 1.26.367 3.414-1.415 3.414H4.828c-1.782 0-2.674-2.154-1.414-3.414l5-5A2 2 0 009 10.172V5L8 4z"/></svg>
               <span data-i18n="gen_cmd">生成命令</span>
          </button>
        </div>
        
        <div id="recursive-result-box" class="hidden mt-5">
              <div class="mb-6">
                  <p id="recursive-url-label" class="text-xs font-bold text-gray-500 dark:text-gray-400 mb-2 uppercase tracking-wide">1. Raw URL:</p>
                  <div class="p-4 bg-emerald-50 dark:bg-emerald-900/20 border border-emerald-100 dark:border-emerald-800 rounded-lg mb-3">
                      <p id="recursive-result-url" class="text-emerald-700 dark:text-emerald-400 font-mono text-xs break-all select-all"></p>
                  </div>
                  <div class="flex gap-3">
                      <button onclick="copyRecursiveUrlOnly()" class="flex-1 bg-gray-100 dark:bg-slate-700 hover:bg-gray-200 dark:hover:bg-slate-600 text-gray-700 dark:text-gray-200 py-2.5 rounded-lg text-xs font-bold transition" data-i18n="copy_link">复制链接</button>
                      <button onclick="openRecursiveUrl()" class="flex-1 bg-blue-50 dark:bg-blue-900/20 hover:bg-blue-100 dark:hover:bg-blue-900/40 text-blue-600 dark:text-blue-400 py-2.5 rounded-lg text-xs font-bold transition" data-i18n="visit_now">立即访问</button>
                  </div>
              </div>
              <div>
                  <p id="recursive-cmd-label" class="text-xs font-bold text-gray-500 dark:text-gray-400 mb-2 uppercase tracking-wide">2. Bash:</p>
                  <div class="p-4 bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg mb-3">
                      <p id="recursive-result-cmd" class="text-slate-700 dark:text-slate-300 font-mono text-xs break-all select-all"></p>
                  </div>
                  <button onclick="copyRecursiveCmd()" class="w-full bg-gray-100 dark:bg-slate-700 hover:bg-gray-200 dark:hover:bg-slate-600 text-gray-700 dark:text-gray-200 py-2.5 rounded-lg text-xs font-bold transition" data-i18n="copy_cmd">复制命令</button>
              </div>
        </div>
      </div>

      <div class="section-box">
        <h2 class="text-lg font-bold mb-4 flex items-center gap-2 opacity-90">
          <span class="text-xl">🐳</span> <span data-i18n="docker_title">Docker 镜像加速</span>
        </h2>
        <div class="flex flex-responsive gap-3">
          <input id="docker-image" type="text" placeholder="如 nginx 或 library/redis" data-i18n-placeholder="docker_placeholder" class="flex-grow p-3.5 rounded-lg text-sm">
          <button onclick="convertDockerImage()" class="bg-indigo-600 hover:bg-indigo-700 text-white px-6 py-3.5 rounded-lg transition font-bold text-sm shadow-md whitespace-nowrap flex items-center justify-center gap-1">
               <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 19l9 2-9-18-9 18 9-2zm0 0v-8"/></svg>
               <span data-i18n="get_cmd">获取命令</span>
          </button>
        </div>
        <div id="docker-result-box" class="hidden mt-5">
           <div class="p-4 bg-emerald-50 dark:bg-emerald-900/20 border border-emerald-100 dark:border-emerald-800 rounded-lg mb-3">
               <p id="docker-result" class="text-emerald-700 dark:text-emerald-400 font-mono text-xs break-all select-all"></p>
          </div>
          <button onclick="copyDockerCommand()" class="w-full bg-gray-100 dark:bg-slate-700 hover:bg-gray-200 dark:hover:bg-slate-600 text-gray-700 dark:text-gray-200 py-2.5 rounded-lg text-xs font-bold transition" data-i18n="copy_cmd_one_click">一键复制命令</button>
        </div>
      </div>

      <div class="section-box">
        <h2 class="text-lg font-bold mb-4 flex items-center gap-2 opacity-90">
          <span class="text-xl">🐧</span> <span data-i18n="linux_title">Linux 软件源加速 (Range 支持)</span>
        </h2>
        <div class="flex flex-responsive gap-3">
          <div class="relative flex-none">
              <select id="linux-distro" class="w-full md:w-48 p-3.5 rounded-lg text-sm bg-gray-50 dark:bg-slate-800 border border-gray-200 dark:border-slate-700 outline-none cursor-pointer appearance-none">
                  ${linuxOptionsHtml}
              </select>
              <div class="absolute inset-y-0 right-0 flex items-center px-2 pointer-events-none text-gray-500">
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"></path></svg>
              </div>
          </div>
          
          <button onclick="generateLinuxCommand()" class="bg-orange-600 hover:bg-orange-700 text-white px-6 py-3.5 rounded-lg transition font-bold text-sm shadow-md whitespace-nowrap flex items-center justify-center gap-1 w-full md:w-auto">
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/></svg>
              <span data-i18n="gen_mirror_cmd">生成换源命令</span>
          </button>
        </div>
        <div id="linux-result-box" class="hidden mt-5">
            <p class="text-xs opacity-70 mb-2" data-i18n="use_cmd_replace">使用以下命令一键替换：</p>
            <div class="p-4 bg-orange-50 dark:bg-orange-900/20 border border-orange-100 dark:border-orange-800 rounded-lg mb-3">
                <p id="linux-result" class="text-orange-700 dark:text-orange-400 font-mono text-xs break-all select-all"></p>
            </div>
            <p class="text-[10px] opacity-60 mt-2 mb-2" data-i18n="linux_note">
                * 注意：脚本仅替换官方默认源。若您已使用其他镜像源（如阿里云），请手动编辑文件。
            </p>
            <button onclick="copyLinuxCommand()" class="w-full bg-gray-100 dark:bg-slate-700 hover:bg-gray-200 dark:hover:bg-slate-600 text-gray-700 dark:text-gray-200 py-2.5 rounded-lg text-xs font-bold transition" data-i18n="copy_cmd">复制命令</button>
        </div>
      </div>
  
      <div class="section-box">
          <h2 class="text-lg font-bold mb-4 flex items-center gap-2 opacity-90">
              <svg class="w-5 h-5 text-purple-600 dark:text-purple-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/></svg>
              <span data-i18n="daemon_title">镜像源配置 (Daemon.json)</span>
          </h2>
          <div class="code-area rounded-lg p-4 overflow-x-auto text-sm">
              <p class="text-gray-500 dark:text-gray-500 mb-1" data-i18n="daemon_step1"># 1. 编辑配置文件</p>
              <p class="font-mono text-blue-600 dark:text-blue-400 font-bold mb-4">nano /etc/docker/daemon.json</p>
              <p class="text-gray-500 dark:text-gray-500 mb-1" data-i18n="daemon_step2"># 2. 填入以下内容</p>
              <pre id="daemon-json-content" class="font-mono text-emerald-600 dark:text-emerald-400 mb-4 bg-transparent p-0 border-0"></pre>
              <p class="text-gray-500 dark:text-gray-500 mb-1" data-i18n="daemon_step3"># 3. 重启 Docker</p>
              <p class="font-mono text-blue-600 dark:text-blue-400 font-bold">sudo systemctl daemon-reload && sudo systemctl restart docker</p>
          </div>
          <button onclick="copyDaemonJson()" class="mt-4 px-4 py-2 bg-gray-800 dark:bg-white hover:bg-black dark:hover:bg-gray-200 text-white dark:text-black rounded-lg text-xs font-bold transition shadow-sm flex items-center gap-2">
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 5H6a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2v-1M8 5a2 2 0 002 2h2a2 2 0 002-2M8 5a2 2 0 012-2h2a2 2 0 012 2m0 0h2a2 2 0 012 2v3m2 4H10m0 0l3-3m-3 3l3 3"/></svg>
              <span data-i18n="copy_config">复制配置</span>
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
            <h3 class="text-lg font-bold mb-2" data-i18n="reset_confirm_title">确认重置额度？</h3>
            <p class="text-sm opacity-70 mb-6 px-4"><span data-i18n="reset_confirm_desc">此操作将清空您当前 IP 在今日的请求记录。</span> (${ip})</p>
            <div class="flex gap-3">
               <button onclick="closeModal('confirmModal')" class="flex-1 px-4 py-2.5 bg-gray-100 hover:bg-gray-200 dark:bg-slate-700 dark:hover:bg-slate-600 rounded-lg text-sm font-bold transition" data-i18n="cancel">取消</button>
               <button onclick="confirmReset()" class="flex-1 px-4 py-2.5 bg-red-500 hover:bg-red-600 text-white rounded-lg text-sm font-bold transition shadow-lg shadow-red-500/30" data-i18n="confirm_reset">确定重置</button>
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
            <h3 class="text-2xl font-bold mb-2" data-i18n="warning_title">⚠️ 高能预警</h3>
            <p class="text-1xl opacity-70 mb-2 px-4" data-i18n="reset_all_desc">确定要清空【所有用户】的统计数据吗？</p>
            <p class="text-1xl text-red-500 font-bold mb-6" data-i18n="irreversible">此操作不可恢复！</p>
            <div class="flex gap-3">
               <button onclick="closeResetAllModal()" class="flex-1 px-4 py-2.5 bg-gray-100 hover:bg-gray-200 dark:bg-slate-700 dark:hover:bg-slate-600 rounded-lg text-sm font-bold transition" data-i18n="cancel">取消</button>
               <button onclick="confirmResetAll()" class="flex-1 px-4 py-2.5 bg-red-600 hover:bg-red-700 text-white rounded-lg text-sm font-bold transition shadow-lg shadow-red-600/30" data-i18n="confirm_clear">确认清空</button>
            </div>
         </div>
      </div>
    </div>

    <div id="logsModal" class="modal-overlay">
      <div class="modal-content modal-content-lg">
          <div class="flex justify-between items-center mb-4">
              <h3 class="text-lg font-bold" data-i18n="logs_title">📄 最近访问日志 (Admin)</h3>
              <button onclick="closeModal('logsModal')" class="text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200">
                  <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
              </button>
          </div>
          
          <div class="log-toolbar">
              <div class="flex items-center gap-2">
                  <button onclick="deleteSelectedLogs()" class="log-btn btn-red flex items-center gap-1">
                      <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path></svg>
                      <span data-i18n="delete_selected">删除选中</span>
                  </button>
                  <button onclick="exportLogsCsv()" class="log-btn bg-green-100 text-green-600 border border-green-200 dark:bg-green-900 dark:text-green-300 dark:border-green-800 flex items-center gap-1">
                      <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/></svg>
                      <span data-i18n="export_csv">导出CSV</span>
                  </button>
              </div>
              <div class="flex-grow"></div>
              <div class="flex items-center gap-2">
                <input id="log-search" type="text" placeholder="搜索 IP/路径..." class="text-xs p-1.5 rounded border border-gray-300 dark:border-slate-600 bg-white dark:bg-slate-900 w-24 md:w-32" oninput="filterLogs()">
                <select id="log-status-filter" class="text-xs p-1.5 rounded border border-gray-300 dark:border-slate-600 bg-white dark:bg-slate-900" onchange="filterLogs()">
                  <option value="all">Status</option>
                  <option value="200">2xx</option>
                  <option value="300">3xx</option>
                  <option value="400">4xx</option>
                  <option value="500">5xx</option>
                </select>
              </div>
              <div class="flex items-center gap-2 bg-gray-100 dark:bg-slate-800 p-1 rounded-lg">
                  <span class="text-xs font-bold px-2 opacity-70" data-i18n="clean_old">清理旧日志:</span>
                  <select id="keep-days" onchange="toggleCustomDays()" class="text-xs p-1.5 rounded border border-gray-300 dark:border-slate-600 bg-white dark:bg-slate-900">
                      <option value="1">1 Day</option>
                      <option value="3">3 Days</option>
                      <option value="7">7 Days</option>
                      <option value="30">30 Days</option>
                      <option value="custom">...</option>
                  </select>
                  <input id="custom-days-input" type="number" placeholder="Days" class="hidden text-xs p-1.5 w-16 rounded border border-gray-300 dark:border-slate-600 bg-white dark:bg-slate-900">
                  <button onclick="deleteOldLogs()" class="log-btn btn-blue flex items-center gap-1">
                      <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path></svg>
                  </button>
              </div>
          </div>

          <div class="max-h-[60vh] overflow-y-auto rounded-lg border border-gray-200 dark:border-slate-700">
              <div class="log-table-x-wrapper" style="overflow-x: auto; width: 100%;">
                <table class="log-table">
                    <thead class="bg-gray-50 dark:bg-slate-800 sticky top-0">
                        <tr>
                            <th class="check-col"><input type="checkbox" id="select-all-logs" onchange="toggleSelectAllLogs()"></th>
                            <th width="15%" data-i18n="col_time">时间</th>
                            <th width="8%" data-i18n="col_status">状态</th>
                            <th width="12%">IP</th>
                            <th width="35%" data-i18n="col_path">访问路径</th>
                            <th width="20%" data-i18n="col_upstream">上游</th>
                            <th width="10%" data-i18n="col_perf">耗时/大小</th>
                        </tr>
                    </thead>
                    <tbody id="logs-table-body" class="bg-white dark:bg-slate-900">
                        <tr><td colspan="7" class="text-center py-4" data-i18n="loading">加载中...</td></tr>
                    </tbody>
                </table>
              </div> </div>
      </div>
    </div>

    <div id="universalConfirmModal" class="modal-overlay">
      <div class="modal-content">
         <div class="text-center">
            <div class="w-12 h-12 bg-red-100 dark:bg-red-900/30 rounded-full flex items-center justify-center mb-4 mx-auto text-red-500">
              <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
            </div>
            <h3 id="uni-confirm-title" class="text-lg font-bold mb-2">Confirm?</h3>
            <p id="uni-confirm-desc" class="text-sm opacity-70 mb-6 px-4">Action cannot be undone.</p>
            <div class="flex gap-3">
               <button onclick="closeModal('universalConfirmModal')" class="flex-1 px-4 py-2.5 bg-gray-100 hover:bg-gray-200 dark:bg-slate-700 dark:hover:bg-slate-600 rounded-lg text-sm font-bold transition" data-i18n="cancel">Cancel</button>
               <button onclick="performPendingAction()" class="flex-1 px-4 py-2.5 bg-red-500 hover:bg-red-600 text-white rounded-lg text-sm font-bold transition shadow-lg shadow-red-500/30" data-i18n="confirm">Confirm</button>
            </div>
         </div>
      </div>
    </div>

    <div id="toast" class="toast bg-slate-800 text-white"></div>
    
    <div id="logDetailModal" class="modal-overlay">
      <div class="modal-content">
         <div class="flex justify-between items-center mb-4 border-b border-gray-100 dark:border-slate-700 pb-2">
             <h3 class="text-lg font-bold" data-i18n="detail_title">📄 完整内容详情</h3>
             <button onclick="closeModal('logDetailModal')" class="text-gray-500 hover:text-gray-700 dark:text-gray-400">
                 <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
             </button>
         </div>
         <div class="bg-gray-50 dark:bg-slate-800 p-4 rounded-lg border border-gray-200 dark:border-slate-700">
             <p class="text-xs font-bold text-gray-500 mb-1 uppercase" data-i18n="full_text">完整文本 (已自动换行):</p>
             <div id="log-detail-modal-content" class="text-sm text-gray-800 dark:text-gray-200 select-all"></div>
         </div>
         <div class="mt-4 text-right">
             <button onclick="closeModal('logDetailModal')" class="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-sm font-bold transition" data-i18n="close">关闭</button>
         </div>
      </div>
    </div>

    <script>
      // --- I18N Configuration ---
      const I18N_DATA = {
        "en": {
            "main_title": "Cloudflare Accelerator",
            "daily_limit": "Daily Limit",
            "reset_limit": "Reset",
            "admin_stats": "Stats",
            "access_logs": "Logs",
            "limit_desc": "Quota refunds on failure · Short-term dupes ignored · <span class='text-green-600 dark:text-green-400 font-bold'>Linux Mirrors (Ubuntu, etc) are Free</span>",
            "stats_overview": "Global Overview Today",
            "reset_all_data": "Clear All Data",
            "loading": "Loading...",
            "hmac_title": "Sign Link Gen (Password-free)",
            "hmac_placeholder": "Target URL (e.g., https://github.com/...)",
            "1_hour": "1 Hour",
            "24_hours": "24 Hours",
            "10_mins": "10 Mins",
            "custom_time": "Custom...",
            "gen_link": "Generate",
            "hmac_note": "* Link contains signature for password-free access. Keep it safe.",
            "github_title": "GitHub File / Script Accelerator",
            "github_placeholder": "Paste URL or bash/curl/git command",
            "get_link": "Get Link",
            "raw_url_label": "1. Accelerated URL (Raw):",
            "copy_link": "Copy Link",
            "visit_now": "Visit Now",
            "terminal_cmd_label": "2. Terminal Command:",
            "copy_cmd": "Copy Command",
            "recursive_title": "Recursive Script (Shell/Curl)",
            "recursive_desc": "For curl | bash scripts. Choose /r/ (Rewrite All) or /rt/ (Text Only).",
            "mode_r": "/r/ Rewrite All",
            "mode_rt": "/rt/ Text Only",
            "recursive_placeholder": "e.g., https://get.docker.com",
            "gen_cmd": "Generate",
            "docker_title": "Docker Image Accelerator",
            "docker_placeholder": "e.g., nginx or library/redis",
            "get_cmd": "Get Cmd",
            "copy_cmd_one_click": "Copy Command",
            "linux_title": "Linux Mirror (Range Support)",
            "linux_select": "Select OS...",
            "gen_mirror_cmd": "Generate Cmd",
            "use_cmd_replace": "Run this to replace sources:",
            "linux_note": "* Note: Replaces official sources only. Manual edit needed for custom sources.",
            "daemon_title": "Registry Config (Daemon.json)",
            "daemon_step1": "# 1. Edit Config",
            "daemon_step2": "# 2. Paste Content",
            "daemon_step3": "# 3. Restart Docker",
            "copy_config": "Copy Config",
            "reset_confirm_title": "Reset Daily Limit?",
            "reset_confirm_desc": "This will clear request records for your IP today.",
            "cancel": "Cancel",
            "confirm_reset": "Reset Now",
            "warning_title": "⚠️ Warning",
            "reset_all_desc": "Clear stats for ALL users?",
            "irreversible": "This cannot be undone!",
            "confirm_clear": "Clear All",
            "logs_title": "📄 Access Logs (Admin)",
            "delete_selected": "Delete",
            "export_csv": "Export CSV",
            "clean_old": "Clean Old:",
            "col_time": "Time",
            "col_status": "Status",
            "col_path": "Path",
            "col_upstream": "Upstream",
            "col_perf": "Perf",
            "detail_title": "📄 Detail View",
            "full_text": "Full Text:",
            "close": "Close",
            "confirm": "Confirm"
        },
        "zh": {
            "main_title": "Cloudflare 加速通道",
            "daily_limit": "今日额度",
            "reset_limit": "重置额度",
            "admin_stats": "全站统计",
            "access_logs": "访问日志",
            "limit_desc": "失败自动退还额度 · 短时重复请求不扣费 · <span class='text-green-600 dark:text-green-400 font-bold'>软件源镜像 (Ubuntu 等) 免费不限量</span>",
            "stats_overview": "今日全站概况",
            "reset_all_data": "清空全站数据",
            "loading": "正在加载...",
            "hmac_title": "签名链接生成 (免密分享)",
            "hmac_placeholder": "目标 URL (如 https://github.com/...)",
            "1_hour": "1 小时",
            "24_hours": "24 小时",
            "10_mins": "10 分钟",
            "custom_time": "自定义...",
            "gen_link": "生成链接",
            "hmac_note": "* 此链接包含签名，有效期内可免密访问，请妥善保管。",
            "github_title": "GitHub 文件 / 脚本命令加速",
            "github_placeholder": "粘贴 链接 或 bash/curl/git 完整命令",
            "get_link": "获取链接",
            "raw_url_label": "1. 加速链接 (Raw URL):",
            "copy_link": "复制链接",
            "visit_now": "立即访问",
            "terminal_cmd_label": "2. 终端命令:",
            "copy_cmd": "复制命令",
            "recursive_title": "递归脚本加速 (Shell / Curl)",
            "recursive_desc": "适用于 curl | bash 脚本。可选择强制重写所有 (/r/) 或仅文本递归 (/rt/)。",
            "mode_r": "/r/ 强制重写所有",
            "mode_rt": "/rt/ 仅文本递归",
            "recursive_placeholder": "如: https://get.docker.com",
            "gen_cmd": "生成命令",
            "docker_title": "Docker 镜像加速",
            "docker_placeholder": "如 nginx 或 library/redis",
            "get_cmd": "获取命令",
            "copy_cmd_one_click": "一键复制命令",
            "linux_title": "Linux 软件源加速 (Range 支持)",
            "linux_select": "请选择系统 (Select OS)...",
            "gen_mirror_cmd": "生成换源命令",
            "use_cmd_replace": "使用以下命令一键替换：",
            "linux_note": "* 注意：脚本仅替换官方默认源。若您已使用其他镜像源（如阿里云），请手动编辑文件。",
            "daemon_title": "镜像源配置 (Daemon.json)",
            "daemon_step1": "# 1. 编辑配置文件",
            "daemon_step2": "# 2. 填入以下内容",
            "daemon_step3": "# 3. 重启 Docker",
            "copy_config": "复制配置",
            "reset_confirm_title": "确认重置额度？",
            "reset_confirm_desc": "此操作将清空您当前 IP 在今日的请求记录。",
            "cancel": "取消",
            "confirm_reset": "确定重置",
            "warning_title": "⚠️ 高能预警",
            "reset_all_desc": "确定要清空【所有用户】的统计数据吗？",
            "irreversible": "此操作不可恢复！",
            "confirm_clear": "确认清空",
            "logs_title": "📄 最近访问日志 (Admin)",
            "delete_selected": "删除选中",
            "export_csv": "导出CSV",
            "clean_old": "清理旧日志:",
            "col_time": "时间",
            "col_status": "状态",
            "col_path": "访问路径",
            "col_upstream": "上游",
            "col_perf": "耗时/大小",
            "detail_title": "📄 完整内容详情",
            "full_text": "完整文本 (已自动换行):",
            "close": "关闭",
            "confirm": "确定执行"
        }
      };

        // --- 从当前 URL 自动推导前缀："/<password>" ---
        // 假设你的页面访问路径是：https://domain.com/<password> 或 /<password>/
        function getApiPrefixFromPath() {
        const parts = (window.location.pathname || '').split('/').filter(Boolean);
        // parts[0] 预期就是 password
        if (!parts || parts.length === 0) return '';
        return '/' + parts[0];
    }

        // --- 初始化全局变量 ---
        window.CURRENT_DOMAIN = window.location.hostname;
        window.API_PREFIX = getApiPrefixFromPath();                       // "/<password>"
        window.PROXY_PREFIX = window.location.origin + window.API_PREFIX + '/'; // "https://domain/<password>/"

        window.CURRENT_CLIENT_IP = "${ip}";
        window.LINUX_MIRRORS = ${linuxMirrorsJson};
        window.ALL_LOGS = [];
        window.FILTERED_LOGS = [];
        window.currentLang = 'zh'; // Default


      let githubAcceleratedUrl = '';
      let githubOpenUrl = '';
      let githubCommand = '';

      let recursiveCommand = '';
      let recursiveUrlOnly = '';
      let dockerCommand = '';
      let linuxCommand = '';
      let daemonJsonStr = '';

      // --- I18N Logic ---
      window.toggleLanguage = function() {
          const newLang = window.currentLang === 'zh' ? 'en' : 'zh';
          window.setLanguage(newLang);
      }

      window.setLanguage = function(lang) {
          window.currentLang = lang;
          localStorage.setItem('lang', lang);
          document.documentElement.lang = lang === 'zh' ? 'zh-CN' : 'en';
          
          const btnText = document.getElementById('lang-text');
          if(btnText) btnText.textContent = lang === 'zh' ? 'CN' : 'EN';

          const data = I18N_DATA[lang];
          if (!data) return;

          // Replace Text Content
          document.querySelectorAll('[data-i18n]').forEach(el => {
              const key = el.getAttribute('data-i18n');
              if (data[key]) el.innerHTML = data[key]; // Use innerHTML to support span colors
          });

          // Replace Placeholders
          document.querySelectorAll('[data-i18n-placeholder]').forEach(el => {
              const key = el.getAttribute('data-i18n-placeholder');
              if (data[key]) el.setAttribute('placeholder', data[key]);
          });
      }

      // --- 提示框 (Toast) 工具 ---
      window.showToast = function(message, isError = false) {
        const toast = document.getElementById('toast');
        if (!toast) return;
        toast.innerHTML = message;
        toast.className = 'toast ' + (isError ? 'bg-red-500' : 'bg-slate-800') + ' show';
        setTimeout(() => toast.classList.remove('show'), 3000);
      }

      // --- 模态框控制 ---
      window.openModal = function(id) {
        const el = document.getElementById(id);
        if (el) el.classList.add('open');
      }
      window.closeModal = function(id) {
        const el = document.getElementById(id);
        if (el) el.classList.remove('open');
      }

      // --- 剪贴板复制工具 ---
      window.copyToClipboard = function(text) {
        if (navigator.clipboard && window.isSecureContext) { return navigator.clipboard.writeText(text); }
        const textArea = document.createElement("textarea");
        textArea.value = text; textArea.style.position = "fixed";
        document.body.appendChild(textArea); textArea.focus(); textArea.select();
        try { document.execCommand('copy'); document.body.removeChild(textArea); return Promise.resolve(); }
        catch (err) { document.body.removeChild(textArea); return Promise.reject(err); }
      }

      // --- 格式化字节 ---
      window.formatBytes = function(bytes) {
          try {
              const b = parseInt(bytes);
              if (isNaN(b) || b < 0) return '-';
              if (b < 1024) return b + 'B';
              if (b < 1024 * 1024) return (b / 1024).toFixed(1) + 'KB';
              if (b < 1024 * 1024 * 1024) return (b / (1024 * 1024)).toFixed(1) + 'MB';
              return (b / (1024 * 1024 * 1024)).toFixed(2) + 'GB';
          } catch (e) { return '-'; }
      }

      // --- 主题切换逻辑 ---
      window.toggleTheme = function() {
        try {
            const body = document.body;
            const sun = document.querySelector('.sun');
            const moon = document.querySelector('.moon');
            if (!body || !sun || !moon) return;

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

      // ======================================================================
      // 核心逻辑: GitHub/通用加速
      // ======================================================================
      window.convertGithubUrl = function() {
        let input = document.getElementById('github-url').value.trim();
        if (!input) return window.showToast('❌ 请输入内容', true);

        const urlRegex = /https?:\\/\\/[^\\s"'()<>]+/;
        const match = input.match(urlRegex);
        let originalUrl = "";

        if (match) { originalUrl = match[0]; }
        else {
            if (!input.includes(' ')) { originalUrl = 'https://' + input; }
            else { return window.showToast('❌ 无法识别有效链接', true); }
        }

        const prefix = window.PROXY_PREFIX;
        const proxiedUrl = prefix + originalUrl;
        let finalCommand = "";
        let label = "";
        const isPureUrl = (match && input === match[0]) || (('https://' + input) === originalUrl);
        
        const repoRegex = /^https?:\\/\\/(?:www\\.)?github\\.com\\/[^\\/]+\\/[^\\/]+(?:\\.git)?\\/?$/;

        if (isPureUrl) {
            if (repoRegex.test(originalUrl)) {
                finalCommand = 'git clone ' + proxiedUrl;
                label = "终端命令 (Git Clone):";
                window.showToast('✅ 已识别为仓库');
            } else {
                const fileName = originalUrl.split('/').pop() || 'download';
                finalCommand = 'wget -c -O "' + fileName + '" "' + proxiedUrl + '"';
                label = "终端命令 (Wget):";
                window.showToast('✅ 已生成 Wget 命令');
            }
        } else {
            finalCommand = input.replace(originalUrl, proxiedUrl);
            label = "终端命令 (自动替换):";
            window.showToast('✅ 已替换命令中的链接');
        }

        githubAcceleratedUrl = proxiedUrl;
        githubOpenUrl = proxiedUrl;
        githubCommand = finalCommand;

        document.getElementById('github-result-url').textContent = proxiedUrl;
        // Update label text based on language if possible, but keep simple for now
        // document.getElementById('github-cmd-label').textContent = "2. " + label; 
        document.getElementById('github-result-cmd').textContent = finalCommand;
        document.getElementById('github-result-box').classList.remove('hidden');
      }

      window.copyGithubUrlOnly = function() { window.copyToClipboard(githubAcceleratedUrl).then(() => window.showToast('✅ 链接已复制')); }
      window.openGithubUrl = function() { window.open(githubOpenUrl, '_blank'); }
      window.copyGithubCmd = function() { window.copyToClipboard(githubCommand).then(() => window.showToast('✅ 命令已复制')); }

      // ======================================================================
      // 核心逻辑: 递归脚本加速
      // ======================================================================
      window.convertRecursiveUrl = function() {
        let input = document.getElementById('recursive-url').value.trim();
        if (!input) return window.showToast('❌ 请输入链接', true);

        const modeEl = document.getElementById('recursive-mode');
        const mode = modeEl ? modeEl.value : 'r'; 

        const urlMatch = input.match(/(https?:\\/\\/[^\\s"'\)]+)/);
        let targetUrl = input;
        if (urlMatch) { targetUrl = urlMatch[0]; }
        else { if (!targetUrl.startsWith('http')) { targetUrl = 'https://' + targetUrl; } }

        const baseUrl = window.PROXY_PREFIX;
        const rawProxyUrl = baseUrl + targetUrl;
        const recursivePrefix = (mode === 'rt') ? 'rt/' : 'r/';
        const recursiveProxyUrl = baseUrl + recursivePrefix + targetUrl;

        const isCommand = input.includes('bash') || input.includes('curl') || input.includes('wget') || input.includes(' ');
        const repoRegex = /^https?:\\/\\/(?:www\\.)?github\\.com\\/[^\\/]+\\/[^\\/]+(?:\\.git)?\\/?$/;

        let displayUrl = recursiveProxyUrl;

        if (isCommand && urlMatch) {
             if (input.includes('git clone') || repoRegex.test(targetUrl)) {
                 recursiveCommand = input.replace(targetUrl, rawProxyUrl);
                 displayUrl = rawProxyUrl;
             } else {
                 recursiveCommand = input.replace(targetUrl, recursiveProxyUrl);
             }
             window.showToast('✅ 已替换命令中的链接');
        } else {
             if (repoRegex.test(targetUrl)) {
                 recursiveCommand = 'git clone ' + rawProxyUrl;
                 displayUrl = rawProxyUrl;
                 window.showToast('✅ 已识别为仓库 (Raw模式)');
             } else {
                 const fileName = targetUrl.split('/').pop() || 'script';
                 recursiveCommand = 'wget -c -O "' + fileName + '" "' + recursiveProxyUrl + '"';
                 displayUrl = recursiveProxyUrl;
                 window.showToast('✅ 已生成 Wget 命令');
             }
        }

        recursiveUrlOnly = displayUrl;
        document.getElementById('recursive-result-url').textContent = recursiveUrlOnly;
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
          
          if (!distro || distro === "") {
              return window.showToast('❌ 请先选择一个系统 (如 Ubuntu)', true);
          }

          const baseUrl = window.location.origin + window.API_PREFIX + '/' + distro + '/';
          const securityUrl = window.location.origin + window.API_PREFIX + '/' + distro + '-security/';

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
          const res = await fetch(window.API_PREFIX + '/reset');
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
          const res = await fetch(window.API_PREFIX + '/reset-all');
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
                const res = await fetch(window.API_PREFIX + '/stats');
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

      // --- [增强 v5.0] 生成签名链接逻辑 ---
      window.toggleSignTtl = function() {
          const select = document.getElementById('sign-ttl');
          const customContainer = document.getElementById('sign-custom-container');
          if (select.value === 'custom') {
              customContainer.classList.remove('hidden');
          } else {
              customContainer.classList.add('hidden');
          }
      }

      window.generateSignedUrl = async function() {
          const target = document.getElementById('sign-target').value.trim();
          let seconds = document.getElementById('sign-ttl').value;
          
          if (seconds === 'custom') {
              const d = parseInt(document.getElementById('ttl-days').value || 0);
              const h = parseInt(document.getElementById('ttl-hours').value || 0);
              const m = parseInt(document.getElementById('ttl-minutes').value || 0);
              seconds = (d * 86400) + (h * 3600) + (m * 60);
              
              if (seconds <= 0) {
                  return window.showToast('❌ 请输入有效的时间', true);
              }
          }

          if (!target) return window.showToast('❌ 请输入目标 URL', true);
          try {
              const res = await fetch(window.API_PREFIX + '/sign-url', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target, seconds })
                });

              const result = await res.json();
              if (res.ok && result.status === 'success') {
                  const fullUrl = window.location.origin + result.url;
                  document.getElementById('sign-result').textContent = fullUrl;
                  document.getElementById('sign-result-box').classList.remove('hidden');
              } else {
                  window.showToast('❌ 生成失败: ' + (result.message || '未知错误'), true);
              }
          } catch(e) { window.showToast('❌ 网络错误', true); }
      }
      
      window.copySignedUrl = function() {
          const url = document.getElementById('sign-result').textContent;
          if(url) window.copyToClipboard(url).then(() => window.showToast('✅ 链接已复制'));
      }

      // ==========================================
      // 🟢 日志管理与筛选函数 (Fix Missing Functions)
      // ==========================================

      // 1. 筛选与渲染日志 (Filter & Render)
      window.filterLogs = function() {
          const input = document.getElementById('log-search').value.toLowerCase();
          const statusFilter = document.getElementById('log-status-filter').value;
          
          if (!window.ALL_LOGS) window.ALL_LOGS = [];
          
          window.FILTERED_LOGS = window.ALL_LOGS.filter(log => {
              // 搜索关键词 (IP 或 URL)
              const matchSearch = (log.ip && log.ip.includes(input)) || (log.url && log.url.toLowerCase().includes(input));
              // 状态码筛选
              let matchStatus = true;
              if (statusFilter !== 'all') {
                  const s = log.status;
                  if (statusFilter === '200') matchStatus = (s >= 200 && s < 300);
                  else if (statusFilter === '300') matchStatus = (s >= 300 && s < 400);
                  else if (statusFilter === '400') matchStatus = (s >= 400 && s < 500);
                  else if (statusFilter === '500') matchStatus = (s >= 500);
              }
              return matchSearch && matchStatus;
          });

          renderLogsTable(window.FILTERED_LOGS);
      }

      // 2. 渲染表格 DOM (已修复：使用单引号拼接，防止 Worker 报错)
      function renderLogsTable(logs) {
          const tbody = document.getElementById('logs-table-body');
          if (!logs || logs.length === 0) {
              tbody.innerHTML = '<tr><td colspan="7" class="text-center py-4 opacity-60">没有符合条件的日志</td></tr>';
              return;
          }

          // [新增] 安全转义，防止 title 属性破坏 HTML 结构
          const escapeHtml = (unsafe) => {
              return (unsafe || "").toString()
                  .replace(/&/g, "&amp;")
                  .replace(/</g, "&lt;")
                  .replace(/>/g, "&gt;")
                  .replace(/"/g, "&quot;")
                  .replace(/'/g, "&#039;");
          }

          let html = '';
          logs.forEach(log => {
              // 状态码颜色
              let statusColor = 'text-green-600 dark:text-green-400';
              if (log.status >= 300 && log.status < 400) statusColor = 'text-yellow-600 dark:text-yellow-400';
              if (log.status >= 400) statusColor = 'text-red-600 dark:text-red-400';

              // 缓存标记
              const cacheBadge = log.cache_hit ? '<span class="px-1 py-0.5 rounded bg-green-100 dark:bg-green-900 text-green-600 dark:text-green-400 text-[10px] ml-1">HIT</span>' : '';

              // ⚠️ 关键修改：这里全部改用单引号 + 字符串拼接
              html += '<tr class="hover:bg-gray-50 dark:hover:bg-slate-800 transition">';
              html += '<td class="check-col"><input type="checkbox" class="log-check" value="' + log.id + '"></td>';
              html += '<td>' + log.time.replace('T', ' ') + '</td>';
              html += '<td class="font-bold ' + statusColor + '">' + log.status + '</td>';
              
              // 增加 title 属性 (Tooltip) [修正] 使用 escapeHtml
              html += '<td class="text-blue-600 dark:text-blue-400" title="' + escapeHtml(log.ip) + '">' + log.ip + '</td>';
              html += '<td title="' + escapeHtml(log.url) + '"><div class="truncate w-64">' + log.url + '</div></td>';
              html += '<td class="opacity-70" title="' + escapeHtml(log.upstream) + '"><div class="truncate w-32">' + log.upstream + '</div></td>';
              
              html += '<td class="opacity-70">' + log.duration + 'ms / ' + window.formatBytes(log.bytes) + cacheBadge + '</td>';
              html += '</tr>';
          });
          tbody.innerHTML = html;
      }

      // 3. 全选/反选
      window.toggleSelectAllLogs = function() {
          const checked = document.getElementById('select-all-logs').checked;
          document.querySelectorAll('.log-check').forEach(box => box.checked = checked);
      }

      // 4. 删除选中日志
      window.deleteSelectedLogs = function() {
          const checkedBoxes = document.querySelectorAll('.log-check:checked');
          const ids = Array.from(checkedBoxes).map(cb => parseInt(cb.value));
          if (ids.length === 0) return window.showToast('❌ 请先勾选日志', true);
          
          if(!confirm('确定要删除选中的 ' + ids.length + ' 条日志吗？')) return;

          fetch(window.API_PREFIX + '/delete-logs', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ ids: ids })
            }).then(res => res.json()).then(data => {
              if(data.status === 'success') {
                  window.showToast('✅ 删除成功');
                  window.fetchLogs(); // 刷新
              } else {
                  window.showToast('❌ 删除失败', true);
              }
          }).catch(() => window.showToast('❌ 网络错误', true));
      }

      // 5. 切换自定义天数输入框
      window.toggleCustomDays = function() {
          const val = document.getElementById('keep-days').value;
          const customInput = document.getElementById('custom-days-input');
          if (val === 'custom') customInput.classList.remove('hidden');
          else customInput.classList.add('hidden');
      }

      // 6. 删除旧日志 (按天数)
      window.deleteOldLogs = function() {
          let days = document.getElementById('keep-days').value;
          if (days === 'custom') {
              days = document.getElementById('custom-days-input').value;
              if (!days) return window.showToast('❌ 请输入天数', true);
          }
          
          if(!confirm('确定要删除 ' + days + ' 天前的所有日志吗？')) return;

          fetch(window.API_PREFIX + '/delete-logs', {
              method: 'POST',
              headers: {'Content-Type': 'application/json'},
              body: JSON.stringify({ days: days })
          }).then(res => res.json()).then(data => {
              if(data.status === 'success') {
                  window.showToast('✅ 清理成功');
                  window.fetchLogs();
              } else {
                  window.showToast('❌ 清理失败', true);
              }
          }).catch(() => window.showToast('❌ 网络错误', true));
      }
      
      // 7. 通用执行占位符
      window.performPendingAction = function() {
          window.closeModal('universalConfirmModal');
      }

      // --- [增强 v5.0] 查看日志逻辑 ---
      window.openLogsModal = function() {
          document.getElementById('logsModal').classList.add('open');
          window.fetchLogs();
      }

      // [优化后的日志获取函数]
      window.fetchLogs = async function() {
          const tbody = document.getElementById('logs-table-body');
          if (tbody) {
              tbody.innerHTML = '<tr><td colspan="7" class="text-center py-4">正在加载日志数据...</td></tr>';
          }

          try {
              const res = await fetch(window.API_PREFIX + '/logs');

              if (res.status === 403) {
                  if (tbody) {
                      tbody.innerHTML = '<tr><td colspan="7" class="text-center py-4 text-red-500 font-bold">❌ 拒绝访问：您当前的 IP 不是管理员 IP，无法查看日志。</td></tr>';
                  }
                  window.ALL_LOGS = [];
                  window.FILTERED_LOGS = [];
                  return false;
              }

              const result = await res.json();

              if (res.ok && result.status === "success") {
                  const logs = result.data || [];

                  if (logs.length === 0) {
                      if (tbody) {
                          tbody.innerHTML = '<tr><td colspan="7" class="text-center py-4 opacity-60">暂无日志 (请检查 D1/KV 绑定是否正确，或尝试访问几次代理链接)</td></tr>';
                      }
                      window.ALL_LOGS = [];
                      window.FILTERED_LOGS = [];
                      return false;
                  }

                  window.ALL_LOGS = logs.map((l, index) => ({
                      id: (typeof l.id !== 'undefined') ? l.id : index,
                      time: l.time || l.created_at || '',
                      ip: l.ip || '',
                      url: l.url || '',
                      status: parseInt(l.status || '0', 10),
                      upstream: l.upstream || '',
                      duration: parseInt(l.duration || '0', 10),
                      bytes: parseInt(l.bytes || '-1', 10),
                      cache_hit: l.cache_hit ? 1 : 0
                  }));

                  window.filterLogs();
                  window.showToast('✅ 日志已加载');
                  return true;
              } else {
                  const errorMsg = result && result.data && result.data[0] && result.data[0].url ? result.data[0].url : '获取失败';
                  if (tbody) {
                      tbody.innerHTML = '<tr><td colspan="7" class="text-center py-4 text-red-500">' + errorMsg + '</td></tr>';
                  }
                  window.ALL_LOGS = [];
                  window.FILTERED_LOGS = [];
                  return false;
              }
          } catch (e) {
              console.error(e);
              if (tbody) {
                  tbody.innerHTML = '<tr><td colspan="7" class="text-center py-4 text-red-500">❌ 网络错误或数据库未连接</td></tr>';
              }
              window.ALL_LOGS = [];
              window.FILTERED_LOGS = [];
              return false;
          }
      }

      // [新增] 导出 CSV
      window.exportLogsCsv = async function() {
          try {
              if (!window.ALL_LOGS || window.ALL_LOGS.length === 0) {
                  window.showToast('正在加载日志后导出...');
                  const ok = await window.fetchLogs();
                  if (!ok) return window.showToast('❌ 没有可导出的日志（日志为空或加载失败）', true);
              }

              const rows = window.FILTERED_LOGS && window.FILTERED_LOGS.length > 0 ? window.FILTERED_LOGS : (window.ALL_LOGS || []);
              if (!rows || rows.length === 0) return window.showToast('❌ 没有可导出的日志（过滤结果为空）', true);

              const header = ['id','time','status','ip','url','upstream','duration_ms','bytes','cache_hit'];

              const escapeCsv = function(v) {
                  const s = (v === null || v === undefined) ? '' : String(v);
                  if (s.includes('"') || s.includes(',') || s.includes('\\n') || s.includes('\\r')) {
                      return '"' + s.replace(/"/g, '""') + '"';
                  }
                  return s;
              };

              let csv = header.join(',') + '\\n';
              for (let i = 0; i < rows.length; i++) {
                  const r = rows[i];
                  const line = [
                      r.id,
                      r.time,
                      r.status,
                      r.ip,
                      r.url,
                      r.upstream,
                      r.duration,
                      r.bytes,
                      r.cache_hit ? 1 : 0
                  ].map(escapeCsv).join(',');
                  csv += line + '\\n';
              }

              const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' });
              const u = URL.createObjectURL(blob);
              const a = document.createElement('a');
              a.href = u;
              a.download = 'access_logs.csv';
              document.body.appendChild(a);
              a.click();
              document.body.removeChild(a);
              URL.revokeObjectURL(u);

              window.showToast('✅ CSV 已导出');
          } catch (e) {
              console.error(e);
              window.showToast('❌ 导出失败', true);
          }
      };

      // [新增] 日志 UI 增强逻辑 (事件委托)
      window.initLogsUiEnhancements = function() {
          const tableBody = document.getElementById('logs-table-body');
          if (!tableBody) return;

          // 使用事件委托处理点击，避免改动 renderLogsTable
          tableBody.addEventListener('click', function(e) {
              // 寻找最近的 td 元素
              const td = e.target.closest('td');
              if (!td) return;
              
              // 忽略复选框列 (第一列)
              if (td.classList.contains('check-col') || td.querySelector('input[type="checkbox"]')) return;

              // [修正] 优先使用 textContent 获取完整文本，即使 CSS 做了截断
              let fullText = td.getAttribute('title'); // 优先拿完整title
              if (!fullText) fullText = td.textContent ? td.textContent.trim() : ''; // 拿纯文本
              
              // 如果内容太短，或者是 "-" 等无意义字符，不弹窗 (除非是 URL 列，URL 列总是值得查看)
              // 简单的判断：如果内容长度超过 20 或者 包含 / 或 . 则认为是值得展示的
              if (fullText && (fullText.length > 20 || fullText.includes('/') || fullText.includes('.'))) {
                  const detailBox = document.getElementById('log-detail-modal-content');
                  if (detailBox) {
                      detailBox.textContent = fullText;
                      window.openModal('logDetailModal');
                  }
              }
          });
      }; 

      // [新增] 自定义时间 UI 初始化函数
      window.initSignTtlUi = function() {
          const select = document.getElementById('sign-ttl');
          const container = document.getElementById('sign-custom-container');
          if (!select || !container) return;

          // 增强 Inputs: 纯数字模式
          const inputs = container.querySelectorAll('input');
          inputs.forEach(inp => {
              inp.setAttribute('inputmode', 'numeric');
              inp.setAttribute('type', 'number'); // 确保软键盘弹出数字
              inp.setAttribute('pattern', '[0-9]*');
              inp.setAttribute('min', '0');
          });

          // 监听 Select 变化
          select.addEventListener('change', function() {
              if (this.value === 'custom') {
                  container.classList.add('sign-custom-open'); // 用于 CSS 钩子（如果需要额外动画）
                  // 自动聚焦天数输入框
                  setTimeout(() => {
                      const daysInput = document.getElementById('ttl-days');
                      if (daysInput) daysInput.focus();
                  }, 50);
              } else {
                  container.classList.remove('sign-custom-open');
              }
          });
      }; 

      // ======================================================================
      // ✅ 只把“初始化/绑定 DOM/恢复主题”等可能报错的逻辑放到 init 里
      // ======================================================================
      (function initDashboard() {
          try {
              console.log('Starting initDashboard...');
              const daemonJsonObj = { "registry-mirrors": ["https://" + window.CURRENT_DOMAIN] };
              daemonJsonStr = JSON.stringify(daemonJsonObj, null, 2);
              const daemonEl = document.getElementById('daemon-json-content');
              if (daemonEl) daemonEl.textContent = daemonJsonStr;

              // Theme Init
              try { if (localStorage.getItem('theme') === 'dark') window.toggleTheme(); } catch(e) {}
              
              // I18N Init
              try { 
                  const savedLang = localStorage.getItem('lang') || 'zh';
                  window.setLanguage(savedLang);
              } catch(e) {}

              try {
                  document.querySelectorAll('.modal-overlay').forEach(overlay => {
                      overlay.addEventListener('click', function(e) {
                          if (e.target === overlay) overlay.classList.remove('open');
                      });
                  });
              } catch (e) {}
              console.log('initDashboard finished.');
              
              // [新增] 启动日志 UI 增强
              if (window.initLogsUiEnhancements) window.initLogsUiEnhancements();
              
              // [新增] 启动自定义时间 UI 增强
              if (window.initSignTtlUi) window.initSignTtlUi();
          } catch (e) {
              console.error('Dashboard init error:', e);
              window.showToast('❌ Dashboard 初始化失败，请打开控制台查看错误', true);
          }
      })();
    </script>
</body>
</html>
    `;
}
