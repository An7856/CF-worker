import { connect } from 'cloudflare:sockets';

let p = 'dylj';
let fdc = [''];
let uid = '';
let yx = ['ip.sb', 'time.is', 'cdns.doon.eu.org'];
let dns = 'https://sky.rethinkdns.com/1:-Pf_____9_8A_AMAIgE8kMABVDDmKOHTAKg=';
let dyhd = atob('aHR0cHM6Ly9hcGkudjEubWsvc3ViPw==');
let dypz = atob('aHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tL0FDTDRTU1IvQUNMNFNTUi9tYXN0ZXIvQ2xhc2gvY29uZmlnL0FDTDRTU1JfT25saW5lX0Z1bGxfTXVsdGlNb2RlLmluaQ==');
let stp = '';
const KP = 'admin_password', KU = 'user_uuid';
const K_SETTINGS = 'SYSTEM_CONFIG';
let cc = null, ct = 0, CD = 60 * 1000;
const STALE_CD = 60 * 60 * 1000;
const loginAttempts = new Map();
const join = (...a) => a.join('');
const KS = 'user_sessions';
const SESSION_DURATION = 8 * 60 * 60 * 1000;
let ev = true;
let et = false;
let tp = '';
let protocolConfig = { ev, et, tp };
let globalTimeout = 8000;
let cachedUsage = null;
let lastUsageTime = 0;

const FAILED_IP_CACHE = new Map();
const FAILED_TTL = 10 * 60 * 1000;

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
let cachedTrojanHash = null;
let cachedTrojanPwd = null;

function uniqueIPList(list) {
    const seen = new Set();
    return list.filter(item => {
        if (!item) return false;
        const key = item.split('#')[0].trim();
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
    });
}

const UUIDUtils = {
    generateStandardUUID() {
        return crypto.randomUUID();
    },
    generateSessionId() {
        return 'session_' + crypto.randomUUID() + Date.now().toString(36);
    },
    isValidUUID(uuid) {
        return UUID_REGEX.test(uuid);
    }
};

const IPParser = {
    parsePreferredIP(input) {
        if (!input) return null;
        let hostname = input.trim();
        let countryName = '';
        let countryCode = '';
        let comment = '';
        if (hostname.includes('#')) {
            const parts = hostname.split('#');
            hostname = parts[0].trim();
            comment = parts[1].trim();
            if (comment.includes('|')) {
                const countryParts = comment.split('|');
                countryName = countryParts[0].trim();
                countryCode = countryParts[1]?.trim() || '';
            } else {
                countryName = comment;
            }
        }
        const { hostname: cleanHost, port: cleanPort } = this.parseConnectionAddress(hostname);
        if (!cleanHost) return null;
        return {
            hostname: cleanHost,
            port: cleanPort,
            countryName,
            countryCode,
            original: input,
            displayName: this.generateDisplayName(cleanHost, cleanPort, countryName, countryCode)
        };
    },
    parseConnectionAddress(input) {
        const defPort = 443;
        let hostname = input.trim();
        let port = defPort;
        if (hostname.includes('#')) {
            hostname = hostname.split('#')[0].trim();
        }
        if (hostname.includes('.tp')) {
            const match = hostname.match(/\.tp(\d+)\./);
            if (match) port = parseInt(match[1]);
        } else if (hostname.includes('[') && hostname.includes(']:')) {
            const portParts = hostname.split(']:');
            port = parseInt(portParts[1]);
            hostname = portParts[0] + ']';
        } else if (hostname.includes(':')) {
            const portParts = hostname.split(':');
            port = parseInt(portParts.pop());
            hostname = portParts.join(':');
        }
        return { hostname, port };
    },
    generateDisplayName(hostname, port, countryName, countryCode) {
        let displayName = hostname;
        if (countryCode) {
            const flag = getFlagEmoji(countryCode);
            displayName = `${flag} ${countryName} ${hostname}:${port}`;
        } else if (countryName) {
            displayName = `${countryName} ${hostname}:${port}`;
        } else if (port !== 443) {
            displayName = `${hostname}:${port}`;
        }
        return displayName;
    }
};

const ResponseBuilder = {
    html(content, status = 200, extraHeaders = {}) {
        return new Response(content, {
            status,
            headers: {
                'Content-Type': 'text/html;charset=utf-8',
                'Cache-Control': 'no-cache, no-store, must-revalidate',
                ...extraHeaders
            }
        });
    },
    text(content, status = 200, extraHeaders = {}) {
        return new Response(content, {
            status,
            headers: {
                'Content-Type': 'text/plain;charset=utf-8',
                'Cache-Control': 'no-cache, no-store, must-revalidate',
                ...extraHeaders
            }
        });
    },
    json(data, status = 200, extraHeaders = {}) {
        return new Response(JSON.stringify(data), {
            status,
            headers: {
                'Content-Type': 'application/json;charset=utf-8',
                ...extraHeaders
            }
        });
    },
    redirect(url, status = 302, extraHeaders = {}) {
        return new Response(null, {
            status,
            headers: {
                'Location': url,
                ...extraHeaders
            }
        });
    }
};

const ConfigUtils = {
    async loadAllConfig(env) {
        const kv = env.SJ || env.sj;
        const defaultConfig = {
            yx: yx,
            fdc: fdc,
            uid: uid,
            dyhd: dyhd,
            dypz: dypz,
            stp: '',
            ev: true,
            et: false,
            tp: '',
            klp: 'login',
            uuidSet: new Set(uid.split(',').map(s => s.trim().toLowerCase())),
            cfConfig: {},
            proxyConfig: {}
        };

        if (!kv) return defaultConfig;

        try {
            const unifiedConfig = await kv.get(K_SETTINGS, 'json');
            if (unifiedConfig) {
                const configUid = unifiedConfig.uid || uid;
                return {
                    yx: unifiedConfig.yx || yx,
                    fdc: unifiedConfig.fdc || fdc,
                    uid: configUid,
                    dyhd: unifiedConfig.dyhd || dyhd,
                    dypz: unifiedConfig.dypz || dypz,
                    stp: unifiedConfig.stp || '',
                    ev: unifiedConfig.protocolConfig?.ev ?? true,
                    et: unifiedConfig.protocolConfig?.et ?? false,
                    tp: unifiedConfig.protocolConfig?.tp ?? '',
                    cfConfig: unifiedConfig.cfConfig || {},
                    proxyConfig: unifiedConfig.proxyConfig || {},
                    klp: unifiedConfig.klp || 'login',
                    uuidSet: new Set(configUid.split(',').map(s => s.trim().toLowerCase()))
                };
            }
        } catch (e) {}

        return defaultConfig;
    }
};

const ErrorHandler = {
    internalError(message = 'Internal Server Error') {
        return ResponseBuilder.text(message, 500);
    },
    unauthorized(message = 'Unauthorized') {
        return ResponseBuilder.text(message, 401);
    }
};

function generateSessionId() {
    return UUIDUtils.generateSessionId();
}

async function saveSession(env, sessionId, userId) {
    const kv = env.SJ || env.sj;
    if (!kv) return false;
    const sessionData = {
        userId: userId,
        createdAt: Date.now(),
        expiresAt: Date.now() + SESSION_DURATION
    };
    await kv.put(`${KS}:${sessionId}`, JSON.stringify(sessionData), { expirationTtl: 28800 });
    return true;
}

async function validateAndRefreshSession(env, sessionId) {
    const kv = env.SJ || env.sj;
    if (!kv) return { valid: false };
    const sessionData = await kv.get(`${KS}:${sessionId}`);
    if (!sessionData) return { valid: false };
    try {
        const session = JSON.parse(sessionData);
        const now = Date.now();
        if (now > session.expiresAt) {
            await kv.delete(`${KS}:${sessionId}`);
            return { valid: false };
        }
        const timeUntilExpiry = session.expiresAt - now;
        const refreshThreshold = 30 * 60 * 1000;
        if (timeUntilExpiry < refreshThreshold) {
            const newExpiresAt = now + SESSION_DURATION;
            session.expiresAt = newExpiresAt;
            await kv.put(
                `${KS}:${sessionId}`,
                JSON.stringify(session),
                { expirationTtl: 28800 }
            );
            return { valid: true, refreshed: true };
        }
        return { valid: true, refreshed: false };
    } catch {
        return { valid: false };
    }
}

async function deleteSession(env, sessionId) {
    const kv = env.SJ || env.sj;
    if (!kv) return false;
    await kv.delete(`${KS}:${sessionId}`);
    return true;
}

function getSessionCookie(cookieHeader) {
    if (!cookieHeader) return null;
    const cookies = cookieHeader.split(';');
    for (const cookie of cookies) {
        const [name, value] = cookie.trim().split('=');
        if (name === 'cf_worker_session' && value) {
            return value;
        }
    }
    return null;
}

function setSessionCookie(sessionId) {
    const expires = new Date(Date.now() + SESSION_DURATION).toUTCString();
    return `cf_worker_session=${sessionId}; Path=/; HttpOnly; Secure; SameSite=Strict; Expires=${expires}`;
}

function clearSessionCookie() {
    return `cf_worker_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Expires=Thu, 01 Jan 1970 00:00:00 GMT`;
}

async function requireAuth(req, env, handler) {
    const sessionId = getSessionCookie(req.headers.get('Cookie'));
    const sessionResult = await validateAndRefreshSession(env, sessionId);
    if (!sessionResult.valid) {
        return getPoemPage();
    }
    if (sessionResult.refreshed) {
        const response = await handler(req, env);
        response.headers.set('Set-Cookie', setSessionCookie(sessionId));
        return response;
    }
    return handler(req, env);
}

async function handleLogin(req, env) {
    const host = req.headers.get('Host');
    const base = `https://${host}`;
    const url = new URL(req.url);
    const passwordChanged = url.searchParams.get('password_changed') === 'true';
    const clientIp = req.headers.get('CF-Connecting-IP') || 'unknown';
    const now = Date.now();

    if (loginAttempts.size > 1000) loginAttempts.clear();
    const attempt = loginAttempts.get(clientIp) || { count: 0, time: 0 };
    
    if (attempt.count > 5 && (now - attempt.time) < 60000) {
        return ResponseBuilder.text('尝试次数过多，请稍后再试', 429);
    }

    if (req.method === 'POST') {
        const form = await req.formData();
        const password = form.get('password');
        const storedPassword = await gP(env);
        if (password === storedPassword) {
            loginAttempts.delete(clientIp);
            const sessionId = generateSessionId();
            await saveSession(env, sessionId, 'admin');
            const response = await getMainPageContent(host, base, storedPassword, await gU(env), env);
            response.headers.set('Set-Cookie', setSessionCookie(sessionId));
            return response;
        } else {
            loginAttempts.set(clientIp, { count: attempt.count + 1, time: now });
            await new Promise(resolve => setTimeout(resolve, 2000));
            return getLoginPage(host, base, true, false);
        }
    } else {
        return getLoginPage(host, base, false, passwordChanged);
    }
}

async function handleLogout(req, env) {
    const host = req.headers.get('Host');
    const base = `https://${host}`;
    const sessionId = getSessionCookie(req.headers.get('Cookie'));
    if (sessionId) {
        await deleteSession(env, sessionId);
    }
    return ResponseBuilder.redirect(`${base}/`, 302, {
        'Set-Cookie': clearSessionCookie()
    });
}

async function optimizeConfigLoading(env, ctx) {
    const now = Date.now();
    if (cc && (now - ct) < CD) {
        return cc;
    }
    const loadConfigTask = async () => {
        try {
            if (env.CONNECT_TIMEOUT) {
                globalTimeout = parseInt(env.CONNECT_TIMEOUT) || 8000;
            }
            const config = await ConfigUtils.loadAllConfig(env);
            const newConfig = {
                ...config,
                timestamp: now,
                parsedIPs: config.yx.map(ip => IPParser.parsePreferredIP(ip)),
                validFDCs: config.fdc.filter(s => s && s.trim() !== '')
            };
            cc = newConfig;
            ct = now;
            yx = cc.yx;
            fdc = cc.fdc;
            uid = cc.uid;
            dyhd = cc.dyhd;
            dypz = cc.dypz;
            stp = cc.stp;
            ev = cc.ev;
            et = cc.et;
            tp = cc.tp;
            protocolConfig = { ev, et, tp };
            return cc;
        } catch (error) {
            if (cc) return cc;
            return {
                yx: yx,
                fdc: fdc,
                uid: uid,
                dyhd: dyhd,
                dypz: dypz,
                stp: stp,
                ev: ev,
                et: et,
                tp: tp,
                parsedIPs: yx.map(ip => IPParser.parsePreferredIP(ip)),
                validFDCs: fdc.filter(s => s && s.trim() !== ''),
                uuidSet: new Set(uid.split(',').map(s => s.trim().toLowerCase())),
                proxyConfig: {}
            };
        }
    };
    if (cc && (now - ct) < STALE_CD && ctx) {
        ctx.waitUntil(loadConfigTask().catch(console.error));
        return cc;
    }
    return await loadConfigTask();
}

async function gP(env) {
    const kv = env.SJ || env.sj;
    return kv ? await kv.get(KP) : null;
}

async function gU(env) {
    const kv = env.SJ || env.sj;
    return kv ? await kv.get(KU) : null;
}

async function sP(env, pw) {
    const kv = env.SJ || env.sj;
    if (!kv) return false;
    await kv.put(KP, pw);
    return true;
}

async function sU(env, u) {
    const kv = env.SJ || env.sj;
    if (!kv) return false;
    await kv.put(KU, u);
    return true;
}

async function saveConfigToKV(env, cfipArr, fdipArr, u = null, protocolCfg = null, cfCfg = null, proxyCfg = null, klp = null, newDyhd = null, newDypz = null, newStp = null) {
    const kv = env.SJ || env.sj;
    if (!kv) return false;

    const unifiedConfig = {
        yx: cfipArr,
        fdc: fdipArr,
        uid: u || uid,
        dyhd: newDyhd || dyhd,
        dypz: newDypz || dypz,
        stp: newStp || stp,
        protocolConfig: protocolCfg || { ev, et, tp },
        cfConfig: cfCfg || {},
        proxyConfig: proxyCfg || {},
        klp: klp || 'login'
    };

    const ps = [
        kv.put(K_SETTINGS, JSON.stringify(unifiedConfig))
    ];

    if (u) ps.push(kv.put(KU, u));
    if (klp) ps.push(kv.put(KP, await gP(env)));

    await Promise.all(ps);

    const uuidSet = new Set((u || uid).split(',').map(s => s.trim().toLowerCase()));
    cc = {
        ...unifiedConfig,
        timestamp: Date.now(),
        ev: unifiedConfig.protocolConfig.ev,
        et: unifiedConfig.protocolConfig.et,
        tp: unifiedConfig.protocolConfig.tp,
        parsedIPs: cfipArr.map(ip => IPParser.parsePreferredIP(ip)),
        validFDCs: fdipArr.filter(s => s && s.trim() !== ''),
        uuidSet: uuidSet
    };
    ct = Date.now();
    return true;
}

async function connectWithTimeout(host, port, timeoutMs) {
    const socket = connect({
        hostname: host,
        port: port,
        allowHalfOpen: true,
        secureTransport: 'off',
        noDelay: true
    });

    let timer = null;
    const timeoutPromise = new Promise((_, reject) => {
        timer = setTimeout(() => {
            try { socket.close(); } catch(e) {}
            reject(new Error(`Connect timeout (${timeoutMs}ms)`));
        }, timeoutMs);
    });

    try {
        await Promise.race([socket.opened, timeoutPromise]);
        return socket;
    } catch (error) {
        try { socket.close(); } catch(e) {}
        throw error;
    } finally {
        if (timer) clearTimeout(timer);
    }
}

async function universalConnectWithFailover() {
    let valid = cc?.validFDCs || fdc.filter(s => s && s.trim() !== '');
    if (valid.length === 0) valid = ['www.visa.com.sg'];

    const PRIMARY_TIMEOUT = 3000;
    const BACKUP_TIMEOUT = 2000;

    const primaryIP = valid[0];
    const backupIPs = valid.slice(1);

    const now = Date.now();
    for (const [ip, time] of FAILED_IP_CACHE) {
        if (now - time > FAILED_TTL) FAILED_IP_CACHE.delete(ip);
    }

    if (!FAILED_IP_CACHE.has(primaryIP)) {
        try {
            const { hostname, port } = IPParser.parseConnectionAddress(primaryIP);
            const socket = await connectWithTimeout(hostname, port, PRIMARY_TIMEOUT);
            return { socket, server: { hostname, port, original: primaryIP } };
        } catch (e) {
            FAILED_IP_CACHE.set(primaryIP, Date.now());
        }
    }

    let candidates = backupIPs.filter(ip => !FAILED_IP_CACHE.has(ip));
    if (candidates.length === 0) {
        if (backupIPs.length > 0) {
            FAILED_IP_CACHE.clear();
            FAILED_IP_CACHE.set(primaryIP, Date.now());
            candidates = backupIPs;
        } else {
             throw new Error(`主IP连接失败，且无可用备选IP`);
        }
    }

    for (let i = candidates.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [candidates[i], candidates[j]] = [candidates[j], candidates[i]];
    }

    let lastError = null;
    for (const s of candidates) {
        const { hostname, port } = IPParser.parseConnectionAddress(s);
        try {
            const socket = await connectWithTimeout(hostname, port, BACKUP_TIMEOUT);
            return { socket, server: { hostname, port, original: s } };
        } catch (err) {
            FAILED_IP_CACHE.set(s, Date.now());
            lastError = err;
        }
    }
    throw new Error(`所有节点连接失败 (主节点+备选节点)，最后错误: ${lastError?.message}`);
}

function safeCloseWebSocket(socket) {
    try {
        if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) {
            socket.close();
        }
    } catch (e) { }
}

function safeCloseSocket(socket) {
    try {
        if (socket) {
            socket.close();
        }
    } catch (e) { }
}

const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;
async function sha224Hash(text) {
    const encoder = new TextEncoder();
    const data = encoder.encode(text);
    const K = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ];
    let H = [
        0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
        0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
    ];
    const msgLen = data.length;
    const bitLen = msgLen * 8;
    const paddedLen = Math.ceil((msgLen + 9) / 64) * 64;
    const padded = new Uint8Array(paddedLen);
    padded.set(data);
    padded[msgLen] = 0x80;

    const view = new DataView(padded.buffer);
    view.setUint32(paddedLen - 4, bitLen, false);
    for (let chunk = 0; chunk < paddedLen; chunk += 64) {
        const W = new Uint32Array(64);
        for (let i = 0; i < 16; i++) {
            W[i] = view.getUint32(chunk + i * 4, false);
        }

        for (let i = 16; i < 64; i++) {
            const s0 = rightRotate(W[i - 15], 7) ^ rightRotate(W[i - 15], 18) ^ (W[i - 15] >>> 3);
            const s1 = rightRotate(W[i - 2], 17) ^ rightRotate(W[i - 2], 19) ^ (W[i - 2] >>> 10);
            W[i] = (W[i - 16] + s0 + W[i - 7] + s1) >>> 0;
        }

        let [a, b, c, d, e, f, g, h] = H;
        for (let i = 0; i < 64; i++) {
            const S1 = rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25);
            const ch = (e & f) ^ (~e & g);
            const temp1 = (h + S1 + ch + K[i] + W[i]) >>> 0;
            const S0 = rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22);
            const maj = (a & b) ^ (a & c) ^ (b & c);
            const temp2 = (S0 + maj) >>> 0;

            h = g;
            g = f;
            f = e;
            e = (d + temp1) >>> 0;
            d = c;
            c = b;
            b = a;
            a = (temp1 + temp2) >>> 0;
        }

        H[0] = (H[0] + a) >>> 0;
        H[1] = (H[1] + b) >>> 0;
        H[2] = (H[2] + c) >>> 0;
        H[3] = (H[3] + d) >>> 0;
        H[4] = (H[4] + e) >>> 0;
        H[5] = (H[5] + f) >>> 0;
        H[6] = (H[6] + g) >>> 0;
        H[7] = (H[7] + h) >>> 0;
    }

    const result = [];
    for (let i = 0; i < 7; i++) {
        result.push(
            ((H[i] >>> 24) & 0xff).toString(16).padStart(2, '0'),
            ((H[i] >>> 16) & 0xff).toString(16).padStart(2, '0'),
            ((H[i] >>> 8) & 0xff).toString(16).padStart(2, '0'),
            (H[i] & 0xff).toString(16).padStart(2, '0')
        );
    }

    return result.join('');
}

function rightRotate(value, amount) {
    return (value >>> amount) | (value << (32 - amount));
}

async function parseTrojanHeader(buffer, ut) {
    const passwordToHash = tp || ut;
    if (cachedTrojanPwd !== passwordToHash || !cachedTrojanHash) {
        cachedTrojanHash = await sha224Hash(passwordToHash);
        cachedTrojanPwd = passwordToHash;
    }
    const sha224Password = cachedTrojanHash;

    if (buffer.byteLength < 58) {
        return {
            hasError: true,
            message: "invalid trojan data - too short"
        };
    }
    let crLfIndex = 56;
    if (new Uint8Array(buffer)[crLfIndex] !== 0x0d ||
        new Uint8Array(buffer)[crLfIndex + 1] !== 0x0a) {
        return {
            hasError: true,
            message: "invalid trojan header format (missing CR LF)"
        };
    }
    const password = new TextDecoder().decode(buffer.subarray(0, crLfIndex));
    if (password !== sha224Password) {
        return {
            hasError: true,
            message: "invalid trojan password"
        };
    }

    const socks5DataBuffer = buffer.subarray(crLfIndex + 2);
    if (socks5DataBuffer.byteLength < 6) {
        return {
            hasError: true,
            message: "invalid SOCKS5 request data"
        };
    }

    const view = new DataView(socks5DataBuffer.buffer, socks5DataBuffer.byteOffset, socks5DataBuffer.byteLength);
    const cmd = view.getUint8(0);
    if (cmd !== 1) {
        return {
            hasError: true,
            message: "unsupported command, only TCP (CONNECT) is allowed"
        };
    }

    const atype = view.getUint8(1);
    let addressLength = 0;
    let addressIndex = 2;
    let address = "";
    switch (atype) {
        case 1:
            addressLength = 4;
            address = new Uint8Array(
                socks5DataBuffer.subarray(addressIndex, addressIndex + addressLength)
            ).join(".");
            break;
        case 3:
            addressLength = new Uint8Array(
                socks5DataBuffer.subarray(addressIndex, addressIndex + 1)
            )[0];
            addressIndex += 1;
            address = new TextDecoder().decode(
                socks5DataBuffer.subarray(addressIndex, addressIndex + addressLength)
            );
            break;
        case 4:
            addressLength = 16;
            const dataView = new DataView(socks5DataBuffer.buffer, socks5DataBuffer.byteOffset + addressIndex, addressLength);
            const ipv6 = [];
            for (let i = 0; i < 8; i++) {
                ipv6.push(dataView.getUint16(i * 2).toString(16));
            }
            address = ipv6.join(":");
            break;
        default:
            return {
                hasError: true,
                message: `invalid addressType is ${atype}`
            };
    }

    if (!address) {
        return {
            hasError: true,
            message: `address is empty, addressType is ${atype}`
        };
    }

    const portIndex = addressIndex + addressLength;
    const portBuffer = socks5DataBuffer.subarray(portIndex, portIndex + 2);
    const portRemote = new DataView(portBuffer.buffer, portBuffer.byteOffset, 2).getUint16(0);

    return {
        hasError: false,
        addressRemote: address,
        addressType: atype,
        port: portRemote,
        hostname: address,
        rawClientData: socks5DataBuffer.subarray(portIndex + 4)
    };
}

async function VLOverWSHandler(req, config, proxyCtx) {
    const webSocketPair = new WebSocketPair();
    const [client, ws] = Object.values(webSocketPair);
    ws.accept();
    
    let remote = { value: null };
    let udpWrite = null;
    let isDns = false;
    let protocolType = null;
    let processed = false;
    let remoteWriter = null;

    const cleanup = () => {
        if (remote.value) {
            safeCloseSocket(remote.value);
            remote.value = null;
        }
        if (remoteWriter) {
            try { remoteWriter.releaseLock(); } catch(e) {}
            remoteWriter = null;
        }
        if (udpWrite && typeof udpWrite.close === 'function') {
            try { udpWrite.close(); } catch(e) {}
            udpWrite = null;
        }
        safeCloseWebSocket(ws);
    };

    ws.addEventListener('close', () => {
        cleanup();
    });

    ws.addEventListener('error', () => {
        cleanup();
    });

    const early = req.headers.get('sec-websocket-protocol') || '';
    const stream = makeReadableWebSocketStream(ws, early);
    
    stream.pipeTo(new WritableStream({
        async write(chunk, ctrl) {
            try {
                if (chunk instanceof ArrayBuffer) {
                    chunk = new Uint8Array(chunk);
                }

                if (processed) {
                    if (isDns && udpWrite) {
                        return udpWrite.write(chunk);
                    }
                    if (remote.value) {
                        if (!remoteWriter) {
                            remoteWriter = remote.value.writable.getWriter();
                        }
                        await remoteWriter.write(chunk);
                        return;
                    }
                    return;
                }

                let protocolDetected = false;

                if (et && !protocolDetected) {
                    const tjResult = await parseTrojanHeader(chunk, uid);
                    if (!tjResult.hasError) {
                        protocolType = 'trojan';
                        protocolDetected = true;
                        const { addressRemote, port, rawClientData } = tjResult;
                        await handleTCP(remote, addressRemote, port, rawClientData, ws, null, proxyCtx);
                        if (remote.value) {
                            remoteWriter = remote.value.writable.getWriter();
                        }
                        processed = true;
                        return;
                    }
                }

                if (ev && !protocolDetected) {
                    const vlessResult = await processVHeader(chunk, config.uuidSet);
                    if (!vlessResult.hasError) {
                        protocolType = 'vless';
                        protocolDetected = true;
                        const { portRemote, addressRemote, rawDataIndex, VLVersion, isUDP } = vlessResult;
                        if (isUDP) {
                            if (portRemote === 53) {
                                isDns = true;
                            } else {
                                return;
                            }
                        }
                        const respHeader = new Uint8Array([VLVersion[0], 0]);
                        const rawData = chunk.subarray(rawDataIndex);
                        
                        if (isDns) {
                            const writerObj = await handleUDPO(ws, respHeader);
                            udpWrite = writerObj;
                            udpWrite.write(rawData);
                            processed = true;
                            return;
                        }
                        
                        await handleTCP(remote, addressRemote, portRemote, rawData, ws, respHeader, proxyCtx);
                        if (remote.value) {
                            remoteWriter = remote.value.writable.getWriter();
                        }
                        processed = true;
                        return;
                    }
                }

                if (!protocolDetected) {
                    throw new Error('Invalid protocol');
                }

            } catch (e) {
                cleanup();
                ctrl.error(e);
            }
        },
        close() {
            cleanup();
        },
        abort(r) {
            cleanup();
        },
    }))
    .catch((e) => {
        cleanup();
    })
    .finally(() => {
        cleanup();
    });

    return new Response(null, {
        status: 101,
        webSocket: client,
    });
}

async function handleTCP(remote, addr, pt, raw, ws, vh, proxyCtx) {
    const tcpSocket = await createConnection(addr, pt, proxyCtx);
    remote.value = tcpSocket;

    if (vh) {
        if (ws.readyState === WS_READY_STATE_OPEN) {
            try {
                ws.send(vh);
            } catch (e) { }
        }
    }

    const writer = tcpSocket.writable.getWriter();
    try {
        await writer.write(raw);
    } finally {
        writer.releaseLock();
    }

    tcpSocket.readable.pipeTo(new WritableStream({
        write(chunk) {
            if (ws.readyState === WS_READY_STATE_OPEN) {
                try {
                    ws.send(chunk);
                } catch (e) { }
            }
        },
        close() {
            safeCloseWebSocket(ws);
        },
        abort() {
            safeCloseWebSocket(ws);
        }
    })).catch(() => {
        safeCloseWebSocket(ws);
    });

    return;
}

async function createConnection(host, port, proxyCtx, addressType = 3) {
    const { enableType, global, parsedAddress } = proxyCtx;
    const tryDirect = async () => {
        try {
            const s = connect({ hostname: host, port: port, connectTimeout: globalTimeout, allowHalfOpen: true, noDelay: true });
            await s.opened;
            return s;
        } catch (e) {
            return null;
        }
    };
    const tryProxy = async () => {
        if (!enableType || !parsedAddress) return null;
        try {
            if (enableType === 'socks5') return await socks5Connect(host, port, parsedAddress, addressType);
            if (enableType === 'http') return await httpConnect(host, port, parsedAddress);
        } catch (e) {
            return null;
        }
        return null;
    };
    const tryReverse = async () => {
        try {
            const { socket } = await universalConnectWithFailover();
            return socket;
        } catch (e) {
            return null;
        }
    };
    let sock = null;
    if (global) {
        sock = await tryProxy();
        if (!sock) sock = await tryDirect();
    } else {
        sock = await tryDirect();
        if (!sock) sock = await tryProxy();
    }
    if (!sock) {
        sock = await tryReverse();
    }
    if (!sock) {
        throw new Error(`连接失败: 直连/代理/反代三层均不可用. 目标: ${host}:${port}`);
    }
    return sock;
}

async function socks5Connect(addressRemote, portRemote, proxyAddress, addressType = 3) {
    const { username, password, hostname, port } = proxyAddress;
    const socket = connect({
        hostname,
        port,
        connectTimeout: globalTimeout,
        allowHalfOpen: true,
        noDelay: true
    });
    const writer = socket.writable.getWriter();
    const reader = socket.readable.getReader();
    const encoder = new TextEncoder();

    try {
        const authMethods = username && password ? new Uint8Array([5, 2, 0, 2]) : new Uint8Array([5, 1, 0]);
        await writer.write(authMethods);

        let res = await reader.read();
        if (res.done || res.value.byteLength < 2) throw new Error('SOCKS5 handshake failed');
        
        const method = res.value[1];

        if (method === 0x02) {
            if (!username || !password) throw new Error('SOCKS5 auth required');
            const userBytes = encoder.encode(username);
            const passBytes = encoder.encode(password);
            const authBuf = new Uint8Array(3 + userBytes.length + passBytes.length);
            authBuf.set([1, userBytes.length], 0);
            authBuf.set(userBytes, 2);
            authBuf.set([passBytes.length], 2 + userBytes.length);
            authBuf.set(passBytes, 3 + userBytes.length);
            
            await writer.write(authBuf);
            res = await reader.read();
            if (res.done || res.value[1] !== 0x00) throw new Error('SOCKS5 auth failed');
        } else if (method !== 0x00) {
            throw new Error('SOCKS5 auth method unsupported');
        }

        const hostBytes = encoder.encode(addressRemote);
        const reqBuf = new Uint8Array(5 + hostBytes.length + 2);
        reqBuf.set([5, 1, 0, 3, hostBytes.length], 0);
        reqBuf.set(hostBytes, 5);
        reqBuf.set([portRemote >> 8, portRemote & 0xff], 5 + hostBytes.length);
        
        await writer.write(reqBuf);

        res = await reader.read();
        if (res.done || res.value.byteLength < 3) throw new Error('SOCKS5 connect failed');
        if (res.value[1] !== 0x00) throw new Error('SOCKS5 connect error: ' + res.value[1]);

        writer.releaseLock();
        reader.releaseLock();

        return socket;
    } catch (e) {
        try { writer.releaseLock(); reader.releaseLock(); socket.close(); } catch (err) {}
        throw e;
    }
}

async function httpConnect(addressRemote, portRemote, proxyAddress) {
    const { username, password, hostname, port } = proxyAddress;
    const socket = await connect({
        hostname,
        port,
        connectTimeout: globalTimeout,
        allowHalfOpen: true,
        noDelay: true
    });
    const writer = socket.writable.getWriter();
    const reader = socket.readable.getReader();
    const encoder = new TextEncoder();
    try {
        const authHeader = username && password
            ? `Proxy-Authorization: Basic ${btoa(`${username}:${password}`)}\r\n`
            : '';
        const connectRequest =
            `CONNECT ${addressRemote}:${portRemote} HTTP/1.1\r\n` +
            `Host: ${addressRemote}:${portRemote}\r\n` +
            authHeader +
            `User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36\r\n` +
            `Connection: Keep-Alive\r\n\r\n`;
        await writer.write(encoder.encode(connectRequest));
        let responseBuffer = new Uint8Array(0);
        let headerFound = false;
        while (!headerFound) {
            const { value, done } = await reader.read();
            if (done) throw new Error('HTTP 代理连接中断');
            const newBuffer = new Uint8Array(responseBuffer.length + value.length);
            newBuffer.set(responseBuffer);
            newBuffer.set(value, responseBuffer.length);
            responseBuffer = newBuffer;
            const respText = new TextDecoder().decode(responseBuffer);
            const doubleCRLF = respText.indexOf('\r\n\r\n');
            const doubleLF = respText.indexOf('\n\n');
            let endPos = -1;
            let sepLen = 0;
            if (doubleCRLF !== -1) {
                endPos = doubleCRLF;
                sepLen = 4;
            } else if (doubleLF !== -1) {
                endPos = doubleLF;
                sepLen = 2;
            }
            if (endPos !== -1) {
                const headers = respText.substring(0, endPos);
                if (!/200 Connection Established|200 OK/i.test(headers)) {
                    throw new Error(`HTTP 代理响应错误: ${headers.split('\n')[0]}`);
                }
                const remainingData = responseBuffer.subarray(endPos + sepLen);
                writer.releaseLock();
                reader.releaseLock();
                if (remainingData.length > 0) {
                    const ts = new TransformStream();
                    const tsWriter = ts.writable.getWriter();
                    tsWriter.write(remainingData);
                    socket.readable.pipeTo(ts.writable, { preventClose: true });
                    return {
                        readable: ts.readable,
                        writable: socket.writable,
                        close: () => socket.close()
                    };
                }
                return socket;
            }
        }
    } catch (err) {
        try { writer.releaseLock(); reader.releaseLock(); socket.close(); } catch(e) {}
        throw err;
    }
}

function makeReadableWebSocketStream(ws, early) {
    let cancel = false;
    const stream = new ReadableStream({
        start(ctrl) {
            ws.addEventListener('message', (e) => {
                if (cancel) return;
                ctrl.enqueue(e.data);
            });
            ws.addEventListener('close', () => {
                safeCloseWebSocket(ws);
                if (cancel) return;
                ctrl.close();
            });
            ws.addEventListener('error', (e) => {
                ctrl.error(e);
            });

            if (early) {
                const { earlyData, error } = base64ToArrayBuffer(early);
                if (error) {
                    ctrl.error(error);
                } else if (earlyData) {
                    ctrl.enqueue(earlyData);
                }
            }
        },

        pull(ctrl) { },
        cancel() {
            cancel = true;
            safeCloseWebSocket(ws);
        }
    });
    return stream;
}

async function processVHeader(VLBuffer, uuidSet) {
    if (VLBuffer.byteLength < 24) {
        return {
            hasError: true,
            message: 'invalid data',
        };
    }
    
    const view = VLBuffer; 
    const version = view.subarray(0, 1);
    const slice = view.subarray(1, 17);
    const sliceStr = stringify(slice);
    
    let isValid = false;
    let isUDP = false;
    
    isValid = uuidSet ? uuidSet.has(sliceStr) : (sliceStr === uid.toLowerCase());

    if (!isValid) {
        return {
            hasError: true,
            message: 'invalid user',
        };
    }
    
    const optLen = view[17];
    const cmd = view[18 + optLen];
    
    if (cmd === 2) {
        isUDP = true;
    } else if (cmd !== 1) {
        return {
            hasError: true,
            message: `command ${cmd} is not support, command 01-tcp,02-udp,03-mux`,
        };
    }
    
    const portIndex = 18 + optLen + 1;
    const portRemote = (view[portIndex] << 8) | view[portIndex + 1];
    
    let addrIndex = portIndex + 2;
    const addrType = view[addrIndex];
    let addrLen = 0;
    let addrValIndex = addrIndex + 1;
    let addrVal = '';
    
    switch (addrType) {
        case 1:
            addrLen = 4;
            addrVal = view.subarray(addrValIndex, addrValIndex + addrLen).join('.');
            break;
        case 2:
            addrLen = view[addrValIndex];
            addrValIndex += 1;
            addrVal = new TextDecoder().decode(view.subarray(addrValIndex, addrValIndex + addrLen));
            break;
        case 3:
            addrLen = 16;
            const dv = new DataView(VLBuffer.buffer, VLBuffer.byteOffset + addrValIndex, addrLen);
            const ipv6 = [];
            for (let i = 0; i < 8; i++) {
                ipv6.push(dv.getUint16(i * 2).toString(16));
            }
            addrVal = ipv6.join(':');
            break;
        default:
            return {
                hasError: true,
                message: `invalid addressType is ${addrType}`,
            };
    }
    if (!addrVal) {
        return {
            hasError: true,
            message: `addressValue is empty, addressType is ${addrType}`,
        };
    }
    return {
        hasError: false,
        addressRemote: addrVal,
        addressType: addrType,
        portRemote: portRemote,
        rawDataIndex: addrValIndex + addrLen,
        VLVersion: version,
        isUDP: isUDP,
    };
}

const byteToHex = [];
for (let i = 0; i < 256; ++i) {
    byteToHex.push((i + 256).toString(16).slice(1));
}
function unsafeStringify(arr, offset = 0) {
    return (byteToHex[arr[offset + 0]] + byteToHex[arr[offset + 1]] + byteToHex[arr[offset + 2]] + byteToHex[arr[offset + 3]] + "-" + byteToHex[arr[offset + 4]] + byteToHex[arr[offset + 5]] + "-" + byteToHex[arr[offset + 6]] + byteToHex[arr[offset + 7]] + "-" + byteToHex[arr[offset + 8]] + byteToHex[arr[offset + 9]] + "-" + byteToHex[arr[offset + 10]] + byteToHex[arr[offset + 11]] + byteToHex[arr[offset + 12]] + byteToHex[arr[offset + 13]] + byteToHex[arr[offset + 14]] + byteToHex[arr[offset + 15]]).toLowerCase();
}
function stringify(arr, offset = 0) {
    const id = unsafeStringify(arr, offset);
    if (!UUIDUtils.isValidUUID(id)) {
        throw TypeError("Stringified id is invalid");
    }
    return id;
}

async function handleUDPO(ws, vh) {
    if (vh) {
        if (ws.readyState === WS_READY_STATE_OPEN) {
            try {
                ws.send(vh);
            } catch (e) { }
        }
    }

    const ts = new TransformStream({
        transform(chunk, ctrl) {
            for (let i = 0; i < chunk.byteLength;) {
                let view = chunk;
                if(chunk instanceof ArrayBuffer) view = new Uint8Array(chunk);
                
                const lenBuf = view.subarray(i, i + 2);
                const len = new DataView(lenBuf.buffer, lenBuf.byteOffset, lenBuf.byteLength).getUint16(0);
                const data = new Uint8Array(view.subarray(i + 2, i + 2 + len));
                i = i + 2 + len;
                ctrl.enqueue({ lenBuf, data });
            }
        },
    });
    ts.readable.pipeTo(new WritableStream({
        async write({ lenBuf, data }) {
            const res = await fetch(dns, {
                method: 'POST',
                headers: { 'content-type': 'application/dns-message' },
                body: data,
            });

            const ans = await res.arrayBuffer();
            const sz = ans.byteLength;
            const szBuf = new Uint8Array([(sz >> 8) & 0xff, sz & 0xff]);

            const responseData = new Uint8Array(szBuf.byteLength + ans.byteLength);
            responseData.set(szBuf, 0);

            responseData.set(new Uint8Array(ans), szBuf.byteLength);

            if (ws.readyState === WS_READY_STATE_OPEN) {
                try {
                    ws.send(responseData);
                } catch (e) { }
            }
        }
    })).catch(() => { });
    const w = ts.writable.getWriter();
    return {
        write(chunk) {
            w.write(chunk);
        },
        close() {
            try { w.close(); } catch(e) {}
        }
    };
}

function getFlagEmoji(c) {
    if (!c || c.length !== 2) return '';
    const cp = c.toUpperCase().split('').map(char => 127397 + char.charCodeAt());
    return String.fromCodePoint(...cp);
}

function genConfig(u, url) {
    if (!u) return '';
    const wp = '/?ed=2560';
    const ep = encodeURIComponent(wp);
    const links = [];

    if (ev) {
        const hd = join('v', 'l', 'e', 's', 's');
        const vlessLinks = yx.map(item => {
            const ipData = IPParser.parsePreferredIP(item);
            if (!ipData) return null;
            const { hostname, port, displayName } = ipData;
            return `${hd}://${u}@${hostname}:${port}?encryption=none&security=tls&sni=${url}&fp=chrome&type=ws&host=${url}&path=${ep}&tfo=1#${encodeURIComponent('Vless-' + displayName)}`;
        }).filter(Boolean);
        links.push(...vlessLinks);
    }

    if (et) {
        const password = tp || u;
        const trojanLinks = yx.map(item => {
            const ipData = IPParser.parsePreferredIP(item);
            if (!ipData) return null;
            const { hostname, port, displayName } = ipData;
            const hd = join('t', 'r', 'o', 'j', 'a', 'n');
            return `${hd}://${password}@${hostname}:${port}?security=tls&sni=${url}&fp=chrome&type=ws&host=${url}&path=${ep}&tfo=1#${encodeURIComponent('Trojan-' + displayName)}`;
        }).filter(Boolean);
        links.push(...trojanLinks);
    }

    if (links.length === 0) {
        const hd = join('v', 'l', 'e', 's', 's');
        const vlessLinks = yx.map(item => {
            const ipData = IPParser.parsePreferredIP(item);
            if (!ipData) return null;
            const { hostname, port, displayName } = ipData;
            return `${hd}://${u}@${hostname}:${port}?encryption=none&security=tls&sni=${url}&fp=chrome&type=ws&host=${url}&path=${ep}&tfo=1#${encodeURIComponent(displayName)}`;
        }).filter(Boolean);
        links.push(...vlessLinks);
    }

    const finalConfig = links.join('\n')
        .replace(new RegExp(join('v', 'l', 'e', 's', 's'), 'g'), 'vless')
        .replace(new RegExp(join('t', 'r', 'o', 'j', 'a', 'n'), 'g'), 'trojan');
    return finalConfig;
}

async function genSurgeConfig(u, url) {
    if (!u) return '';
    const wp = '/?ed=2560';
    const nodes = [];
    const nodeNames = [];

    if (et) {
        const password = tp || u;
        yx.forEach(item => {
            const ipData = IPParser.parsePreferredIP(item);
            if (!ipData) return;
            const { hostname, port, displayName } = ipData;
            const nodeConfig = `${displayName} = trojan, ${hostname}, ${port}, password=${password}, sni=${url}, skip-cert-verify=true, ws=true, ws-path=${wp}, ws-headers=Host:"${url}", tfo=true`;
            nodes.push(nodeConfig);
            nodeNames.push(displayName);
        });
    }

    if (nodes.length === 0) return '骚年，不用怀疑，你未启用Trojan协议，请到设置里启用Trojan再使用喔！！！';

    if (stp) {
        try {
            const response = await fetch(stp);
            if (response.ok) {
                let templateContent = await response.text();
                templateContent = templateContent.replace(/\{nodes\}/g, nodes.join('\n'));
                templateContent = templateContent.replace(/\{names\}/g, nodeNames.join(', '));
                return templateContent;
            }
        } catch (e) {}
    }

    return `#!MANAGED-CONFIG https://${url}/${u}?format=surge interval=86400 strict=true

[General]
skip-proxy = 192.168.0.0/24, 10.0.0.0/8, 172.16.0.0/12, 127.0.0.1, localhost, *.local
exclude-simple-hostnames = true
dns-server = 223.5.5.5, 114.114.114.114
wifi-assist = true
ipv6 = false

[Proxy]
${nodes.join('\n')}

[Proxy Group]
🌎 节点选择 = select, ${nodeNames.join(', ')}

[Rule]
RULE-SET,https://github.com/Blankwonder/surge-list/raw/master/blocked.list,🌎 节点选择
RULE-SET,https://github.com/Blankwonder/surge-list/raw/master/cn.list,DIRECT
RULE-SET,SYSTEM,🌎 节点选择
RULE-SET,LAN,DIRECT
GEOIP,CN,DIRECT
FINAL, 🌎 节点选择,dns-failed`;
}

async function getCloudflareUsage(env) {
    const now = Date.now();
    if (cachedUsage && (now - lastUsageTime < 300000)) {
        return cachedUsage;
    }
    
    if (!cc?.cfConfig) return { success: false, pages: 0, workers: 0, total: 0 };
    const { accountId, apiToken } = cc.cfConfig;
    if (!apiToken) {
        return { success: false, pages: 0, workers: 0, total: 0 };
    }

    const API = "https://api.cloudflare.com/client/v4";
    const sum = (a) => a?.reduce((t, i) => t + (i?.sum?.requests || 0), 0) || 0;
    
    const headers = { "Authorization": `Bearer ${apiToken}`, "Content-Type": "application/json" };

    try {
        let AccountID = accountId;
        if (!AccountID) {
            try {
                const r = await fetch(`${API}/accounts`, {
                    method: "GET",
                    headers: headers
                });
                if (r.ok) {
                    const d = await r.json();
                    if (d?.result?.length > 0) {
                        AccountID = d.result[0].id;
                    }
                }
            } catch (e) {
                console.error("Failed to fetch account ID:", e);
            }
        }

        if (!AccountID) return { success: false, pages: 0, workers: 0, total: 0 };

        const dateNow = new Date();
        dateNow.setUTCHours(0, 0, 0, 0);
        
        const res = await fetch(`${API}/graphql`, {
            method: "POST",
            headers: headers,
            body: JSON.stringify({
                query: `query getBillingMetrics($AccountID: String!, $filter: AccountWorkersInvocationsAdaptiveFilter_InputObject) {
                    viewer { accounts(filter: {accountTag: $AccountID}) {
                        pagesFunctionsInvocationsAdaptiveGroups(limit: 1000, filter: $filter) { sum { requests } }
                        workersInvocationsAdaptive(limit: 10000, filter: $filter) { sum { requests } }
                    } }
                }`,
                variables: { 
                    AccountID, 
                    filter: { 
                        datetime_geq: dateNow.toISOString(), 
                        datetime_leq: new Date().toISOString() 
                    } 
                }
            })
        });

        if (!res.ok) return { success: false, pages: 0, workers: 0, total: 0 };
        const result = await res.json();
        if (result.errors?.length) return { success: false, pages: 0, workers: 0, total: 0 };

        const acc = result?.data?.viewer?.accounts?.[0];
        if (!acc) return { success: false, pages: 0, workers: 0, total: 0 };

        const pages = sum(acc.pagesFunctionsInvocationsAdaptiveGroups);
        const workers = sum(acc.workersInvocationsAdaptive);
        const total = pages + workers;

        const usageResult = { success: true, pages, workers, total };
        cachedUsage = usageResult;
        lastUsageTime = now;
        return usageResult;
    } catch (error) {
        console.error("Usage API Error:", error);
        return { success: false, pages: 0, workers: 0, total: 0 };
    }
}

async function getRequestProxyConfig(request, config) {
    const url = new URL(request.url);
    const { pathname, searchParams } = url;

    let proxyCtx = {
        enableType: config.proxyConfig?.enabled ? config.proxyConfig.type : null,
        global: config.proxyConfig?.global || false,
        account: config.proxyConfig?.account || '',
        whitelist: [],
        parsedAddress: {}
    };

    let tempAccount = searchParams.get('socks5') || searchParams.get('http') || proxyCtx.account;
    if (searchParams.has('globalproxy')) proxyCtx.global = true;

    let socksMatch;
    if ((socksMatch = pathname.match(/\/(socks5?|http):\/?\/?(.+)/i))) {
        proxyCtx.enableType = socksMatch[1].toLowerCase() === 'http' ? 'http' : 'socks5';
        tempAccount = socksMatch[2].split('#')[0];
        proxyCtx.global = true;

        if (tempAccount.includes('@')) {
            const atIndex = tempAccount.lastIndexOf('@');
            let userPassword = tempAccount.substring(0, atIndex).replaceAll('%3D', '=');
            if (/^(?:[A-Z0-9+/]{4})*(?:[A-Z0-9+/]{2}==|[A-Z0-9+/]{3}=)?$/i.test(userPassword) && !userPassword.includes(':')) {
                userPassword = atob(userPassword);
            }
            tempAccount = `${userPassword}@${tempAccount.substring(atIndex + 1)}`;
        }
    } else if ((socksMatch = pathname.match(/\/(g?s5|socks5|g?http)=(.+)/i))) {
        const type = socksMatch[1].toLowerCase();
        tempAccount = socksMatch[2];
        proxyCtx.enableType = type.includes('http') ? 'http' : 'socks5';
        proxyCtx.global = type.startsWith('g') || proxyCtx.global;
    }

    if (tempAccount) {
        try {
            proxyCtx.parsedAddress = await 获取SOCKS5账号(tempAccount);
            if (searchParams.get('http')) proxyCtx.enableType = 'http';
        } catch (err) {
            proxyCtx.enableType = null;
        }
    }
    
    return proxyCtx;
}

async function 获取SOCKS5账号(address) {
    address = address.replace(/^(socks5?|https?|g?s5|g?https?):\/\//i, '');
    if (address.includes('#')) {
        address = address.split('#')[0];
    }
    address = address.trim();
    if (address.includes('@')) {
        const lastAtIndex = address.lastIndexOf('@');
        let userPassword = address.substring(0, lastAtIndex).replaceAll('%3D', '=');
        const base64Regex = /^(?:[A-Z0-9+/]{4})*(?:[A-Z0-9+/]{2}==|[A-Z0-9+/]{3}=)?$/i;
        if (base64Regex.test(userPassword) && !userPassword.includes(':')) {
            try {
                userPassword = atob(userPassword);
            } catch (e) {}
        }
        address = `${userPassword}@${address.substring(lastAtIndex + 1)}`;
    }
    const atIndex = address.lastIndexOf("@");
    const [hostPart, authPart] = atIndex === -1 ? [address, undefined] : [address.substring(atIndex + 1), address.substring(0, atIndex)];
    let username, password;
    if (authPart) {
        const parts = authPart.split(':');
        username = parts[0];
        password = parts.slice(1).join(':');
    }
    let hostname, port;
    if (hostPart.includes("]:")) {
        const parts = hostPart.split("]:");
        hostname = parts[0] + "]";
        port = parseInt(parts[1]);
    } else if (hostPart.startsWith("[")) {
        hostname = hostPart;
        port = 80;
    } else {
        const parts = hostPart.split(":");
        if (parts.length >= 2) {
            const portStr = parts.pop().replace(/[^\d]/g, '');
            port = parseInt(portStr);
            hostname = parts.join(':');
        } else {
            hostname = hostPart;
            port = 80;
        }
    }
    if (isNaN(port)) throw new Error(`端口解析错误: ${address}`);
    if (!hostname) throw new Error('域名/IP为空');
    return { username, password, hostname, port };
}

function base64ToArrayBuffer(b64) {
    if (!b64) {
        return { error: null };
    }
    try {
        b64 = b64.replace(/-/g, '+').replace(/_/g, '/');
        const dec = atob(b64);
        const buf = Uint8Array.from(dec, (c) => c.charCodeAt(0));
        return { earlyData: buf.buffer, error: null };
    } catch (e) {
        return { error: e };
    }
}

function safeBase64(str) {
    try {
        return btoa(str);
    } catch (e) {
        return btoa(encodeURIComponent(str).replace(/%([0-9A-F]{2})/g, (m, p1) => String.fromCharCode('0x' + p1)));
    }
}

function getCommonCSS() {
    return `
    :root {
        --primary: #4f46e5;
        --primary-hover: #4338ca;
        --secondary: #64748b;
        --bg-grad-1: hsla(253,16%,7%,1);
        --bg-grad-2: hsla(225,39%,30%,1);
        --bg-grad-3: hsla(339,49%,30%,1);
        --surface: rgba(255, 255, 255, 0.9);
        --glass: blur(12px) saturate(180%);
        --text: #1e293b;
        --text-light: #64748b;
        --border: rgba(226, 232, 240, 0.8);
        --shadow: 0 10px 30px -10px rgba(0,0,0,0.1);
        --radius: 16px;
    }
    @media (prefers-color-scheme: dark) {
        :root {
            --primary: #818cf8;
            --primary-hover: #6366f1;
            --secondary: #94a3b8;
            --surface: rgba(30, 41, 59, 0.85);
            --text: #f1f5f9;
            --text-light: #94a3b8;
            --border: rgba(51, 65, 85, 0.8);
            --shadow: 0 10px 30px -10px rgba(0,0,0,0.5);
        }
    }
    * { box-sizing: border-box; }
    body {
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        background-color: #0f172a;
        background-image: 
            radial-gradient(at 0% 0%, var(--bg-grad-1) 0, transparent 50%), 
            radial-gradient(at 50% 0%, var(--bg-grad-2) 0, transparent 50%), 
            radial-gradient(at 100% 0%, var(--bg-grad-3) 0, transparent 50%);
        background-attachment: fixed;
        color: var(--text);
        margin: 0;
        min-height: 100vh;
        width: 100vw;
        overflow-x: hidden;
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        -webkit-font-smoothing: antialiased;
        padding: 1rem;
    }
    .card {
        background: var(--surface);
        backdrop-filter: var(--glass);
        -webkit-backdrop-filter: var(--glass);
        border: 1px solid var(--border);
        border-radius: var(--radius);
        box-shadow: var(--shadow);
        padding: 2.5rem;
        width: 100%;
        max-width: 100%;
        transition: transform 0.2s ease;
    }
    .logo {
        font-size: 3rem;
        margin-bottom: 1rem;
        background: linear-gradient(135deg, #6366f1 0%, #a855f7 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        display: inline-block;
        filter: drop-shadow(0 2px 4px rgba(99, 102, 241, 0.3));
    }
    h1 {
        font-size: 1.75rem;
        font-weight: 700;
        margin: 0 0 0.5rem 0;
        letter-spacing: -0.025em;
    }
    p {
        color: var(--text-light);
        line-height: 1.6;
        margin-bottom: 1.5rem;
    }
    .form-group {
        margin-bottom: 1.25rem;
        text-align: left;
    }
    label {
        display: block;
        font-size: 0.875rem;
        font-weight: 500;
        margin-bottom: 0.5rem;
        color: var(--text);
    }
    input, select, textarea {
        width: 100%;
        max-width: 100%;
        padding: 0.75rem 1rem;
        border-radius: 0.75rem;
        border: 1px solid var(--border);
        background: rgba(255,255,255,0.05);
        color: var(--text);
        font-size: 1rem;
        transition: all 0.2s;
    }
    input:focus, select:focus, textarea:focus {
        outline: none;
        border-color: var(--primary);
        box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.2);
        background: rgba(255,255,255,0.1);
    }
    .btn {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        width: 100%;
        padding: 0.875rem 1.5rem;
        border-radius: 0.75rem;
        background: linear-gradient(135deg, var(--primary) 0%, #a855f7 100%);
        color: white;
        font-weight: 600;
        border: none;
        cursor: pointer;
        transition: all 0.2s;
        text-decoration: none;
        box-shadow: 0 4px 6px -1px rgba(99, 102, 241, 0.4);
        gap: 0.5rem;
        white-space: nowrap;
        font-size: 1rem;
    }
    .btn:hover {
        transform: translateY(-2px);
        box-shadow: 0 10px 15px -3px rgba(99, 102, 241, 0.5);
        filter: brightness(1.1);
    }
    .btn-secondary {
        background: transparent;
        border: 1px solid var(--border);
        color: var(--text);
        box-shadow: none;
        font-size: 1rem;
        padding: 0.875rem 1.5rem;
    }
    .btn-secondary:hover {
        background: rgba(255,255,255,0.05);
        box-shadow: none;
    }
    .error-msg {
        background: rgba(239, 68, 68, 0.1);
        border: 1px solid rgba(239, 68, 68, 0.2);
        color: #ef4444;
        padding: 0.75rem;
        border-radius: 0.5rem;
        font-size: 0.875rem;
        margin-bottom: 1.5rem;
    }
    .success-msg {
        background: rgba(34, 197, 94, 0.1);
        border: 1px solid rgba(34, 197, 94, 0.2);
        color: #22c55e;
        padding: 0.75rem;
        border-radius: 0.5rem;
        font-size: 0.875rem;
        margin-bottom: 1.5rem;
        transition: all 0.5s ease;
    }
    .footer {
        margin-top: 2rem;
        font-size: 0.875rem;
        color: var(--text-light);
        opacity: 0.8;
    }
    .toggle-switch {
        display: flex;
        align-items: center;
        gap: 0.5rem;
        cursor: pointer;
        user-select: none;
    }
    .toggle-switch input {
        appearance: none;
        -webkit-appearance: none;
        width: 1.2rem;
        height: 1.2rem;
        border: 2px solid var(--border);
        background: rgba(255,255,255,0.05);
        cursor: pointer;
        position: relative;
        display: flex;
        align-items: center;
        justify-content: center;
        transition: all 0.2s ease;
        flex-shrink: 0;
    }
    .toggle-switch input:checked {
        background: var(--primary);
        border-color: var(--primary);
    }
    .toggle-switch input[type="checkbox"] { border-radius: 6px; }
    .toggle-switch input[type="radio"] { border-radius: 50%; }
    .toggle-switch input::after {
        content: '';
        position: absolute;
        opacity: 0;
        transition: opacity 0.2s;
    }
    /* Checkmark for checkbox */
    .toggle-switch input[type="checkbox"]::after {
        width: 4px;
        height: 8px;
        border: solid white;
        border-width: 0 2px 2px 0;
        transform: rotate(45deg) translate(-1px, -1px);
    }
    /* Dot for radio */
    .toggle-switch input[type="radio"]::after {
        width: 6px;
        height: 6px;
        background: white;
        border-radius: 50%;
    }
    .toggle-switch input:checked::after { opacity: 1; }
    
    @keyframes pulse-green {
        0% { box-shadow: 0 0 0 0 rgba(34, 197, 94, 0.7); }
        70% { box-shadow: 0 0 0 6px rgba(34, 197, 94, 0); }
        100% { box-shadow: 0 0 0 0 rgba(34, 197, 94, 0); }
    }
    .status-dot {
        height: 10px; width: 10px; background-color: #22c55e;
        border-radius: 50%; display: inline-block;
        margin-right: 6px;
        animation: pulse-green 2s infinite;
    }
    .toast-container {
        position: fixed;
        top: 24px;
        left: 50%;
        transform: translateX(-50%);
        z-index: 10000;
        display: flex;
        flex-direction: column;
        gap: 10px;
        pointer-events: none;
    }
    .toast {
        background: var(--surface);
        backdrop-filter: blur(12px);
        -webkit-backdrop-filter: blur(12px);
        padding: 12px 24px;
        border-radius: 50px;
        box-shadow: var(--shadow);
        color: var(--text);
        font-weight: 500;
        font-size: 0.95rem;
        display: flex;
        align-items: center;
        gap: 10px;
        opacity: 0;
        transform: translateY(-20px);
        transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        pointer-events: auto;
        border: 1px solid var(--border);
    }
    .toast.show { opacity: 1; transform: translateY(0); }
    .toast.success { border-color: rgba(34, 197, 94, 0.5); }
    .toast.success i { color: #22c55e; }
    .toast.error { border-color: rgba(239, 68, 68, 0.5); }
    .toast.error i { color: #ef4444; }
    `;
}

function getPoemPage() {
    const mottoes = [
        { content: "天行健，君子以自强不息。", author: "《周易》" },
        { content: "满招损，谦受益。", author: "《尚书》" },
        { content: "知行合一，止于至善。", author: "王阳明" },
        { content: "海纳百川，有容乃大。", author: "林则徐" },
        { content: "不积跬步，无以至千里。", author: "荀子" }
    ];
    const motto = mottoes[Math.floor(Math.random() * mottoes.length)];
    
    const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>每日一言</title>
<style>${getCommonCSS()}</style>
</head>
<body>
    <div style="width: 100%; max-width: 440px;">
        <div class="card" style="text-align: center;">
            <div class="logo">🍃</div>
            <h1 style="margin-bottom: 1.5rem;">每日一言</h1>
            <p style="font-size: 1.25rem; font-weight: 500; color: var(--text); margin-bottom: 0.5rem;">“${motto.content}”</p>
            <p style="font-size: 0.875rem; margin-bottom: 2rem;">— ${motto.author}</p>
            <div id="time" style="font-family: monospace; color: var(--text-light);">Loading...</div>
            <div style="margin-top: 1.5rem; font-size: 0.75rem; opacity: 0.5;">刷新页面获取新灵感</div>
        </div>
    </div>
    <script>
        function updateTime() {
            document.getElementById('time').innerText = new Date().toLocaleString('zh-CN');
        }
        setInterval(updateTime, 1000); updateTime();
    </script>
</body>
</html>`;
    return ResponseBuilder.html(html);
}

async function handleUsageAPI(req, env, ctx) {
    const sessionId = getSessionCookie(req.headers.get('Cookie'));
    const sessionResult = await validateAndRefreshSession(env, sessionId);
    if (!sessionResult.valid) {
        return ResponseBuilder.json({ success: false, error: 'Unauthorized' }, 401);
    }
    
    const config = await optimizeConfigLoading(env, ctx);
    const hasCloudflareConfig = config?.cfConfig && config.cfConfig.apiToken;
    
    if (!hasCloudflareConfig) {
        return ResponseBuilder.json({ 
            success: false, 
            error: 'Cloudflare API not configured' 
        }, 400);
    }
    
    const usage = await getCloudflareUsage(env);
    return ResponseBuilder.json({ 
        success: usage.success, 
        usage: {
            pages: usage.pages,
            workers: usage.workers,
            total: usage.total
        }
    });
}

async function handleProxyTest(req, env) {
    try {
        const { type, account } = await req.json();
        
        if (!account) {
            throw new Error("节点地址为空");
        }

        const parsedAddress = await 获取SOCKS5账号(account);
        
        const targetHost = "www.google.com";
        const targetPort = 80;
        
        const startTime = Date.now();
        let socket;

        if (type === 'socks5') {
            socket = await socks5Connect(targetHost, targetPort, parsedAddress);
        } else if (type === 'http') {
            const conn = await httpConnect(targetHost, targetPort, parsedAddress);
            socket = conn.close ? conn : { close: () => conn.cancel ? conn.cancel() : null };
        } else {
            throw new Error("未知的代理协议类型");
        }

        const latency = Date.now() - startTime;
        
        try {
            if (socket && typeof socket.close === 'function') socket.close();
        } catch(e) {}

        return ResponseBuilder.json({
            success: true,
            message: `连接成功! 延迟: ${latency}ms`
        });

    } catch (e) {
        return ResponseBuilder.json({
            success: false,
            message: `连接失败: ${e.message}`
        });
    }
}

export default {
    async fetch(req, env, ctx) {
        try {
            await optimizeConfigLoading(env, ctx);
            if (p === 'dylj' || p === '') {
                p = uid || 'dylj';
            }
            if (env.FDIP) {
                const servers = env.FDIP.split(',').map(s => s.trim());
                fdc = servers;
            }
            p = env.SUB_PATH || env.subpath || p;
            uid = env.UUID || env.uuid || env.AUTH || uid;
            dns = env.DNS_RESOLVER || dns;
            
            const upg = req.headers.get('Upgrade');
            const url = new URL(req.url);
            
            const config = await optimizeConfigLoading(env, ctx);
            const loginPath = config.klp || 'login';
            if (upg && upg.toLowerCase() === 'websocket') {
                const proxyCtx = await getRequestProxyConfig(req, config);
                return await VLOverWSHandler(req, config, proxyCtx);
            } else {
                const pathname = url.pathname;
                if (pathname === '/') {
                    const sessionId = getSessionCookie(req.headers.get('Cookie'));
                    const sessionResult = await validateAndRefreshSession(env, sessionId);
                    
                    if (sessionResult.valid) {
                        const host = req.headers.get('Host');
                        const base = `https://${host}`;
                        const response = await getMainPageContent(host, base, await gP(env), await gU(env), env);
                        if (sessionResult.refreshed) {
                            response.headers.set('Set-Cookie', setSessionCookie(sessionId));
                        }
                        return response;
                    } else {
                        const pw = await gP(env);
                        const u = await gU(env);
                        
                        if (!pw || !u) {
                            return getInitPage(req.headers.get('Host'), `https://${req.headers.get('Host')}`, true);
                        }
                        
                        return getPoemPage();
                    }
                }
                
                if (pathname === `/${loginPath}`) {
                    return await handleLogin(req, env);
                }
                
                switch (pathname) {
                    case `/${p}`:
                        return await sub(req);
                    case '/info':
                        return await requireAuth(req, env, () => ResponseBuilder.json(req.cf));
                    case '/connect':
                        return await requireAuth(req, env, handleConnectTest);
                    case '/test-dns':
                        return await requireAuth(req, env, handleDNSTest);
                    case '/test-config':
                        return await requireAuth(req, env, handleConfigTest);
                    case '/test-failover':
                        return await requireAuth(req, env, handleFailoverTest);
                    case '/test-proxy':
                        return await requireAuth(req, env, handleProxyTest);
                    case '/admin/save':
                        return await handleAdminSave(req, env);
                    case '/admin':
                        return await requireAuth(req, env, getAdminPage);
                    case '/init':
                        return await handleInit(req, env);
                    case '/zxyx':
                        return await requireAuth(req, env, zxyx);
                    case '/logout':
                        return await handleLogout(req, env);
                    case '/api/usage':
                        return await handleUsageAPI(req, env, ctx);
                    default:
                        if (pathname === `/${uid}`) {
                            return await sub(req);
                        }
                        return getPoemPage();
                }
            }
        } catch (err) {
            return ErrorHandler.internalError();
        }
    },
};

function getLoginPage(url, baseUrl, showError = false, showPasswordChanged = false) {
    let msgHtml = '';
    if (showPasswordChanged) msgHtml = `<div class="success-msg">密码已修改，请重新登录</div>`;
    else if (showError) msgHtml = `<div class="error-msg">密码错误，请重试</div>`;

    const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>登录</title>
<style>${getCommonCSS()}</style>
</head>
<body>
    <div style="width: 100%; max-width: 440px;">
        <div class="card" style="text-align: center;">
            <div class="logo">🔒</div>
            <h1>欢迎回来</h1>
            <p>请输入密码以访问控制台</p>
            ${msgHtml}
            <form method="post" action="/${cc?.klp || 'login'}">
                <div class="form-group">
                    <label>访问密码</label>
                    <input type="password" name="password" required autofocus placeholder="请输入登录密码">
                </div>
                <button type="submit" class="btn">立即登录 ➜</button>
            </form>
            <div class="footer">© 2025 Workers Service</div>
        </div>
    </div>
</body>
</html>`;
    return ResponseBuilder.html(html);
}

function getInitPage(url, baseUrl, isFirstTime = true) {
    const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>系统初始化</title>
<style>${getCommonCSS()}</style>
<script>
function genUUID() {
    const p1 = 'xxxxxxxx-xxxx-4xxx';
    const p2 = '-yxxx-xxxxxxxxxxxx';
    const u = (p1 + p2).replace(/[xy]/g, function(c) {
        const r = Math.random() * 16 | 0, v = c === 'x' ? r : (r & 0x3 | 0x8);
        return v.toString(16);
    });
    document.getElementById('uuid').value = u;
}
function validateForm(e) {
    const u = document.getElementById('uuid').value;
    const p1 = '^[0-9a-f]{8}-[0-9a-f]{4}-';
    const p2 = '[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-';
    const p3 = '[0-9a-f]{12}$';
    if (!new RegExp(p1 + p2 + p3, 'i').test(u)) {
        alert('UUID 格式不正确');
        return false;
    }
    return true;
}
</script>
</head>
<body>
    <div style="width: 100%; max-width: 500px;">
        <div class="card">
            <div style="text-align: center;">
                <div class="logo">🚀</div>
                <h1>系统初始化</h1>
                <p>首次运行，请配置基本安全信息</p>
            </div>
            <form action="/init" method="post" onsubmit="return validateForm()">
                <div class="form-group">
                    <label>管理员密码</label>
                    <input type="password" name="password" required minlength="4" placeholder="设置后台登录密码">
                </div>
                <div class="form-group">
                    <label>确认密码</label>
                    <input type="password" name="confirm_password" required minlength="4" placeholder="再次输入密码">
                </div>
                <div class="form-group">
                    <label>UUID (用户ID)</label>
                    <div style="display: flex; gap: 0.5rem;">
                        <input type="text" id="uuid" name="uuid" required placeholder="xxxxxxxx-xxxx-4xxx...">
                        <button type="button" class="btn-secondary" onclick="genUUID()" style="width: auto; white-space: nowrap;">生成</button>
                    </div>
                </div>
                <div class="form-group">
                    <label>自定义登录路径</label>
                    <input type="text" name="login_path" value="login" required placeholder="例如: admin">
                </div>
                <button type="submit" class="btn">完成设置 ➜</button>
            </form>
        </div>
    </div>
</body>
</html>`;
    return ResponseBuilder.html(html);
}

async function handleInit(req, env) {
    const host = req.headers.get('Host');
    const base = `https://${host}`;
    if (req.method !== 'POST') return getInitPage(host, base, true);
    
    const form = await req.formData();
    const password = form.get('password');
    const confirmPassword = form.get('confirm_password');
    const uuid = form.get('uuid');
    const loginPath = form.get('login_path') || 'login';
    
    if (password !== confirmPassword) return ResponseBuilder.html('密码不匹配', 400);
    if (!UUIDUtils.isValidUUID(uuid)) return ResponseBuilder.html('UUID无效', 400);
    
    await sP(env, password);
    await sU(env, uuid);
    await saveConfigToKV(env, yx, fdc, uuid, null, null, null, loginPath);
    
    uid = uuid;
    const sessionId = generateSessionId();
    await saveSession(env, sessionId, 'admin');
    
    return ResponseBuilder.redirect(`${base}/${loginPath}`, 302, {
        'Set-Cookie': setSessionCookie(sessionId)
    });
}

async function getMainPageContent(host, base, pw, uuid, env) {
    const proxyStatus = cc?.proxyConfig?.enabled 
        ? `<span style="color:#22c55e;">● 已启用 (${cc.proxyConfig.type.toUpperCase()} | ${cc.proxyConfig.global ? '全局' : '分流'})</span>` 
        : `<span style="color:#94a3b8;">● 未启用</span>`;
    
    const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>控制台</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
<style>
${getCommonCSS()}
body { justify-content: flex-start; padding: 2rem 1rem; }
.dashboard-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
    gap: 1.5rem;
    width: 100%;
    max-width: 1000px;
    margin-top: 1.5rem;
}
@media (max-width: 768px) {
    .dashboard-grid { grid-template-columns: 1fr; }
}
.card { padding: 1.5rem; }
.stat-item { display: flex; justify-content: space-between; padding: 0.75rem 0; border-bottom: 1px solid rgba(255,255,255,0.1); }
.stat-item:last-child { border-bottom: none; }
.stat-label { color: var(--text-light); display: flex; align-items: center; gap: 0.5rem; }
.stat-val { font-weight: 500; word-break: break-all; text-align: right; }
.action-grid { display: flex; flex-wrap: wrap; gap: 0.75rem; margin-top: 1rem; }
.action-grid .btn, .action-grid .btn-secondary { flex: 1 1 auto; min-width: 120px; }
.copy-btn { cursor: pointer; color: var(--primary); margin-left: 0.5rem; }
.nav-header {
    width: 100%; max-width: 1000px; display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem;
}
.nav-brand { font-size: 1.5rem; font-weight: 700; background: linear-gradient(to right, #6366f1, #a855f7); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
.nav-actions { display: flex; gap: 1rem; }
.glass-btn { background: var(--surface); backdrop-filter: var(--glass); padding: 0.5rem 1rem; border-radius: 2rem; text-decoration: none; color: var(--text); font-size: 0.875rem; border: 1px solid var(--border); transition: all 0.2s; display: flex; align-items: center; gap: 0.5rem; white-space: nowrap; }
.glass-btn:hover { background: rgba(255,255,255,0.2); }
</style>
</head>
<body>
    <div class="nav-header">
        <div class="nav-brand">Workers Service</div>
        <div class="nav-actions">
            <a href="/admin" class="glass-btn"><i class="fas fa-cog"></i> 设置</a>
            <a href="/logout" class="glass-btn"><i class="fas fa-sign-out-alt"></i> 退出</a>
        </div>
    </div>

    <div class="dashboard-grid">
        <div class="card">
            <h3 style="margin-top:0"><i class="fas fa-server" style="color:var(--primary)"></i> 系统状态</h3>
            <div class="stat-item">
                <span class="stat-label">运行状态</span>
                <span class="stat-val" style="display:flex; align-items:center;"><span class="status-dot"></span>正常运行</span>
            </div>
            <div class="stat-item">
                <span class="stat-label">协议</span>
                <span class="stat-val" style="display: flex; align-items: center; gap: 8px; justify-content: flex-end;">
                 <span style="color:${ev?'#22c55e':'#94a3b8'}">Vless ${ev?'●':'●'}</span>
                  <span style="opacity: 0.2;">|</span>
                  <span style="color:${et?'#22c55e':'#94a3b8'}">Trojan ${et?'●':'●'}</span>
                </span>
            </div>
            <div class="stat-item">
                <span class="stat-label">代理转发</span>
                <span class="stat-val">${proxyStatus}</span>
            </div>
            <div class="stat-item">
                <span class="stat-label">API用量</span>
                <span class="stat-val" id="usage">加载中...</span>
            </div>
        </div>

        <div class="card">
            <h3 style="margin-top:0"><i class="fas fa-link" style="color:#ec4899"></i> 订阅管理</h3>
            <div class="action-grid">
                <button class="btn btn-secondary" onclick="copy('${base}/${uuid}')"><i class="fas fa-bolt"></i> Base64</button>
                <button class="btn btn-secondary" onclick="copySub('clash')"><i class="fas fa-cat"></i> Clash</button>
                <button class="btn btn-secondary" onclick="copySub('singbox')"><i class="fas fa-box"></i> SingBox</button>
                <button class="btn btn-secondary" onclick="copy('${base}/${uuid}?format=surge')"><i class="fas fa-paper-plane"></i> Surge</button>
            </div>
        </div>
        
        <div class="card" style="grid-column: 1 / -1;">
             <h3 style="margin-top:0"><i class="fas fa-tools" style="color:#f59e0b"></i> 快捷工具</h3>
             <div class="action-grid">
                <a href="/admin#ip" class="btn btn-secondary"><i class="fas fa-list"></i> IP 库管理</a>
                <a href="/zxyx" class="btn"><i class="fas fa-tachometer-alt"></i> 在线优选 IP</a>
             </div>
        </div>
    </div>

    <script>
    function showToast(msg, type = 'success') {
        let container = document.querySelector('.toast-container');
        if (!container) {
            container = document.createElement('div');
            container.className = 'toast-container';
            document.body.appendChild(container);
        }
        const toast = document.createElement('div');
        toast.className = 'toast ' + type;
        const icon = type === 'success' ? '<i class="fas fa-check-circle"></i>' : '<i class="fas fa-exclamation-circle"></i>';
        toast.innerHTML = icon + '<span>' + msg + '</span>';
        container.appendChild(toast);
        requestAnimationFrame(() => toast.classList.add('show'));
        setTimeout(() => {
            toast.classList.remove('show');
            setTimeout(() => toast.remove(), 300);
        }, 3000);
    }

    function copy(text) {
        navigator.clipboard.writeText(text).then(() => showToast('已复制到剪贴板', 'success'))
        .catch(() => showToast('复制失败，请手动复制', 'error'));
    }
    
    function copySub(type) {
        const rawSub = '${base}/${uuid}';
        const backend = '${cc?.dyhd || dyhd}';
        const config = '${cc?.dypz || dypz}';
        
        let url = backend;
        if (!url.includes('?')) url += '?';
        if (!url.endsWith('?') && !url.endsWith('&')) url += '&';
        
        url += 'target=' + type;
        url += '&url=' + encodeURIComponent(rawSub);
        url += '&config=' + encodeURIComponent(config);
        
        if(type === 'singbox') {
            url += '&include=&exclude='; 
        }
        
        url += '&emoji=true&list=false&tfo=false&scv=false&fdn=false&sort=false';
        copy(url);
    }

    fetch('/api/usage').then(r=>r.json()).then(d=>{
        const el = document.getElementById('usage');
        if(d.success) {
            const total = d.usage.total;
            const limit = 100000;
            const percent = (total / limit) * 100;
            let color = '#22c55e';
            if (percent >= 80) color = '#ef4444';
            else if (percent >= 60) color = '#f59e0b';
            
            el.innerHTML = \`<span style="color:\${color}; font-weight:bold;">\${total} 请求</span>\`;
        } else {
            el.innerText = '未配置';
        }
    });
    </script>
</body>
</html>`;
    return ResponseBuilder.html(html);
}

async function sub(req) {
    const url = new URL(req.url);
    const host = req.headers.get('Host');
    const format = url.searchParams.get('format');
    if (format === 'surge') {
        const cfg = await genSurgeConfig(uid, host);
        return ResponseBuilder.text(cfg);
    }
    const cfg = genConfig(uid, host);
    const content = safeBase64(cfg);
    return ResponseBuilder.text(content);
}

async function handleAdminSave(req, env) {
    try {
        const sessionId = getSessionCookie(req.headers.get('Cookie'));
        const sessionResult = await validateAndRefreshSession(env, sessionId);
        if (!sessionResult.valid) return ErrorHandler.unauthorized();
        
        const form = await req.formData();
        const cfipList = form.get('cfip') || '';
        const fdipList = form.get('fdip') || '';
        const u = form.get('uuid');
        
        const formDyhd = form.get('dyhd');
        const formDypz = form.get('dypz');
        const surgeT = form.get('surgeTemplate');
        
        const newPassword = form.get('new_password');
        
        const protocolEv = form.get('protocol_ev') === 'on';
        const protocolEt = form.get('protocol_et') === 'on';
        const protocolTp = form.get('protocol_tp');
        
        const cfApiMode = form.get('cf_api_mode');
        let cfAccountId = form.get('cf_account_id');
        const cfApiToken = form.get('cf_api_token');
        const cfEmail = form.get('cf_email');
        const cfGlobalApiKey = form.get('cf_global_api_key');
        
        const proxyEnabled = form.get('proxy_enabled') === 'on';
        const proxyType = form.get('proxy_type');
        const proxyAccount = form.get('proxy_account');
        const proxyMode = form.get('proxy_mode');
        const loginPath = form.get('login_path') || 'login';
        
        if (u && !UUIDUtils.isValidUUID(u)) return ResponseBuilder.text('UUID无效', 400);
        
        const cfipArr = uniqueIPList(cfipList.split('\n').map(x => x.trim()).filter(Boolean));
        const fdipArr = uniqueIPList(fdipList.split('\n').map(x => x.trim()).filter(Boolean));
        
        if (newPassword) await sP(env, newPassword);

        if (!cfAccountId && cfApiToken) {
            try {
                const resp = await fetch("https://api.cloudflare.com/client/v4/accounts", {
                    headers: {
                        "Authorization": `Bearer ${cfApiToken}`,
                        "Content-Type": "application/json"
                    }
                });
                if (resp.ok) {
                    const data = await resp.json();
                    if (data.result && data.result.length > 0) {
                        cfAccountId = data.result[0].id;
                    }
                }
            } catch (e) {}
        }
        
        const protocolCfg = { ev: protocolEv, et: protocolEt, tp: protocolTp };
        const cfCfg = { accountId: cfAccountId, apiToken: cfApiToken };
        const proxyCfg = { enabled: proxyEnabled, type: proxyType, account: proxyAccount, global: proxyMode === 'global', whitelist: [] };
        
        await saveConfigToKV(env, cfipArr, fdipArr, u, protocolCfg, cfCfg, proxyCfg, loginPath, formDyhd, formDypz, surgeT);

        yx = cfipArr; fdc = fdipArr; dyhd = formDyhd; dypz = formDypz; stp = surgeT;
        if (u) uid = u;
        ev = protocolEv; et = protocolEt; tp = protocolTp;
        protocolConfig = { ev, et, tp };
        
        const host = req.headers.get('Host');
        
        if (req.headers.get('Accept') === 'application/json') {
             return ResponseBuilder.json({ success: true });
        }
        
        return ResponseBuilder.redirect(`https://${host}/admin?msg=saved`);
    } catch (e) {
        return ResponseBuilder.text(e.message, 500);
    }
}

async function getAdminPage(req, env) {
    const sessionId = getSessionCookie(req.headers.get('Cookie'));
    const sessionResult = await validateAndRefreshSession(env, sessionId);
    if (!sessionResult.valid) return ErrorHandler.unauthorized();
    
    const url = new URL(req.url);
    if (!cc) await optimizeConfigLoading(env);
    
    const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>系统配置</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
<style>
${getCommonCSS()}
body { justify-content: flex-start; padding: 2rem 1rem; }
.admin-container { max-width: 1000px; width: 100%; margin: 0 auto; }
.card { padding: 1.5rem; margin-bottom: 1.5rem; }
h3 {
    margin-top: 0;
    margin-bottom: 1.25rem;
    font-size: 1.25rem;
    font-weight: 700;
    color: var(--text);
    display: flex;
    align-items: center;
    gap: 0.75rem;
}
.grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; }
@media (max-width: 768px) { .grid-2 { grid-template-columns: 1fr; } }
label { font-size: 0.9rem; font-weight: 600; color: var(--text); margin-bottom: 0.5rem; display: block; }
.form-group { margin-bottom: 1.25rem; position: relative; }
textarea { 
    font-family: 'Menlo', 'Monaco', 'Courier New', monospace; 
    font-size: 0.85rem; 
    line-height: 1.4;
    height: 140px; 
    background: rgba(255,255,255,0.03); 
    border-color: var(--border);
}
textarea:focus { background: rgba(255,255,255,0.08); }
.help-text { 
    font-size: 0.8rem; 
    color: var(--text-light); 
    margin-top: 0.5rem; 
    line-height: 1.4;
    display: flex;
    align-items: flex-start;
    gap: 0.4rem;
    background: rgba(255,255,255,0.03);
    padding: 0.5rem;
    border-radius: 0.5rem;
}
.help-text i { margin-top: 0.15rem; color: var(--primary); opacity: 0.8; }
.toggle-switch { margin-bottom: 0; }
</style>
<script>
function genUUID() {
    const u = crypto.randomUUID();
    document.getElementById('uuid').value = u;
}
function showToast(msg, type = 'success') {
    let container = document.querySelector('.toast-container');
    if (!container) {
        container = document.createElement('div');
        container.className = 'toast-container';
        document.body.appendChild(container);
    }
    const toast = document.createElement('div');
    toast.className = 'toast ' + type;
    const icon = type === 'success' ? '<i class="fas fa-check-circle"></i>' : '<i class="fas fa-exclamation-circle"></i>';
    toast.innerHTML = icon + '<span>' + msg + '</span>';
    container.appendChild(toast);
    requestAnimationFrame(() => toast.classList.add('show'));
    setTimeout(() => {
        toast.classList.remove('show');
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}
function testProxy() {
    const btn = document.getElementById('proxy-test-btn');
    const accountInput = document.querySelector('input[name="proxy_account"]');
    const typeSelect = document.querySelector('select[name="proxy_type"]');
    
    const account = accountInput.value.trim();
    const type = typeSelect.value;

    if (!account) {
        showToast('请先输入节点地址', 'error');
        accountInput.focus();
        return;
    }

    const originalText = btn.innerHTML;
    btn.disabled = true;
    btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> 测试中...';
    
    fetch('/test-proxy', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ account: account, type: type })
    })
    .then(r => r.json())
    .then(data => {
        if(data.success) {
            showToast(data.message, 'success');
        } else {
            showToast(data.message, 'error');
        }
    })
    .catch(e => showToast('请求错误: ' + e, 'error'))
    .finally(() => {
        btn.disabled = false;
        btn.innerHTML = originalText;
    });
}
async function saveConfig(e) {
    e.preventDefault();
    const form = e.target;
    const btn = form.querySelector('button[type="submit"]');
    const originalText = btn.innerHTML;
    btn.disabled = true;
    btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> 保存中...';
    
    try {
        const response = await fetch('/admin/save', {
            method: 'POST',
            body: new FormData(form),
            headers: {
                'Accept': 'application/json'
            }
        });
        if (response.ok) {
            showToast('配置已保存并立即生效', 'success');
        } else {
            showToast('保存失败', 'error');
        }
    } catch (err) {
        showToast('网络错误: ' + err, 'error');
    } finally {
        btn.disabled = false;
        btn.innerHTML = originalText;
    }
}
</script>
</head>
<body>
    <div class="admin-container">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom: 1.5rem;">
            <h1 style="margin:0"><i class="fas fa-cogs"></i> 系统配置</h1>
            <a href="/" class="btn-secondary btn" style="width:auto; padding: 0.6rem 1.2rem; gap: 0.5rem;"><i class="fas fa-arrow-left"></i> 返回主页</a>
        </div>

        <form onsubmit="saveConfig(event)">
            <div class="card" id="ip">
                <h3><i class="fas fa-globe" style="color:var(--primary)"></i> IP 资源管理</h3>
                <div class="grid-2">
                    <div class="form-group">
                        <label>优选 IP / 域名 (Web伪装 & 订阅)</label>
                        <textarea name="cfip" placeholder="例如: 1.1.1.1:443#美国">${yx.join('\n')}</textarea>
                        <div class="help-text"><i class="fas fa-info-circle"></i><span>格式: <code>IP:端口#备注</code><br>用于 Web 伪装和生成订阅链接。</span></div>
                    </div>
                    <div class="form-group">
                        <label>反代 IP / 域名 (中转连接)</label>
                        <textarea name="fdip" placeholder="例如: ip.sb">${fdc.join('\n')}</textarea>
                        <div class="help-text"><i class="fas fa-info-circle"></i><span>格式: <code>IP</code> 或 <code>域名</code><br>用于 Worker 实际回源连接。</span></div>
                    </div>
                </div>
            </div>

            <div class="card">
                <h3><i class="fas fa-shield-alt" style="color:#ec4899"></i> 协议与安全</h3>
                <div class="grid-2">
                    <div class="form-group">
                        <label>启用协议</label>
                        <div style="display:flex; gap:2rem; margin-top:0.5rem; background:rgba(255,255,255,0.03); padding:1rem; border-radius:0.5rem; align-items:center;">
                            <label class="toggle-switch" style="margin:0"><input type="checkbox" name="protocol_ev" ${ev ? 'checked' : ''}> Vless</label>
                            <label class="toggle-switch" style="margin:0"><input type="checkbox" name="protocol_et" ${et ? 'checked' : ''}> Trojan</label>
                        </div>
                    </div>
                    <div class="form-group">
                        <label>Trojan 密码</label>
                        <input type="text" name="protocol_tp" value="${tp}" placeholder="留空则默认使用 UUID">
                    </div>
                </div>
                <div class="form-group">
                    <label>UUID (用户ID)</label>
                    <div style="display: flex; gap: 0.75rem;">
                        <input type="text" id="uuid" name="uuid" value="${uid}" required style="font-family:monospace;">
                        <button type="button" class="btn btn-secondary" onclick="genUUID()" style="width: auto; padding: 0 1.5rem;">生成</button>
                    </div>
                </div>
                 <div class="form-group">
                    <label>修改后台密码</label>
                    <input type="password" name="new_password" placeholder="留空保持不变">
                </div>
            </div>

            <div class="card">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:1.25rem;">
                    <h3 style="margin:0"><i class="fas fa-network-wired" style="color:#f59e0b"></i> 代理转发 (SOCKS5/HTTP)</h3>
                    <button type="button" class="btn btn-secondary" onclick="testProxy()" id="proxy-test-btn" style="width:auto; padding:0.4rem 1rem; font-size:0.85rem;">
                        <i class="fas fa-stethoscope"></i> 测试连通性
                    </button>
                </div>
                
                <div class="form-group">
                    <label class="toggle-switch" style="display:flex; align-items:center; margin-bottom: 1rem;">
                        <input type="checkbox" name="proxy_enabled" ${cc?.proxyConfig?.enabled ? 'checked' : ''}> 启用代理转发功能
                    </label>
                </div>
                <div class="grid-2">
                    <div class="form-group">
                        <label>节点地址</label>
                        <input type="text" name="proxy_account" value="${cc?.proxyConfig?.account || ''}" placeholder="user:pass@host:port">
                    </div>
                    <div class="form-group">
                        <label>协议类型</label>
                        <select name="proxy_type">
                            <option value="socks5" ${cc?.proxyConfig?.type === 'socks5' ? 'selected' : ''}>SOCKS5</option>
                            <option value="http" ${cc?.proxyConfig?.type === 'http' ? 'selected' : ''}>HTTP</option>
                        </select>
                    </div>
                </div>
                <div class="form-group">
                    <label>转发模式</label>
                    <div style="display:flex; gap:2rem; margin-top:0.5rem; background:rgba(255,255,255,0.03); padding:1rem; border-radius:0.5rem;">
                        <label class="toggle-switch">
                            <input type="radio" name="proxy_mode" value="global" ${cc?.proxyConfig?.global ? 'checked' : ''}> 全局代理 (Global)
                        </label>
                        <label class="toggle-switch">
                            <input type="radio" name="proxy_mode" value="failover" ${!cc?.proxyConfig?.global ? 'checked' : ''}> 故障分流 (Failover)
                        </label>
                    </div>
                    <div class="help-text" style="margin-top:0.5rem;"><i class="fas fa-lightbulb"></i><span>全局：所有流量优先走代理；分流：直连失败后尝试代理。</span></div>
                    <div style="margin-top: 0.75rem;">
                        <details style="background: transparent; border: none;">
                            <summary style="cursor: pointer; color: var(--primary); font-size: 0.85rem; display: flex; align-items: center; gap: 0.25rem;">
                                <i class="fas fa-question-circle" style="font-size: 0.8rem;"></i>
                                支持格式说明
                            </summary>
                            <div style="margin-top: 0.5rem; padding: 0.5rem; background: rgba(255,255,255,0.03); border-radius: 0.25rem; font-size: 0.75rem; line-height: 1.4;">
                                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 0.5rem;">
                                    <div>
                                        <div style="color: var(--text); font-weight: 500;">基本格式</div>
                                        <code style="font-size: 0.7rem;">user:pass@host:port</code>
                                        <br><code style="font-size: 0.7rem;">host:port</code>
                                    </div>
                                    <div>
                                        <div style="color: var(--text); font-weight: 500;">高级格式</div>
                                        <code style="font-size: 0.7rem;">base64@host:port</code>
                                        <br><code style="font-size: 0.7rem;">[IPv6]:port</code>
                                    </div>
                                </div>
                                <div style="margin-top: 0.5rem; color: var(--text-light); font-size: 0.7rem;">
                                    <i class="fas fa-bolt" style="color: var(--primary);"></i>
                                    路径用法: <code>socks5://...#备注</code> 或 <code>http://...#备注</code>
                                </div>
                            </div>
                        </details>
                    </div>
                </div>
            </div>
            
            <div class="card">
                <h3><i class="fas fa-bolt" style="color:#8b5cf6"></i> 订阅配置</h3>
                <div class="grid-2">
                    <div class="form-group">
                        <label>订阅转换后端地址</label>
                        <input type="text" name="dyhd" value="${cc?.dyhd || dyhd}" placeholder="https://xxx.xx.xx/sub?">
                    </div>
                    <div class="form-group">
                        <label>远程配置规则地址</label>
                        <input type="text" name="dypz" value="${cc?.dypz || dypz}" placeholder="https://...">
                    </div>
                </div>
                <div class="form-group">
                    <label>Surge 专用模版</label>
                    <input type="text" name="surgeTemplate" value="${cc?.stp || ''}" placeholder="https://raw.githubusercontent.com/...">
                    <div class="help-text"><i class="fas fa-exclamation-circle"></i><span>仅影响 Surge 订阅格式。留空则使用系统内置模版。</span></div>
                </div>
                 <div class="form-group">
                    <label>自定义后台入口路径</label>
                    <div style="position:relative;">
                        <span style="position:absolute; left:1rem; top:0.75rem; color:var(--text-light); opacity:0.5;">/</span>
                        <input type="text" name="login_path" value="${cc?.klp || 'login'}" style="padding-left: 2rem;">
                    </div>
                    <div class="help-text"><i class="fas fa-lock"></i> <span>设置后只能通过 <code>域名/路径</code> 访问。</span></div>
                </div>
            </div>

            <div class="card" style="margin-bottom: 5rem;">
                <h3><i class="fas fa-chart-line" style="color:#10b981"></i> Cloudflare API (用量统计)</h3>
                <div class="grid-2">
                    <div class="form-group">
                        <label>Account ID</label>
                        <input type="text" name="cf_account_id" value="${cc?.cfConfig?.accountId || ''}" placeholder="支持手动输入 & 支持通过Token自动获取">
                    </div>
                    <div class="form-group">
                        <label>API Token</label>
                        <input type="password" name="cf_api_token" value="${cc?.cfConfig?.apiToken || ''}" placeholder="填入Token并保存后，系统将尝试自动获取ID">
                    </div>
                </div>
                <div class="help-text"><i class="fas fa-shield-alt"></i><span>请在 Cloudflare 用户资料页创建 Token，阅读日志权限选择 "Analytics: Read" (分析:读取)。</span></div>
            </div>

            <div style="position: fixed; bottom: 2rem; left: 0; right: 0; display: flex; justify-content: center; pointer-events: none; z-index: 100;">
                <button type="submit" class="btn" style="pointer-events: auto; box-shadow: 0 10px 30px rgba(79, 70, 229, 0.4); width: auto; padding: 1rem 3rem; border-radius: 2rem;">
                    <i class="fas fa-save"></i> 保存所有配置
                </button>
            </div>
        </form>
    </div>
</body>
</html>`;
    return ResponseBuilder.html(html);
}

async function handleConnectTest(req, env) {
    try {
        const { socket, server } = await universalConnectWithFailover();
        socket.close();
        return ResponseBuilder.json({
            success: true,
            message: `成功连接到 ${server.original}`,
            server: server
        });
    } catch (e) {
        return ResponseBuilder.json({
            success: false,
            message: `连接失败: ${e.message}`
        }, 500);
    }
}

async function handleDNSTest(req, env) {
    try {
        const res = await fetch(dns, {
            method: 'POST',
            headers: { 'content-type': 'application/dns-message' },
            body: new Uint8Array([0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 6, 103, 111, 111, 103, 108, 101, 3, 99, 111, 109, 0, 0, 1, 0, 1])
        });
        const ans = await res.arrayBuffer();
        return ResponseBuilder.json({
            success: true,
            message: 'DNS查询成功',
            response: new Uint8Array(ans).slice(0, 100)
        });
    } catch (e) {
        return ResponseBuilder.json({
            success: false,
            message: `DNS查询失败: ${e.message}`
        }, 500);
    }
}

async function handleConfigTest(req, env) {
    try {
        const host = req.headers.get('Host');
        const config = genConfig(uid, host);
        return ResponseBuilder.json({
            success: true,
            message: '配置生成成功',
            config: config
        });
    } catch (e) {
        return ResponseBuilder.json({
            success: false,
            message: `配置生成失败: ${e.message}`
        }, 500);
    }
}

async function handleFailoverTest(req, env) {
    try {
        const testResults = [];
        const servers = [...fdc, 'www.visa.com.sg'];
        
        for (let i = 0; i < servers.length; i++) {
            const s = servers[i];
            try {
                const { hostname, port } = IPParser.parseConnectionAddress(s);
                const socket = await connect({
                    hostname: hostname,
                    port: port,
                    connectTimeout: globalTimeout,
                    noDelay: true
                });
                socket.close();
                testResults.push({
                    server: s,
                    status: 'success',
                    message: `连接成功`
                });
            } catch (e) {
                testResults.push({
                    server: s,
                    status: 'failed',
                    message: `连接失败: ${e.message}`
                });
            }
        }
        
        return ResponseBuilder.json({
            success: true,
            message: '故障转移测试完成',
            results: testResults
        });
    } catch (e) {
        return ResponseBuilder.json({
            success: false,
            message: `故障转移测试失败: ${e.message}`
        }, 500);
    }
}

async function zxyx(request, env, txt = 'ADD.txt') {
    const countryCodeToName = {
        'US': '美国', 'SG': '新加坡', 'DE': '德国', 'JP': '日本', 'KR': '韩国',
        'HK': '香港', 'TW': '台湾', 'GB': '英国', 'FR': '法国', 'IN': '印度',
        'BR': '巴西', 'CA': '加拿大', 'AU': '澳大利亚', 'NL': '荷兰', 'CH': '瑞士',
        'SE': '瑞典', 'IT': '意大利', 'ES': '西班牙', 'RU': '俄罗斯', 'ZA': '南非',
        'MX': '墨西哥', 'MY': '马来西亚', 'TH': '泰国', 'ID': '印度尼西亚', 'VN': '越南',
        'PH': '菲律宾', 'TR': '土耳其', 'SA': '沙特阿拉伯', 'AE': '阿联酋', 'EG': '埃及',
        'NG': '尼日利亚', 'IL': '以色列', 'PL': '波兰', 'UA': '乌克兰', 'CZ': '捷克',
        'RO': '罗马尼亚', 'GR': '希腊', 'PT': '葡萄牙', 'DK': '丹麦', 'FI': '芬兰',
        'NO': '挪威', 'AT': '奥地利', 'BE': '比利时', 'IE': '爱尔兰', 'LU': '卢森堡',
        'CY': '塞浦路斯', 'MT': '马耳他', 'IS': '冰岛', 'CN': '中国'
    };

    function getCountryName(countryCode) {
        return countryCodeToName[countryCode] || countryCode;
    }

    if (!env.SJ) {
        env.SJ = env.SJ || env.sj;
    }
    
    const country = request.cf?.country || 'CN';
    
    async function getNipDomain() {
        try {
            const response = await fetch(atob('aHR0cHM6Ly9jbG91ZGZsYXJlLWRucy5jb20vZG5zLXF1ZXJ5P25hbWU9bmlwLjA5MDIyNy54eXomdHlwZT1UWFQ='), {
                headers: {
                    'Accept': 'application/dns-json'
                }
            });

            if (response.ok) {
                const data = await response.json();
                if (data.Status === 0 && data.Answer && data.Answer.length > 0) {
                    const txtRecord = data.Answer[0].data;
                    const domain = txtRecord.replace(/^"(.*)"$/, '$1');
                    return domain;
                }
            }
            return atob('bmlwLmxmcmVlLm9yZw==');
        } catch (error) {
            return atob('aXAuMDkwMjI3Lnh5eg==');
        }
    }
    
    const nipDomain = await getNipDomain();
    
    function isValidIP(ip) {
        const ipRegex = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
        const match = ip.match(ipRegex);
        
        if (!match) return false;
        
        for (let i = 1; i <= 4; i++) {
            const num = parseInt(match[i]);
            if (num < 0 || num > 255) {
                return false;
            }
        }
        
        return true;
    }

    function parseCIDRFormat(cidrString) {
        try {
            const [network, prefixLength] = cidrString.split('/');
            const prefix = parseInt(prefixLength);
            
            if (isNaN(prefix) || prefix < 8 || prefix > 32) {
                return null;
            }
            
            const ipRegex = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
            if (!ipRegex.test(network)) {
                return null;
            }
            
            const octets = network.split('.').map(Number);
            for (const octet of octets) {
                if (octet < 0 || octet > 255) {
                    return null;
                }
            }
            
            return {
                network: network,
                prefixLength: prefix,
                type: 'cidr'
            };
        } catch (error) {
            return null;
        }
    }

    function generateIPsFromCIDR(cidr, maxIPs = 100) {
        try {
            const [network, prefixLength] = cidr.split('/');
            const prefix = parseInt(prefixLength);

            const ipToInt = (ip) => {
                return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet), 0) >>> 0;
            };

            const intToIP = (int) => {
                return [
                    (int >>> 24) & 255,
                    (int >>> 16) & 255,
                    (int >>> 8) & 255,
                    int & 255
                ].join('.');
            };

            const networkInt = ipToInt(network);
            const hostBits = 32 - prefix;
            const numHosts = Math.pow(2, hostBits);

            if (numHosts <= 2) {
                return [];
            }

            const maxHosts = numHosts - 2;
            const actualCount = Math.min(maxIPs, maxHosts);
            const ips = new Set();

            if (maxHosts <= 0) {
                return [];
            }

            let attempts = 0;
            const maxAttempts = actualCount * 10;

            while (ips.size < actualCount && attempts < maxAttempts) {
                const randomOffset = Math.floor(Math.random() * maxHosts) + 1;
                const randomIP = intToIP(networkInt + randomOffset);
                ips.add(randomIP);
                attempts++;
            }

            return Array.from(ips);
        } catch (error) {
            return [];
        }
    }

    async function GetCFIPs(ipSource = 'official', targetPort = '443', maxCount = 50) {
        try {
            let response;
            if (ipSource.startsWith('http://') || ipSource.startsWith('https://')) {
                try {
                    response = await fetch(ipSource, {
                        headers: {
                            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
                        }
                    });
                } catch (e) {
                    throw new Error(`无法连接到自定义 API: ${e.message}`);
                }
            } else if (ipSource === 'as13335') {
                response = await fetch(atob('aHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tL2lwdmVyc2UvYXNuLWlwL21hc3Rlci9hcy8xMzMzNS9pcHY0LWFnZ3JlZ2F0ZWQudHh0'));
            } else if (ipSource === 'as209242') {
                response = await fetch(atob('aHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tL2lwdmVyc2UvYXNuLWlwL21hc3Rlci9hcy8yMDkyNDIvaXB2NC1hZ2dyZWdhdGVkLnR4dA=='));
            } else if (ipSource === 'as24429') {
                response = await fetch(atob('aHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tL2lwdmVyc2UvYXNuLWlwL21hc3Rlci9hcy8yNDQyOS9pcHY0LWFnZ3JlZ2F0ZWQudHh0'));
            } else if (ipSource === 'as35916') {
                response = await fetch(atob('aHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tL2lwdmVyc2UvYXNuLWlwL21hc3Rlci9hcy8zNTkxNi9pcHY0LWFnZ3JlZ2F0ZWQudHh0'));
            } else if (ipSource === 'as199524') {
                response = await fetch(atob('aHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tL2lwdmVyc2UvYXNuLWlwL21hc3Rlci9hcy8xOTk1MjQvaXB2NC1hZ2dyZWdhdGVkLnR4dA=='));
            } else {
                response = await fetch(atob('aHR0cHM6Ly93d3cuY2xvdWRmbGFyZS5jb20vaXBzLXY0Lw=='));
            }

            if (!response.ok) throw new Error(`API 响应错误: ${response.status}`);
            
            const text = await response.text();
            let lines = [];
            try {
                const json = JSON.parse(text);
                if (Array.isArray(json)) lines = json;
                else if (json.data && Array.isArray(json.data)) lines = json.data;
                else lines = text.split('\n');
            } catch {
                lines = text.split('\n');
            }

            const cidrs = lines.map(String).filter(line => line.trim() && !line.trim().startsWith('#') && !line.trim().startsWith('//'));

            const allIPs = new Set();
            
            for (const cidr of cidrs) {
                const cidrInfo = parseCIDRFormat(cidr.trim());
                if (cidrInfo) {
                    const ipsFromCIDR = generateIPsFromCIDR(cidr.trim(), Math.ceil(maxCount / (cidrs.length || 1)));
                    ipsFromCIDR.forEach(ip => allIPs.add(ip + ':' + targetPort));
                } else {
                    let cleanIP = cidr.trim();
                    if (isValidIP(cleanIP.split(':')[0])) {
                         if (!cleanIP.includes(':')) cleanIP += ':' + targetPort;
                         allIPs.add(cleanIP);
                    }
                }
            }

            const ipArray = Array.from(allIPs);
            if (ipArray.length > 0) {
                 for (let i = ipArray.length - 1; i > 0; i--) {
                    const j = Math.floor(Math.random() * (i + 1));
                    [ipArray[i], ipArray[j]] = [ipArray[j], ipArray[i]];
                }
            }
            
            return ipArray.slice(0, maxCount);

        } catch (error) {
            return [];
        }
    }

    const url = new URL(request.url);
    
    if (request.method === "POST") {
        if (!env.SJ) return new Response("未绑定KV空间", { status: 400 });

        try {
            const contentType = request.headers.get('Content-Type');

            if (contentType && contentType.includes('application/json')) {
                const data = await request.json();
                const action = url.searchParams.get('action') || 'save';

                if (!data.ips || !Array.isArray(data.ips)) {
                    return new Response(JSON.stringify({ error: 'Invalid IP list' }), {
                        status: 400,
                        headers: { 'Content-Type': 'application/json' }
                    });
                }

                let currentConfig = await env.SJ.get(K_SETTINGS, 'json');
                if (!currentConfig) {
                    currentConfig = {
                        yx: yx,
                        fdc: fdc,
                        uid: uid,
                        dyhd: dyhd,
                        dypz: dypz,
                        protocolConfig: { ev, et, tp },
                        cfConfig: {},
                        proxyConfig: {},
                        klp: 'login'
                    };
                }

                if (action === 'replace-cf' || action === 'append-cf') {
                    if (data.ips.length > 0 && data.ips.join('\n').length > 24 * 1024 * 1024) {
                        return new Response(JSON.stringify({ error: '内容过大' }), { status: 400, headers: { 'Content-Type': 'application/json' }});
                    }

                    if (action === 'replace-cf') {
                        currentConfig.yx = uniqueIPList(data.ips);
                        await env.SJ.put(K_SETTINGS, JSON.stringify(currentConfig));
                        yx = currentConfig.yx;
                        cc = { ...currentConfig, yx: currentConfig.yx, ct: Date.now() };
                        return new Response(JSON.stringify({
                            success: true,
                            message: `成功替换优选IP列表，保存 ${currentConfig.yx.length} 个IP并立即生效`
                        }), { headers: { 'Content-Type': 'application/json' }});
                    } else {
                        const newIPs = uniqueIPList([...currentConfig.yx, ...data.ips]);
                        if (newIPs.join('\n').length > 24 * 1024 * 1024) {
                            return new Response(JSON.stringify({ error: '追加后内容过大' }), { status: 400, headers: { 'Content-Type': 'application/json' }});
                        }
                        currentConfig.yx = newIPs;
                        await env.SJ.put(K_SETTINGS, JSON.stringify(currentConfig));
                        yx = newIPs;
                        cc = { ...currentConfig, yx: newIPs, ct: Date.now() };
                        return new Response(JSON.stringify({
                            success: true,
                            message: `成功追加优选IP列表，新增 ${data.ips.length} 个IP并立即生效`
                        }), { headers: { 'Content-Type': 'application/json' }});
                    }
                }
                else if (action === 'replace-fd' || action === 'append-fd') {
                    if (data.ips.length > 0 && data.ips.join('\n').length > 24 * 1024 * 1024) {
                        return new Response(JSON.stringify({ error: '内容过大' }), { status: 400, headers: { 'Content-Type': 'application/json' }});
                    }

                    if (action === 'replace-fd') {
                        currentConfig.fdc = uniqueIPList(data.ips);
                        await env.SJ.put(K_SETTINGS, JSON.stringify(currentConfig));
                        fdc = currentConfig.fdc;
                        cc = { ...currentConfig, fdc: currentConfig.fdc, ct: Date.now() };
                        return new Response(JSON.stringify({
                            success: true,
                            message: `成功替换反代IP列表，保存 ${currentConfig.fdc.length} 个IP并立即生效`
                        }), { headers: { 'Content-Type': 'application/json' }});
                    } else {
                        const newIPs = uniqueIPList([...currentConfig.fdc, ...data.ips]);
                        if (newIPs.join('\n').length > 24 * 1024 * 1024) {
                            return new Response(JSON.stringify({ error: '追加后内容过大' }), { status: 400, headers: { 'Content-Type': 'application/json' }});
                        }
                        currentConfig.fdc = newIPs;
                        await env.SJ.put(K_SETTINGS, JSON.stringify(currentConfig));
                        fdc = newIPs;
                        cc = { ...currentConfig, fdc: newIPs, ct: Date.now() };
                        return new Response(JSON.stringify({
                            success: true,
                            message: `成功追加反代IP列表，新增 ${data.ips.length} 个IP并立即生效`
                        }), { headers: { 'Content-Type': 'application/json' }});
                    }
                } else {
                    return new Response(JSON.stringify({ error: '未知的操作类型' }), {
                        status: 400,
                        headers: { 'Content-Type': 'application/json' }
                    });
                }
            } else {
                const content = await request.text();
                await env.SJ.put(txt, content);
                return new Response("保存成功");
            }

        } catch (error) {
            return new Response(JSON.stringify({
                error: '操作失败: ' + error.message
            }), {
                status: 500,
                headers: { 'Content-Type': 'application/json' }
            });
        }
    }

    if (url.searchParams.get('loadIPs')) {
        const ipSource = url.searchParams.get('loadIPs');
        const port = url.searchParams.get('port') || '443';
        const count = parseInt(url.searchParams.get('count')) || 50;
        const ips = await GetCFIPs(ipSource, port, count);

        return new Response(JSON.stringify({ ips }), {
            headers: {
                'Content-Type': 'application/json',
            },
        });
    }

    let content = '';
    let hasKV = !!env.SJ;

    if (hasKV) {
        try {
            content = await env.SJ.get(txt) || '';
        } catch (error) {
            content = '读取数据时发生错误: ' + error.message;
        }
    }

    const cfIPs = [];
    const isChina = country === 'CN';
    const countryDisplayClass = isChina ? '' : 'proxy-warning';
    const countryDisplayText = isChina ? `${country}` : `${country} (可能需关闭代理)`;

    const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>在线优选工具</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
<style>
${getCommonCSS()}
body { justify-content: flex-start; padding: 2rem 1rem 8rem 1rem; }
.container { max-width: 1000px; width: 100%; margin: 0 auto; }
.card { padding: 1.5rem; margin-bottom: 1.5rem; }
h3 { margin-top: 0; margin-bottom: 1.25rem; font-size: 1.25rem; font-weight: 700; color: var(--text); display: flex; align-items: center; gap: 0.75rem; }
.grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; }
.grid-3 { display: grid; grid-template-columns: repeat(3, 1fr); gap: 1rem; }
@media (max-width: 768px) { .grid-2, .grid-3 { grid-template-columns: 1fr; } }
.nav-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem; }
.nav-brand { font-size: 1.5rem; font-weight: 700; background: linear-gradient(to right, #6366f1, #a855f7); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
.stats-val { font-size: 1.25rem; font-weight: 600; color: var(--primary); }
.stats-label { font-size: 0.85rem; color: var(--text-light); }
.proxy-warning { color: #ef4444; font-weight: bold; }
.ip-list { background: rgba(0,0,0,0.03); padding: 1rem; border-radius: 0.5rem; border: 1px solid var(--border); max-height: 400px; overflow-y: auto; font-family: monospace; font-size: 0.9rem; }
.ip-item { margin: 4px 0; padding: 4px 8px; border-radius: 4px; display: flex; justify-content: space-between; }
.ip-item:hover { background: rgba(255,255,255,0.05); }
.good-latency { color: #22c55e; }
.medium-latency { color: #f59e0b; }
.bad-latency { color: #ef4444; }
.progress-container { background: rgba(0,0,0,0.1); border-radius: 2rem; height: 10px; overflow: hidden; margin: 1rem 0; display: flex; }
.progress-bar-success { background: #22c55e; height: 100%; width: 0%; transition: width 0.3s ease; }
.progress-bar-fail { background: #ef4444; height: 100%; width: 0%; transition: width 0.3s ease; }
.btn-group { display: flex; gap: 1rem; flex-wrap: wrap; margin-top: 1rem; }
label { font-size: 0.9rem; font-weight: 600; margin-bottom: 0.5rem; display: block; }
select, input[type="number"] { width: 100%; }
.control-section { padding-bottom: 1.5rem; border-bottom: 1px dashed var(--border); margin-bottom: 1.5rem; }
.control-section:last-child { border-bottom: none; margin-bottom: 0; padding-bottom: 0; }
</style>
<script>
function showToast(msg, type = 'success') {
    let container = document.querySelector('.toast-container');
    if (!container) {
        container = document.createElement('div');
        container.className = 'toast-container';
        document.body.appendChild(container);
    }
    const toast = document.createElement('div');
    toast.className = 'toast ' + type;
    const icon = type === 'success' ? '<i class="fas fa-check-circle"></i>' : '<i class="fas fa-exclamation-circle"></i>';
    toast.innerHTML = icon + '<span>' + msg + '</span>';
    container.appendChild(toast);
    requestAnimationFrame(() => toast.classList.add('show'));
    setTimeout(() => {
        toast.classList.remove('show');
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}
</script>
</head>
<body>
    <div class="container">
        <div class="nav-header">
            <div class="nav-brand">在线优选 IP</div>
            <div style="display:flex; gap:0.5rem;">
                 <a href="/admin" class="btn btn-secondary" style="width:auto; padding: 0.5rem 1rem;"><i class="fas fa-cog"></i> 配置</a>
                 <a href="/" class="btn btn-secondary" style="width:auto; padding: 0.5rem 1rem;"><i class="fas fa-arrow-left"></i> 首页</a>
            </div>
        </div>

        ${!isChina ? `<div class="card" style="padding: 1rem; margin-bottom: 1.5rem;"><div style="display:flex; gap:1rem; align-items:center;"><i class="fas fa-exclamation-triangle" style="color:#ef4444; font-size:1.5rem;"></i><div><h4 style="margin:0; color:#ef4444;">代理环境警告</h4><p style="margin:0.25rem 0 0 0; font-size:0.9rem;">检测到您可能处于代理或 VPN 环境中（${country}），测速结果可能不准确。建议关闭代理后刷新页面。</p></div></div></div>` : ''}

        <div class="card" id="status-card">
            <h3><i class="fas fa-chart-bar" style="color:var(--primary)"></i> 状态概览</h3>
            <div class="grid-3">
                <div style="text-align:center;">
                    <div class="stats-label">您的位置</div>
                    <div class="stats-val ${countryDisplayClass}">${countryDisplayText}</div>
                </div>
                <div style="text-align:center;">
                    <div class="stats-label">加载 IP 数</div>
                    <div class="stats-val" id="ip-count">0</div>
                </div>
                <div style="text-align:center;">
                    <div class="stats-label">有效结果</div>
                    <div class="stats-val" id="result-count-val" style="color:#22c55e;">0</div>
                </div>
            </div>
            <div style="margin-top: 1.5rem;">
                <div style="display:flex; justify-content:space-between; font-size:0.85rem; color:var(--text-light); margin-bottom: 0.5rem;">
                    <span id="progress-text">准备就绪</span>
                    <span id="progress-percent">0%</span>
                </div>
                <div class="progress-container">
                    <div class="progress-bar-success" id="progress-bar-success"></div>
                    <div class="progress-bar-fail" id="progress-bar-fail"></div>
                </div>
            </div>
        </div>

        <div class="card">
            <h3><i class="fas fa-sliders-h" style="color:#f59e0b"></i> 测速配置</h3>
            
            <div class="control-section">
                <div class="grid-3">
                    <div class="form-group">
                        <label>IP 来源库</label>
                        <select id="ip-source-select">
                            <option value="official">Cloudflare 官方</option>
                            <option value="as13335">AS13335 (Cloudflare)</option>
                            <option value="as209242">AS209242 (ArvanCloud)</option>
                            <option value="as24429">AS24429 (Alibaba)</option>
                            <option value="as199524">AS199524 (G-Core)</option>
                            <option value="local">本地文件上传</option>
                            <option value="custom">远程 API</option>
                        </select>
                        <div id="custom-api-input-group" style="display:none; margin-top:0.75rem;">
                            <input type="text" id="custom-api-url" placeholder="请输入 API 地址 (如: https://example.com/ips.txt)" style="font-size:16px;">
                            <div style="font-size:0.75rem; color:var(--text-light); margin-top:0.25rem;">支持格式: 纯文本 IP/CIDR (换行分隔)</div>
                        </div>
                    </div>
                    <div class="form-group">
                        <label>测速端口</label>
                        <select id="port-select">
                            <option value="443">443 (HTTPS)</option>
                            <option value="2053">2053 (HTTPS)</option>
                            <option value="2083">2083 (HTTPS)</option>
                            <option value="2087">2087 (HTTPS)</option>
                            <option value="2096">2096 (HTTPS)</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label>本地文件</label>
                        <div style="display:flex; gap:0.5rem;">
                            <input type="file" id="local-file-input" accept=".txt,.json,.csv,.conf,.list" style="display:none;" onchange="handleFileUpload(this.files)">
                            <button class="btn btn-secondary" onclick="document.getElementById('local-file-input').click()" style="width:100%; padding: 0.75rem;"><i class="fas fa-upload"></i> 选择文件</button>
                        </div>
                    </div>
                </div>
                <div class="grid-2" style="margin-top:1rem;">
                    <div class="form-group">
                        <label>测试数量</label>
                        <input type="number" id="count-input" value="50" min="1" max="500">
                    </div>
                    <div class="form-group">
                        <label>并发线程</label>
                        <input type="number" id="concurrency-input" value="6" min="1" max="20">
                    </div>
                </div>
                
                <div style="margin-top:1rem; display:none;" id="saved-files-wrapper">
                    <label>已保存的列表</label>
                    <div style="display:flex; gap:0.5rem;">
                        <select id="saved-files-select" onchange="handleSavedFileSelect(this)"></select>
                        <button class="btn btn-secondary" style="width:auto; padding:0 0.75rem;" onclick="deleteSavedFile()" id="delete-btn" disabled><i class="fas fa-trash"></i></button>
                    </div>
                </div>
            </div>
        </div>

        <div class="card" id="result-card">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:1rem;">
                <h3><i class="fas fa-list-ul" style="color:#8b5cf6"></i> 测速结果</h3>
                <span id="ip-display-info" style="font-size:0.85rem; color:var(--text-light);"></span>
            </div>
            
            <div id="region-filter" style="margin-bottom:1rem; display:none; gap:0.5rem; flex-wrap:wrap;"></div>
            
            <div class="ip-list" id="ip-list">
                <div style="text-align:center; color:var(--text-light); padding:2rem;">请配置参数并点击"开始测速"</div>
            </div>
            
            <div style="margin-top:1rem; display:none; text-align:center;" id="show-more-section">
                <button class="btn btn-secondary" style="width:auto;" onclick="toggleShowMore()" id="show-more-btn">显示更多</button>
            </div>

            <div class="btn-group">
                <button class="btn" style="flex:1; background:linear-gradient(135deg, #3b82f6 0%, #2563eb 100%);" id="replace-cf-btn" onclick="replaceCFIPs()" disabled>
                    <i class="fas fa-exchange-alt"></i> 替换优选 IP
                </button>
                <button class="btn" style="flex:1; background:linear-gradient(135deg, #0ea5e9 0%, #0284c7 100%);" id="append-cf-btn" onclick="appendCFIPs()" disabled>
                    <i class="fas fa-plus"></i> 追加优选 IP
                </button>
                <button class="btn" style="flex:1; background:linear-gradient(135deg, #d946ef 0%, #c026d3 100%);" id="replace-fd-btn" onclick="replaceFDIPs()" disabled>
                    <i class="fas fa-sync"></i> 替换反代 IP
                </button>
                <button class="btn" style="flex:1; background:linear-gradient(135deg, #ec4899 0%, #db2777 100%);" id="append-fd-btn" onclick="appendFDIPs()" disabled>
                    <i class="fas fa-folder-plus"></i> 追加反代 IP
                </button>
            </div>
        </div>
    </div>

    <div style="position: fixed; bottom: 2rem; left: 0; right: 0; display: flex; justify-content: center; pointer-events: none; z-index: 100;">
        <button class="btn" id="test-btn" onclick="startTest()" style="pointer-events: auto; box-shadow: 0 10px 30px rgba(79, 70, 229, 0.4); width: auto; padding: 1rem 3rem; border-radius: 2rem;">
            <i class="fas fa-play"></i> 开始测速
        </button>
    </div>

<script>
const LATENCY_CALIBRATION_FACTOR = 0.25;
function calibrateLatency(rawLatency) { return Math.max(1, Math.round(rawLatency * LATENCY_CALIBRATION_FACTOR)); }
const LocalStorageKeys = { SAVED_FILES: 'cf-ip-saved-files', FILE_PREFIX: 'cf-ip-file-' };
let originalIPs = [], testResults = [], displayedResults = [], showingAll = false, currentDisplayType = 'loading', cloudflareLocations = {};
const StorageKeys = { PORT: 'cf-ip-test-port', IP_SOURCE: 'cf-ip-test-source', COUNT: 'cf-ip-test-count', CONCURRENCY: 'cf-ip-test-concurrency' };
function initializeLocalStorage(){if(!localStorage.getItem(LocalStorageKeys.SAVED_FILES)){localStorage.setItem(LocalStorageKeys.SAVED_FILES,JSON.stringify([]))}updateSavedFilesSelect()}
function updateSavedFilesSelect(){const savedFilesSelect=document.getElementById('saved-files-select');const savedFiles=JSON.parse(localStorage.getItem(LocalStorageKeys.SAVED_FILES)||'[]');const wrapper=document.getElementById('saved-files-wrapper');if(savedFiles.length>0){wrapper.style.display='block'}else{wrapper.style.display='none'}savedFilesSelect.innerHTML='<option value="">-- 选择已保存文件 --</option>';savedFiles.forEach(file=>{const option=document.createElement('option');option.value=file.id;option.textContent=\`\${file.name} (\${file.ipCount}IP)\`;savedFilesSelect.appendChild(option)});updateFileManagementButtons()}
function updateFileManagementButtons(){const savedFilesSelect=document.getElementById('saved-files-select');const deleteBtn=document.getElementById('delete-btn');const hasSelection=savedFilesSelect.value!=='';deleteBtn.disabled=!hasSelection}
function handleSavedFileSelect(select){updateFileManagementButtons();if(select.value){document.getElementById('ip-source-select').value='local';loadSavedFile(select.value)}}
function parseCIDRFormat(cidrString){try{const[network,prefixLength]=cidrString.split('/');const prefix=parseInt(prefixLength);if(isNaN(prefix)||prefix<8||prefix>32){return null}const ipRegex=/^(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})$/;if(!ipRegex.test(network)){return null}const octets=network.split('.').map(Number);for(const octet of octets){if(octet<0||octet>255){return null}}return{network:network,prefixLength:prefix,type:'cidr'}}catch(error){return null}}
function generateIPsFromCIDR(cidr,maxIPs=100){try{const[network,prefixLength]=cidr.split('/');const prefix=parseInt(prefixLength);const ipToInt=(ip)=>{return ip.split('.').reduce((acc,octet)=>(acc<<8)+parseInt(octet),0)>>>0};const intToIP=(int)=>{return[(int>>>24)&255,(int>>>16)&255,(int>>>8)&255,int&255].join('.')};const networkInt=ipToInt(network);const hostBits=32-prefix;const numHosts=Math.pow(2,hostBits);if(numHosts<=2){return[]}const maxHosts=numHosts-2;const actualCount=Math.min(maxIPs,maxHosts);const ips=new Set();if(maxHosts<=0){return[]}let attempts=0;const maxAttempts=actualCount*10;while(ips.size<actualCount&&attempts<maxAttempts){const randomOffset=Math.floor(Math.random()*maxHosts)+1;const randomIP=intToIP(networkInt+randomOffset);ips.add(randomIP);attempts++}return Array.from(ips)}catch(error){return[]}}
function handleFileUpload(files){if(files.length===0)return;const file=files[0];const reader=new FileReader();reader.onload=function(e){const content=e.target.result;const fileName=file.name.replace(/\\.[^/.]+$/,"");const targetPort=document.getElementById('port-select').value;const parsedIPs=parseFileContent(content,targetPort);if(parsedIPs.length===0){showToast('未能在文件中找到有效的IP地址','error');return}saveFileToLocalStorage(fileName,parsedIPs,content);document.getElementById('ip-source-select').value='local';loadIPsFromArray(parsedIPs);showToast(\`成功加载 \${parsedIPs.length} 个IP\`,'success')};reader.onerror=function(){showToast('文件读取失败','error')};reader.readAsText(file)}
function parseFileContent(content,targetPort){const lines=content.split('\\n');const ips=new Set();const userCount=parseInt(document.getElementById('count-input').value)||50;lines.forEach(line=>{line=line.trim();if(!line||line.startsWith('#')||line.startsWith('//'))return;const cidrInfo=parseCIDRFormat(line);if(cidrInfo){const maxIPsPerCIDR=Math.ceil(userCount/lines.length);const ipsFromCIDR=generateIPsFromCIDR(line,maxIPsPerCIDR);ipsFromCIDR.forEach(ip=>{const formattedIP=\`\${ip}:\${targetPort}\`;ips.add(formattedIP)});return}const parsedIP=parseIPLine(line,targetPort);if(parsedIP){if(Array.isArray(parsedIP)){parsedIP.forEach(ip=>ips.add(ip))}else{ips.add(parsedIP)}}});const ipArray=Array.from(ips);return userCount<ipArray.length?ipArray.slice(0,userCount):ipArray}
function parseIPLine(line,targetPort){try{let ip='';let port=targetPort;let comment='';let mainPart=line;if(line.includes('#')){const parts=line.split('#');mainPart=parts[0].trim();comment=parts.slice(1).join('#').trim()}if(mainPart.includes(':')){const parts=mainPart.split(':');if(parts.length===2){ip=parts[0].trim();port=parts[1].trim()}else{return null}}else{ip=mainPart.trim()}if(!isValidIP(ip)){return null}const portNum=parseInt(port);if(isNaN(portNum)||portNum<1||portNum>65535){return null}if(comment){return\`\${ip}:\${port}#\${comment}\`}else{return\`\${ip}:\${port}\`}}catch(error){return null}}
function isValidIP(ip){const ipv4Regex=/^(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})$/;const match=ip.match(ipv4Regex);if(match){for(let i=1;i<=4;i++){const num=parseInt(match[i]);if(num<0||num>255){return false}}return true}return false}
function saveFileToLocalStorage(fileName,ips,originalContent){const fileId='file_'+Date.now();const fileData={id:fileId,name:fileName,ips:ips,content:originalContent,ipCount:ips.length,timestamp:Date.now()};localStorage.setItem(LocalStorageKeys.FILE_PREFIX+fileId,JSON.stringify(fileData));const savedFiles=JSON.parse(localStorage.getItem(LocalStorageKeys.SAVED_FILES)||'[]');savedFiles.push({id:fileId,name:fileName,ipCount:ips.length,timestamp:Date.now()});localStorage.setItem(LocalStorageKeys.SAVED_FILES,JSON.stringify(savedFiles));updateSavedFilesSelect();document.getElementById('saved-files-select').value=fileId;updateFileManagementButtons()}
function loadSavedFile(fileId){if(!fileId)return;const fileData=localStorage.getItem(LocalStorageKeys.FILE_PREFIX+fileId);if(!fileData){showToast('文件不存在','error');return}const parsedData=JSON.parse(fileData);const currentPort=document.getElementById('port-select').value;const updatedIPs=parsedData.ips.map(ip=>updateIPPort(ip,currentPort));document.getElementById('ip-source-select').value='local';loadIPsFromArray(updatedIPs);showToast(\`已加载 "\${parsedData.name}"\`,'success')};
function updateIPPort(ipString,newPort){try{let ip='';let port=newPort;let comment='';if(ipString.includes('#')){const parts=ipString.split('#');const mainPart=parts[0].trim();comment=parts[1].trim();if(mainPart.includes(':')){const ipPortParts=mainPart.split(':');if(ipPortParts.length===2){ip=ipPortParts[0].trim()}else{return ipString}}else{ip=mainPart}}else{if(ipString.includes(':')){const ipPortParts=ipString.split(':');if(ipPortParts.length===2){ip=ipPortParts[0].trim()}else{return ipString}}else{ip=ipString}}if(comment){return\`\${ip}:\${port}#\${comment}\`}else{return\`\${ip}:\${port}\`}}catch(error){return ipString}}
function loadIPsFromArray(ips){originalIPs=ips;testResults=[];displayedResults=[];showingAll=false;currentDisplayType='loading';document.getElementById('ip-count').textContent=ips.length;displayLoadedIPs();document.getElementById('test-btn').disabled=false;updateButtonStates()}
function deleteSavedFile(){const savedFilesSelect=document.getElementById('saved-files-select');const fileId=savedFilesSelect.value;if(!fileId)return;if(!confirm('确定删除？'))return;const savedFiles=JSON.parse(localStorage.getItem(LocalStorageKeys.SAVED_FILES)||'[]');const filteredFiles=savedFiles.filter(file=>file.id!==fileId);localStorage.setItem(LocalStorageKeys.SAVED_FILES,JSON.stringify(filteredFiles));localStorage.removeItem(LocalStorageKeys.FILE_PREFIX+fileId);updateSavedFilesSelect();updateFileManagementButtons();showToast('文件已删除','success')}
async function loadCloudflareLocations(){try{const response=await fetch(atob('aHR0cHM6Ly9zcGVlZC5jbG91ZGZsYXJlLmNvbS9sb2NhdGlvbnM='));if(response.ok){const locations=await response.json();cloudflareLocations={};locations.forEach(location=>{cloudflareLocations[location.iata]=location})}}catch(error){}}
function initializeSettings(){
    const portSelect=document.getElementById('port-select');
    const ipSourceSelect=document.getElementById('ip-source-select');
    const countInput=document.getElementById('count-input');
    const concurrencyInput=document.getElementById('concurrency-input');
    const customApiGroup = document.getElementById('custom-api-input-group');
    const customApiInput = document.getElementById('custom-api-url');
    const savedPort=localStorage.getItem(StorageKeys.PORT);
    const savedIPSource=localStorage.getItem(StorageKeys.IP_SOURCE);
    const savedCount=localStorage.getItem(StorageKeys.COUNT);
    const savedConcurrency=localStorage.getItem(StorageKeys.CONCURRENCY);
    const savedCustomUrl = localStorage.getItem('cf-ip-custom-url');
    if(savedPort)portSelect.value=savedPort;
    if(savedIPSource) {
        ipSourceSelect.value=savedIPSource;
        if(savedIPSource === 'custom') customApiGroup.style.display = 'block';
    }
    if(savedCount)countInput.value=savedCount;
    if(savedConcurrency)concurrencyInput.value=savedConcurrency;
    if(savedCustomUrl) customApiInput.value = savedCustomUrl;
    portSelect.addEventListener('change',function(){localStorage.setItem(StorageKeys.PORT,this.value);if(originalIPs.length>0){const newPort=this.value;const updatedIPs=originalIPs.map(ip=>updateIPPort(ip,newPort));loadIPsFromArray(updatedIPs)}});
    ipSourceSelect.addEventListener('change',function(){
        localStorage.setItem(StorageKeys.IP_SOURCE,this.value);
        if(this.value === 'custom') {
            customApiGroup.style.display = 'block';
            customApiInput.focus();
        } else {
            customApiGroup.style.display = 'none';
        }
    });
    customApiInput.addEventListener('input', function() { localStorage.setItem('cf-ip-custom-url', this.value.trim()); });
    countInput.addEventListener('change',function(){localStorage.setItem(StorageKeys.COUNT,this.value)});
    concurrencyInput.addEventListener('change',function(){localStorage.setItem(StorageKeys.CONCURRENCY,this.value)})
}
document.addEventListener('DOMContentLoaded',async function(){await loadCloudflareLocations();initializeSettings();initializeLocalStorage()});
function shuffleArray(array){const newArray=[...array];for(let i=newArray.length-1;i>0;i--){const j=Math.floor(Math.random()*(i+1));[newArray[i],newArray[j]]=[newArray[j],newArray[i]]}return newArray}
function toggleShowMore(){if(currentDisplayType==='testing'){return}showingAll=!showingAll;if(currentDisplayType==='loading'){displayLoadedIPs()}else if(currentDisplayType==='results'){displayResults()}}
function displayLoadedIPs(){const ipList=document.getElementById('ip-list');const showMoreSection=document.getElementById('show-more-section');const showMoreBtn=document.getElementById('show-more-btn');const ipDisplayInfo=document.getElementById('ip-display-info');if(originalIPs.length===0){ipList.innerHTML='<div style="text-align:center;padding:1rem;">加载IP列表失败</div>';showMoreSection.style.display='none';ipDisplayInfo.textContent='';return}const displayCount=showingAll?originalIPs.length:Math.min(originalIPs.length,16);const displayIPs=originalIPs.slice(0,displayCount);if(originalIPs.length<=16){ipDisplayInfo.textContent=\`共 \${originalIPs.length} 个IP\`;showMoreSection.style.display='none'}else{ipDisplayInfo.textContent=\`显示 \${displayCount} / \${originalIPs.length} 个IP\`;if(currentDisplayType!=='testing'){showMoreSection.style.display='block';showMoreBtn.textContent=showingAll?'显示更少':'显示更多';showMoreBtn.disabled=false}else{showMoreSection.style.display='none'}}ipList.innerHTML=displayIPs.map(ip=>\`<div class="ip-item"><span>\${ip}</span></div>\`).join('')}
function updateButtonStates(){const replaceCfBtn=document.getElementById('replace-cf-btn');const appendCfBtn=document.getElementById('append-cf-btn');const replaceFdBtn=document.getElementById('replace-fd-btn');const appendFdBtn=document.getElementById('append-fd-btn');const hasResults=displayedResults.length>0;replaceCfBtn.disabled=!hasResults;appendCfBtn.disabled=!hasResults;replaceFdBtn.disabled=!hasResults;appendFdBtn.disabled=!hasResults}
function disableAllButtons(){document.querySelectorAll('button, select, input').forEach(el=>el.disabled=true)}
function enableButtons(){document.querySelectorAll('button, select, input').forEach(el=>{if(el.id!=='delete-btn')el.disabled=false});updateButtonStates();updateFileManagementButtons()}
function formatIPForSave(result){const port=document.getElementById('port-select').value;let ip=result.ip;let countryCode=result.locationCode||'XX';let countryName=getCountryName(countryCode);return\`\${ip}:\${port}#\${countryName}|\${countryCode}\`}
function formatIPForFD(result){const port=document.getElementById('port-select').value;let countryCode=result.locationCode||'XX';let countryName=getCountryName(countryCode);return\`\${result.ip}:\${port}#\${countryName}\`}
function getCountryName(countryCode){const countryMap={'US':'美国','SG':'新加坡','DE':'德国','JP':'日本','KR':'韩国','HK':'香港','TW':'台湾','GB':'英国','FR':'法国','IN':'印度','BR':'巴西','CA':'加拿大','AU':'澳大利亚','NL':'荷兰','CH':'瑞士','SE':'瑞典','IT':'意大利','ES':'西班牙','RU':'俄罗斯','ZA':'南非','MX':'墨西哥','MY':'马来西亚','TH':'泰国','ID':'印度尼西亚','VN':'越南','PH':'菲律宾','TR':'土耳其','SA':'沙特阿拉伯','AE':'阿联酋','EG':'埃及','NG':'尼日利亚','IL':'以色列','PL':'波兰','UA':'乌克兰','CZ':'捷克','RO':'罗马尼亚','GR':'希腊','PT':'葡萄牙','DK':'丹麦','FI':'芬兰','NO':'挪威','AT':'奥地利','BE':'比利时','IE':'爱尔兰','LU':'卢森堡','CY':'塞浦路斯','MT':'马耳他','IS':'冰岛','CN':'中国'};return countryMap[countryCode]||countryCode}
async function saveIPs(action,formatFunction,buttonId,successMessage){let ipsToSave=[];if(document.getElementById('region-filter')&&document.getElementById('region-filter').style.display!=='none'&&document.querySelector('.region-btn.active').getAttribute('data-region')!=='all'){ipsToSave=displayedResults}else{ipsToSave=testResults}if(ipsToSave.length===0){showToast('无有效IP可保存','error');return}const button=document.getElementById(buttonId);const originalText=button.innerHTML;disableAllButtons();button.textContent='保存中...';try{const saveCount=Math.min(ipsToSave.length,6);const ips=ipsToSave.slice(0,saveCount).map(result=>formatFunction(result));const response=await fetch(\`?action=\${action}\`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ips})});const data=await response.json();if(data.success){showToast(successMessage+' (前'+saveCount+'个)','success')}else{showToast(data.error||'保存失败','error')}}catch(error){showToast('保存失败','error')}finally{button.innerHTML=originalText;enableButtons()}}
async function replaceCFIPs(){await saveIPs('replace-cf',formatIPForSave,'replace-cf-btn','已替换优选 IP')}
async function appendCFIPs(){await saveIPs('append-cf',formatIPForSave,'append-cf-btn','已追加优选 IP')}
async function replaceFDIPs(){await saveIPs('replace-fd',formatIPForFD,'replace-fd-btn','已替换反代 IP')}
async function appendFDIPs(){await saveIPs('append-fd',formatIPForFD,'append-fd-btn','已追加反代 IP')}
function isRetriableError(error){if(!error)return false;const errorMessage=error.message||error.toString();const retryablePatterns=['timeout','abort','network','fetch','failed','load failed','connection','socket','reset'];const nonRetryablePatterns=['HTTP 4','HTTP 5','404','500','502','503','certificate','SSL','TLS','CORS','blocked'];const isRetryable=retryablePatterns.some(pattern=>errorMessage.toLowerCase().includes(pattern.toLowerCase()));const isNonRetryable=nonRetryablePatterns.some(pattern=>errorMessage.toLowerCase().includes(pattern.toLowerCase()));return isRetryable&&!isNonRetryable}
async function smartRetry(operation,maxAttempts=3,baseDelay=200,timeout=5000){let lastError;for(let attempt=1;attempt<=maxAttempts;attempt++){const controller=new AbortController();const timeoutId=setTimeout(()=>controller.abort(),timeout);try{const result=await Promise.race([operation(controller.signal),new Promise((_,reject)=>setTimeout(()=>reject(new Error('Operation timeout')),timeout))]);clearTimeout(timeoutId);if(result&&result.success!==false){return result}if(result&&result.error){if(result.error.includes('HTTP 4')||result.error.includes('HTTP 5')){return result}}lastError=result?result.error:new Error('Operation failed')}catch(error){clearTimeout(timeoutId);lastError=error;if(!error.message.includes('network')&&!error.message.includes('timeout')&&!error.message.includes('fetch')){throw error}}if(attempt<maxAttempts){const delay=baseDelay*Math.pow(2,attempt-1)+Math.random()*100;await new Promise(resolve=>setTimeout(resolve,delay))}}throw lastError}
async function testIP(ip,port){const timeout=3000;const parsedIP=parseIPFormat(ip,port);if(!parsedIP){return null}const latencyResult=await smartRetry((signal)=>singleLatencyTest(parsedIP.host,parsedIP.port,timeout,signal),2,200,timeout+1000);if(!latencyResult){return null}const locationCode=cloudflareLocations[latencyResult.colo]?cloudflareLocations[latencyResult.colo].cca2:latencyResult.colo;const countryName=getCountryName(locationCode);const typeText=latencyResult.type==='official'?'官方':'反代';const calibratedLatency=calibrateLatency(latencyResult.latency);let display;if(latencyResult.type==='official'){display=\`\${parsedIP.host}:\${parsedIP.port}#\${countryName}|\${locationCode} \${typeText} \${calibratedLatency}ms\`}else{display=\`\${parsedIP.host}:\${parsedIP.port}#\${countryName} \${typeText} \${calibratedLatency}ms\`}return{ip:parsedIP.host,port:parsedIP.port,latency:latencyResult.latency,calibratedLatency:calibratedLatency,colo:latencyResult.colo,type:latencyResult.type,locationCode:locationCode,comment:\`\${countryName} \${typeText}\`,display:display}}
function parseIPFormat(ipString,defaultPort){try{let host,port,comment;let mainPart=ipString;if(ipString.includes('#')){const parts=ipString.split('#');mainPart=parts[0];comment=parts[1]}if(mainPart.includes(':')){const parts=mainPart.split(':');host=parts[0];port=parseInt(parts[1])}else{host=mainPart;port=parseInt(defaultPort)}if(!host||!port||isNaN(port)){return null}return{host:host.trim(),port:port,comment:comment?comment.trim():null}}catch(error){return null}}
async function singleLatencyTest(ip,port,timeout,abortSignal){const controller=new AbortController();const timeoutId=setTimeout(()=>controller.abort(),timeout);if(abortSignal){abortSignal.addEventListener('abort',()=>controller.abort())}const startTime=Date.now();try{const parts=ip.split('.').map(part=>{const hex=parseInt(part,10).toString(16);return hex.length===1?'0'+hex:hex});const nip=parts.join('');const response=await fetch(\`https://\${nip}.${nipDomain}:\${port}/cdn-cgi/trace\`,{signal:controller.signal,mode:'cors'});clearTimeout(timeoutId);if(response.status===200){const latency=Date.now()-startTime;const responseText=await response.text();const traceData=parseTraceResponse(responseText);if(traceData&&traceData.ip&&traceData.colo){const responseIP=traceData.ip;let ipType='official';if(responseIP.includes(':')||responseIP===ip){ipType='proxy'}return{ip:ip,port:port,latency:latency,colo:traceData.colo,type:ipType,responseIP:responseIP}}}return null}catch(error){clearTimeout(timeoutId);const latency=Date.now()-startTime;if(latency<timeout-100){return{ip:ip,port:port,latency:latency,colo:'UNKNOWN',type:'unknown',responseIP:null}}return null}}
function parseTraceResponse(responseText){try{const lines=responseText.split('\\n');const data={};for(const line of lines){const trimmedLine=line.trim();if(trimmedLine&&trimmedLine.includes('=')){const[key,value]=trimmedLine.split('=',2);data[key]=value}}return data}catch(error){return null}}
async function testIPsWithConcurrency(ips,port,maxConcurrency=6){const results=[];const totalIPs=ips.length;let completedTests=0;let activeWorkers=0;let currentIndex=0;let successCount=0;let failCount=0;const validCountLabel=document.getElementById('result-count-val');const progressBarSuccess=document.getElementById('progress-bar-success');const progressBarFail=document.getElementById('progress-bar-fail');const progressText=document.getElementById('progress-text');const progressPercent=document.getElementById('progress-percent');const workers=Array(Math.min(maxConcurrency,ips.length)).fill().map(async(_,workerId)=>{while(currentIndex<ips.length){const index=currentIndex++;if(index>=ips.length)break;const ip=ips[index];activeWorkers++;try{await new Promise(resolve=>setTimeout(resolve,Math.random()*100));const result=await testIP(ip,port);if(result){results.push(result);successCount++}else{failCount++}}catch(error){failCount++}finally{activeWorkers--;completedTests++;const successPercentVal=(successCount/totalIPs)*100;const failPercentVal=(failCount/totalIPs)*100;progressBarSuccess.style.width=successPercentVal+'%';progressBarFail.style.width=failPercentVal+'%';validCountLabel.textContent=successCount;progressPercent.textContent=Math.round((completedTests/totalIPs)*100)+'%';progressText.textContent=\`进度: \${completedTests}/\${totalIPs}\`;await new Promise(resolve=>setTimeout(resolve,0))}}});await Promise.all(workers);return results}
function displayResults(){const ipList=document.getElementById('ip-list');const resultCountVal=document.getElementById('result-count-val');const showMoreSection=document.getElementById('show-more-section');const showMoreBtn=document.getElementById('show-more-btn');const ipDisplayInfo=document.getElementById('ip-display-info');if(testResults.length===0){ipList.innerHTML='<div style="text-align:center;padding:1rem;">无有效IP</div>';resultCountVal.textContent='0';ipDisplayInfo.textContent='';showMoreSection.style.display='none';displayedResults=[];updateButtonStates();return}const maxDisplayCount=showingAll?testResults.length:Math.min(testResults.length,16);displayedResults=testResults.slice(0,maxDisplayCount);resultCountVal.textContent=testResults.length;if(testResults.length<=16){ipDisplayInfo.textContent=\`共 \${testResults.length} 个结果\`;showMoreSection.style.display='none'}else{ipDisplayInfo.textContent=\`显示 \${maxDisplayCount} / \${testResults.length} 个结果\`;showMoreSection.style.display='block';showMoreBtn.textContent=showingAll?'显示更少':'显示更多';showMoreBtn.disabled=false}const resultsHTML=displayedResults.map(result=>{const calibratedLatency=result.calibratedLatency||calibrateLatency(result.latency);let latencyClass='good-latency';if(calibratedLatency>200)latencyClass='bad-latency';else if(calibratedLatency>100)latencyClass='medium-latency';return\`<div class="ip-item"><span class="\${latencyClass}">\${result.display}</span></div>\`}).join('');ipList.innerHTML=resultsHTML;updateButtonStates()}
function createRegionFilter(){const uniqueRegions=[...new Set(testResults.map(result=>result.locationCode))];uniqueRegions.sort();const filterContainer=document.getElementById('region-filter');if(!filterContainer)return;if(uniqueRegions.length===0){filterContainer.style.display='none';return}let filterHTML='<button class="btn btn-secondary region-btn active" style="width:auto; padding:0.25rem 0.75rem; font-size:0.85rem;" data-region="all">全部</button>';uniqueRegions.forEach(region=>{const count=testResults.filter(r=>r.locationCode===region).length;filterHTML+=\`<button class="btn btn-secondary region-btn" style="width:auto; padding:0.25rem 0.75rem; font-size:0.85rem;" data-region="\${region}">\${region}(\${count})</button>\`});filterContainer.innerHTML=filterHTML;filterContainer.style.display='flex';document.querySelectorAll('.region-btn').forEach(button=>{button.addEventListener('click',function(e){e.preventDefault();document.querySelectorAll('.region-btn').forEach(btn=>{btn.classList.remove('active');btn.style.background='transparent';btn.style.color='var(--text)'});this.classList.add('active');this.style.background='var(--primary)';this.style.color='white';const selectedRegion=this.getAttribute('data-region');if(selectedRegion==='all'){displayedResults=[...testResults]}else{displayedResults=testResults.filter(result=>result.locationCode===selectedRegion)}showingAll=false;displayFilteredResults()})})}
function displayFilteredResults(){const ipList=document.getElementById('ip-list');const showMoreSection=document.getElementById('show-more-section');const showMoreBtn=document.getElementById('show-more-btn');const ipDisplayInfo=document.getElementById('ip-display-info');if(displayedResults.length===0){ipList.innerHTML='<div style="text-align:center;padding:1rem;">无结果</div>';showMoreSection.style.display='none';updateButtonStates();return}const maxDisplayCount=showingAll?displayedResults.length:Math.min(displayedResults.length,16);const currentResults=displayedResults.slice(0,maxDisplayCount);const filteredCount=displayedResults.length;if(filteredCount<=16){ipDisplayInfo.textContent=\`筛选: \${filteredCount} 个\`;showMoreSection.style.display='none'}else{ipDisplayInfo.textContent=\`显示 \${maxDisplayCount} / \${filteredCount} 个\`;showMoreSection.style.display='block';showMoreBtn.textContent=showingAll?'显示更少':'显示更多'}const resultsHTML=currentResults.map(result=>{const calibratedLatency=result.calibratedLatency||calibrateLatency(result.latency);let latencyClass='good-latency';if(calibratedLatency>200)latencyClass='bad-latency';else if(calibratedLatency>100)latencyClass='medium-latency';return\`<div class="ip-item"><span class="\${latencyClass}">\${result.display}</span></div>\`}).join('');ipList.innerHTML=resultsHTML;updateButtonStates()}
async function loadIPs(ipSource,port,count){try{const response=await fetch(\`?loadIPs=\${ipSource}&port=\${port}&count=\${count}\`,{method:'GET'});if(!response.ok){throw new Error('Failed to load IPs')}const data=await response.json();return data.ips||[]}catch(error){return[]}}
function scrollToElement(id){const el=document.getElementById(id);if(el){el.scrollIntoView({behavior:'smooth',block:'start'})}}
async function startTest(){const testBtn=document.getElementById('test-btn');const portSelect=document.getElementById('port-select');const ipSourceSelect=document.getElementById('ip-source-select');const countInput=document.getElementById('count-input');const concurrencyInput=document.getElementById('concurrency-input');const progressBarSuccess=document.getElementById('progress-bar-success');const progressBarFail=document.getElementById('progress-bar-fail');const progressText=document.getElementById('progress-text');const ipList=document.getElementById('ip-list');const ipCount=document.getElementById('ip-count');const resultCountVal=document.getElementById('result-count-val');const showMoreSection=document.getElementById('show-more-section');const selectedPort=portSelect.value;const selectedIPSource=ipSourceSelect.value;const selectedCount=parseInt(countInput.value)||50;const selectedConcurrency=parseInt(concurrencyInput.value)||6;localStorage.setItem(StorageKeys.PORT,selectedPort);localStorage.setItem(StorageKeys.IP_SOURCE,selectedIPSource);localStorage.setItem(StorageKeys.COUNT,selectedCount);localStorage.setItem(StorageKeys.CONCURRENCY,selectedConcurrency);testBtn.disabled=true;testBtn.innerHTML='<i class="fas fa-spinner fa-spin"></i> 处理中...';disableAllButtons();testResults=[];displayedResults=[];showingAll=false;currentDisplayType='loading';ipList.innerHTML='<div style="text-align:center;padding:1rem;">正在加载IP列表...</div>';showMoreSection.style.display='none';progressBarSuccess.style.width='0%';progressBarFail.style.width='0%';resultCountVal.textContent='0';if(window.innerWidth<768)scrollToElement('status-card');let ipSourceName='';
let finalSourceParam = selectedIPSource;
switch(selectedIPSource){case'official':ipSourceName='Official';break;case'as13335':ipSourceName='AS13335';break;case'as209242':ipSourceName='AS209242';break;case'as24429':ipSourceName='Alibaba';break;case'as199524':ipSourceName='G-Core';break;case'local':ipSourceName='本地';break;case'custom':ipSourceName='远程API';const customUrl=document.getElementById('custom-api-url').value.trim();if(!customUrl||(!customUrl.startsWith('http://')&&!customUrl.startsWith('https://'))){showToast('请输入有效的 HTTP/HTTPS API 地址','error');testBtn.disabled=false;testBtn.innerHTML='<i class="fas fa-play"></i> 开始测速';enableButtons();return}finalSourceParam=customUrl;break;default:ipSourceName='未知'}progressText.textContent='正在加载列表...';if(selectedIPSource==='local'){const savedFilesSelect=document.getElementById('saved-files-select');const fileId=savedFilesSelect.value;if(!fileId){if(originalIPs.length===0){showToast('请先上传文件','error');testBtn.disabled=false;testBtn.innerHTML='<i class="fas fa-play"></i> 开始测速';enableButtons();progressText.textContent='未就绪';return}const allIPs=[...originalIPs];const shuffled=shuffleArray(allIPs);originalIPs=selectedCount<shuffled.length?shuffled.slice(0,selectedCount):shuffled}else{const fileData=localStorage.getItem(LocalStorageKeys.FILE_PREFIX+fileId);if(!fileData){showToast('文件失效','error');testBtn.disabled=false;testBtn.innerHTML='<i class="fas fa-play"></i> 开始测速';enableButtons();return}const parsedData=JSON.parse(fileData);const currentPort=selectedPort;const parsedIPs=parseFileContent(parsedData.content,currentPort);if(parsedIPs.length===0){showToast('无有效IP','error');testBtn.disabled=false;testBtn.innerHTML='<i class="fas fa-play"></i> 开始测速';enableButtons();return}const shuffled=shuffleArray(parsedIPs);originalIPs=selectedCount<shuffled.length?shuffled.slice(0,selectedCount):shuffled}}else{originalIPs=await loadIPs(finalSourceParam,selectedPort,selectedCount)}if(originalIPs.length===0){ipList.innerHTML='<div style="text-align:center;padding:1rem;">加载失败</div>';ipCount.textContent='0';testBtn.disabled=false;testBtn.innerHTML='<i class="fas fa-play"></i> 开始测速';enableButtons();progressText.textContent='失败';return}ipCount.textContent=originalIPs.length;displayLoadedIPs();testBtn.innerHTML='<i class="fas fa-circle-notch fa-spin"></i> 测速中...';progressText.textContent='测速进行中...';currentDisplayType='testing';showMoreSection.style.display='none';const results=await testIPsWithConcurrency(originalIPs,selectedPort,selectedConcurrency);testResults=results.sort((a,b)=>a.latency-b.latency);currentDisplayType='results';showingAll=false;displayResults();createRegionFilter();testBtn.disabled=false;testBtn.innerHTML='<i class="fas fa-redo"></i> 重新测速';enableButtons();progressText.textContent='测速完成';scrollToElement('result-card')}
</script>
</body>
</html>`;

    const response = new Response(html, {
        headers: {
            'Content-Type': 'text/html; charset=UTF-8',
        },
    });

    return response;
}
