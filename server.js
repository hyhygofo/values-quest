// values-quest 登录服务（本地 / Vercel 通用）
// 零依赖：仅用 Node 内置模块。托管 index.html + 飞书 OAuth 授权登录。
// 状态层 serverless 友好：会话用签名 Cookie，state 用签名短时令牌，禁用列表走环境变量。
const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// ---- 读取 .env（本地开发用；Vercel 上由平台环境变量提供，文件不存在则忽略）----
const ENV = {};
const envPath = path.join(__dirname, '.env');
if (fs.existsSync(envPath)) {
  for (const line of fs.readFileSync(envPath, 'utf8').split('\n')) {
    const m = line.match(/^\s*([A-Z_]+)\s*=\s*(.*)\s*$/);
    if (m) ENV[m[1]] = m[2];
  }
}
const APP_ID = ENV.FEISHU_APP_ID || process.env.FEISHU_APP_ID;
const APP_SECRET = ENV.FEISHU_APP_SECRET || process.env.FEISHU_APP_SECRET;
const PORT = Number(ENV.PORT || process.env.PORT || 3000);
// BASE_URL：优先 env 覆盖；否则 Vercel 用 VERCEL_URL；否则回退 localhost
const BASE_URL = ENV.BASE_URL || process.env.BASE_URL
  || ('https://' + (process.env.VERCEL_URL || `localhost:${PORT}`));
// 飞书重定向 URI 必须精确匹配开放平台白名单。
const REDIRECT_URI = BASE_URL.replace(/\/$/, '') + '/auth/feishu/callback';
if (!APP_ID || !APP_SECRET) { console.error('缺少 FEISHU_APP_ID / FEISHU_APP_SECRET'); process.exit(1); }

// ---- 无状态签名工具：用 APP_SECRET 作为 HMAC key（同源 secret，无需额外环境变量）----
function b64url(buf) {
  return Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function sign(obj) {
  const payload = b64url(JSON.stringify(obj));
  const sig = crypto.createHmac('sha256', APP_SECRET).update(payload).digest('hex');
  return payload + '.' + sig;
}
function unsign(token) {
  if (!token || typeof token !== 'string' || !token.includes('.')) return null;
  const [payload, sig] = token.split('.');
  const expected = crypto.createHmac('sha256', APP_SECRET).update(payload).digest('hex');
  const a = Buffer.from(sig); const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try { return JSON.parse(Buffer.from(payload.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString()); }
  catch { return null; }
}
// 禁用用户列表（飞书 open_id），逗号分隔，走环境变量，零外部存储
function disabledList() {
  return (process.env.DISABLED_OPEN_IDS || ENV.DISABLED_OPEN_IDS || '')
    .split(',').map(s => s.trim()).filter(Boolean);
}

function httpsJson(method, url, headers, body) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const data = body ? JSON.stringify(body) : null;
    const req = https.request({ hostname: u.hostname, path: u.pathname + u.search, method,
      headers: Object.assign({ 'Content-Type': 'application/json' }, headers,
        data ? { 'Content-Length': Buffer.byteLength(data) } : {}) }, res => {
      let buf = '';
      res.on('data', c => buf += c);
      res.on('end', () => { try { resolve(JSON.parse(buf)); } catch (e) { reject(e); } });
    });
    req.on('error', reject);
    if (data) req.write(data);
    req.end();
  });
}

function getCookie(req, name) {
  const c = (req.headers.cookie || '').split(';').map(s => s.trim().split('='));
  const hit = c.find(([k]) => k === name);
  return hit ? decodeURIComponent(hit[1]) : null;
}
function send(res, code, body, headers) {
  res.writeHead(code, Object.assign({ 'Content-Type': 'text/html; charset=utf-8' }, headers));
  res.end(body);
}
// 当前登录用户：从签名 Cookie 中恢复（验签失败返回 null）
function currentUser(req) {
  const c = getCookie(req, 'vq_user');
  return c ? unsign(c) : null;
}

const LOGIN_PAGE = (msg) => `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>价值观大冒险 - 登录</title>
<style>body{background:#0a0a2e;color:#fff;display:flex;align-items:center;justify-content:center;min-height:100vh;font-family:'PingFang SC',sans-serif;margin:0}
.card{text-align:center;background:rgba(30,30,80,.6);padding:48px 64px;border-radius:16px;box-shadow:0 0 60px rgba(100,100,255,.3)}
h1{color:#FFD700;margin-bottom:8px}p{color:#aaa;margin-bottom:32px}
a.btn{display:inline-block;padding:14px 40px;border-radius:10px;background:#3370ff;color:#fff;text-decoration:none;font-size:18px;font-weight:bold}
.err{color:#FF6B6B;margin-top:16px;min-height:20px}</style></head><body>
<div class="card"><h1>价值观大冒险</h1><p>GOFO Values Quest · 请使用飞书账号登录</p>
<a class="btn" href="/auth/feishu/login">🚀 飞书登录</a><div class="err">${msg || ''}</div></div></body></html>`;

const handler = async (req, res) => {
  const u = new URL(req.url, BASE_URL);

  // 发起授权：生成签名短时 state（含 10 分钟过期，无需服务端存储）
  if (u.pathname === '/auth/feishu/login') {
    const state = sign({ n: crypto.randomBytes(8).toString('hex'), exp: Date.now() + 10 * 60 * 1000 });
    const authUrl = 'https://accounts.feishu.cn/open-apis/authen/v1/authorize'
      + `?client_id=${APP_ID}&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&state=${state}`;
    res.writeHead(302, { Location: authUrl });
    return res.end();
  }

  // 回调：先校验 state 签名与有效期，再换取用户身份
  if (u.pathname === '/auth/feishu/callback') {
    const state = u.searchParams.get('state');
    const code = u.searchParams.get('code');
    const st = unsign(state);
    if (!st) return send(res, 403, LOGIN_PAGE('登录失败：state 无效，请重新登录'));
    if (Date.now() > st.exp) return send(res, 403, LOGIN_PAGE('登录失败：state 已过期，请重新登录'));
    if (!code) return send(res, 400, LOGIN_PAGE('登录失败：缺少授权码'));
    try {
      const tok = await httpsJson('POST', 'https://open.feishu.cn/open-apis/authen/v2/oauth/token', {}, {
        grant_type: 'authorization_code', client_id: APP_ID, client_secret: APP_SECRET,
        code, redirect_uri: REDIRECT_URI,
      });
      if (tok.code !== 0 || !tok.access_token) return send(res, 401, LOGIN_PAGE('换取令牌失败：' + (tok.error_description || tok.msg || tok.code)));
      const info = await httpsJson('GET', 'https://open.feishu.cn/open-apis/authen/v1/user_info',
        { Authorization: 'Bearer ' + tok.access_token });
      if (info.code !== 0) return send(res, 401, LOGIN_PAGE('获取用户信息失败：' + info.msg));
      const d = info.data;
      // 禁用用户拦截（走环境变量 DISABLED_OPEN_IDS，零外部存储）
      if (disabledList().includes(d.open_id)) {
        return send(res, 403, LOGIN_PAGE(`账号 ${d.name} 已被停用，禁止登录`));
      }
      // 登录身份写入签名 Cookie（HttpOnly，30 天），无需服务端会话存储
      const user = {
        open_id: d.open_id, union_id: d.union_id, name: d.name,
        tenant_key: d.tenant_key || '', // 真实 tenant_key 来自首次登录返回，不编造
        login_at: new Date().toISOString(),
      };
      res.writeHead(302, {
        Location: '/',
        'Set-Cookie': `vq_user=${sign(user)}; HttpOnly; Path=/; SameSite=Lax; Max-Age=${30 * 24 * 3600}`,
      });
      return res.end();
    } catch (e) {
      return send(res, 500, LOGIN_PAGE('登录异常：' + e.message));
    }
  }

  if (u.pathname === '/logout') {
    res.writeHead(302, { Location: '/', 'Set-Cookie': 'vq_user=; Max-Age=0; Path=/' });
    return res.end();
  }

  if (u.pathname === '/api/me') {
    const user = currentUser(req);
    return send(res, user ? 200 : 401,
      JSON.stringify(user ? { ok: true, user } : { ok: false }),
      { 'Content-Type': 'application/json; charset=utf-8' });
  }

  // 静态资源（assets）直接读取返回，提升 Vercel 兼容性
  if (u.pathname.startsWith('/assets/')) {
    const fp = path.join(__dirname, u.pathname);
    const assetsRoot = path.join(__dirname, 'assets');
    if (fp.startsWith(assetsRoot) && fs.existsSync(fp) && fs.statSync(fp).isFile()) {
      const ext = path.extname(fp);
      const ct = { '.js': 'text/javascript', '.css': 'text/css', '.png': 'image/png',
        '.jpg': 'image/jpeg', '.svg': 'image/svg+xml', '.json': 'application/json' }[ext] || 'application/octet-stream';
      return send(res, 200, fs.readFileSync(fp), { 'Content-Type': ct });
    }
    return send(res, 404, 'Not Found');
  }

  // 游戏首页：未登录先看登录页，已登录返回游戏页
  if (u.pathname === '/' || u.pathname === '/index.html') {
    const user = currentUser(req);
    if (!user) return send(res, 200, LOGIN_PAGE());
    return send(res, 200, fs.readFileSync(path.join(__dirname, 'index.html'), 'utf8'));
  }

  send(res, 404, 'Not Found');
};

// 供 Vercel（api/index.js require 本文件）使用
module.exports = handler;

// 本地运行：VERCEL 未设置时才 listen；Vercel 上由平台托管，不自行监听端口
if (!process.env.VERCEL) {
  http.createServer(handler).listen(PORT, () => {
    console.log(`values-quest 服务已启动: ${BASE_URL}`);
    console.log(`飞书回调地址: ${REDIRECT_URI}`);
  });
}
