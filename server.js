// values-quest 本地登录服务（测试环境）
// 零依赖：仅用 Node 内置模块。托管 index.html + 飞书 OAuth 授权登录。
const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// ---- 读取 .env ----
const ENV = {};
const envPath = path.join(__dirname, '.env');
if (fs.existsSync(envPath)) {
  for (const line of fs.readFileSync(envPath, 'utf8').split('\n')) {
    const m = line.match(/^\s*([A-Z_]+)\s*=\s*(.*)\s*$/);
    if (m) ENV[m[1]] = m[2];
  }
}
const APP_ID = ENV.FEISHU_APP_ID;
const APP_SECRET = ENV.FEISHU_APP_SECRET;
const PORT = Number(ENV.PORT || 3000);
const BASE_URL = ENV.BASE_URL || `http://localhost:${PORT}`;
// 飞书重定向 URI 必须精确匹配开放平台白名单。
const REDIRECT_URI = BASE_URL.replace(/\/$/, '') + '/auth/feishu/callback';
if (!APP_ID || !APP_SECRET) { console.error('缺少 FEISHU_APP_ID / FEISHU_APP_SECRET'); process.exit(1); }

// ---- 状态与会话（落盘持久化，一次性 state，可跨进程重启存活）----
const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const STATES_FILE = path.join(DATA_DIR, 'states.json');
const SESSIONS_FILE = path.join(DATA_DIR, 'sessions.json');
fs.mkdirSync(DATA_DIR, { recursive: true });

function loadMap(file) {
  try { return new Map(Object.entries(JSON.parse(fs.readFileSync(file, 'utf8')))); }
  catch { return new Map(); }
}
function saveMap(file, map) {
  fs.writeFileSync(file, JSON.stringify(Object.fromEntries(map)));
}
const states = loadMap(STATES_FILE);     // state -> expireAt
const sessions = loadMap(SESSIONS_FILE); // sid -> { user, createdAt }
// 启动时清理已过期 state
for (const [s, exp] of states) if (Date.now() > exp) states.delete(s);
saveMap(STATES_FILE, states);

function loadUsers() { try { return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8')); } catch { return {}; } }
function saveUsers(u) { fs.writeFileSync(USERS_FILE, JSON.stringify(u, null, 2)); }

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
function currentUser(req) {
  const sid = getCookie(req, 'vq_sid');
  return sid && sessions.get(sid) ? sessions.get(sid).user : null;
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

const server = http.createServer(async (req, res) => {
  const u = new URL(req.url, BASE_URL);

  // 发起授权：生成一次性 state
  if (u.pathname === '/auth/feishu/login') {
    const state = crypto.randomBytes(24).toString('hex');
    states.set(state, Date.now() + 10 * 60 * 1000);
    saveMap(STATES_FILE, states);
    const authUrl = 'https://accounts.feishu.cn/open-apis/authen/v1/authorize'
      + `?client_id=${APP_ID}&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&state=${state}`;
    res.writeHead(302, { Location: authUrl });
    return res.end();
  }

  // 回调：先校验 state，再换取用户身份
  if (u.pathname === '/auth/feishu/callback') {
    const state = u.searchParams.get('state');
    const code = u.searchParams.get('code');
    const exp = states.get(state);
    states.delete(state); saveMap(STATES_FILE, states); // 一次性，无论成败都作废
    if (!state || !exp) return send(res, 403, LOGIN_PAGE('登录失败：state 无效或已使用，请重新登录'));
    if (Date.now() > exp) return send(res, 403, LOGIN_PAGE('登录失败：state 已过期，请重新登录'));
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
      const users = loadUsers();
      const existing = users[d.open_id];
      if (existing && existing.status === 'disabled') {
        return send(res, 403, LOGIN_PAGE(`账号 ${d.name} 已被停用，禁止登录`));
      }
      users[d.open_id] = {
        open_id: d.open_id, union_id: d.union_id, name: d.name,
        tenant_key: d.tenant_key || '', // 真实 tenant_key 来自首次登录返回，不编造
        status: existing ? existing.status : 'active',
        first_login: existing ? existing.first_login : new Date().toISOString(),
        last_login: new Date().toISOString(),
      };
      saveUsers(users);
      const sid = crypto.randomBytes(24).toString('hex');
      sessions.set(sid, { user: users[d.open_id], createdAt: Date.now() });
      saveMap(SESSIONS_FILE, sessions);
      res.writeHead(302, { Location: '/', 'Set-Cookie': `vq_sid=${sid}; HttpOnly; Path=/; SameSite=Lax` });
      return res.end();
    } catch (e) {
      return send(res, 500, LOGIN_PAGE('登录异常：' + e.message));
    }
  }

  if (u.pathname === '/logout') {
    const sid = getCookie(req, 'vq_sid');
    if (sid) { sessions.delete(sid); saveMap(SESSIONS_FILE, sessions); }
    res.writeHead(302, { Location: '/', 'Set-Cookie': 'vq_sid=; Max-Age=0; Path=/' });
    return res.end();
  }

  if (u.pathname === '/api/me') {
    const user = currentUser(req);
    return send(res, user ? 200 : 401,
      JSON.stringify(user ? { ok: true, user } : { ok: false }),
      { 'Content-Type': 'application/json; charset=utf-8' });
  }

  // 游戏首页：未登录先看登录页
  if (u.pathname === '/' || u.pathname === '/index.html') {
    const user = currentUser(req);
    if (!user) return send(res, 200, LOGIN_PAGE());
    return send(res, 200, fs.readFileSync(path.join(__dirname, 'index.html'), 'utf8'));
  }

  send(res, 404, 'Not Found');
});

server.listen(PORT, () => {
  console.log(`values-quest 测试服务已启动: ${BASE_URL}`);
  console.log(`飞书回调地址: ${REDIRECT_URI}`);
});
