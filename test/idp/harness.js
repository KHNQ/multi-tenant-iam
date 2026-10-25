/**
 * Test harness for the identity provider and the console BFF.
 *
 * Starts what the suite needs and nothing it does not share with anything
 * else: a throwaway redis-server on a free port (no persistence), and a
 * gateway process pointed at it with its own JWT_SECRET, log directory and
 * one-time-password files. A `Browser` follows the flows the way a user agent
 * does — a cookie jar, manual redirects, and the sign-in forms filled in.
 */

const { spawn, spawnSync } = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const net = require('net');
const os = require('os');
const path = require('path');
const Redis = require('ioredis');

const ROOT = path.join(__dirname, '..', '..');

function freePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.unref();
    server.on('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });
}

const sleep = (ms) => new Promise((resolve) => { setTimeout(resolve, ms); });

async function waitFor(check, { timeoutMs = 20000, intervalMs = 150, what = 'condition' } = {}) {
  const started = Date.now();
  let lastError;
  while (Date.now() - started < timeoutMs) {
    try {
      if (await check()) return;
    } catch (err) {
      lastError = err;
    }
    await sleep(intervalMs);
  }
  throw new Error(`Timed out waiting for ${what}${lastError ? `: ${lastError.message}` : ''}`);
}

const redisAvailable = () => spawnSync('redis-server', ['--version']).status === 0;

async function startRedis(dir) {
  const port = await freePort();
  const proc = spawn('redis-server', ['--port', String(port), '--save', '', '--appendonly', 'no', '--dir', dir], { stdio: 'ignore' });
  const client = new Redis({ port, lazyConnect: true, maxRetriesPerRequest: 1, retryStrategy: () => 200 });
  await waitFor(async () => {
    try { await client.connect(); } catch { /* not yet */ }
    return (await client.ping()) === 'PONG';
  }, { what: 'redis-server' });
  return { port, proc, client, url: `redis://127.0.0.1:${port}` };
}

/**
 * @param {object} [opts]
 * @param {object} [opts.env] extra environment for the gateway
 */
async function startStack({ env = {} } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'iam-idp-test-'));
  const redis = await startRedis(dir);
  const port = await freePort();
  const publicUrl = `http://localhost:${port}`;
  const files = {
    consoleAdmin: path.join(dir, 'initial-console-admin-password'),
    gatewayAdmin: path.join(dir, 'initial-admin-password'),
  };
  let output = '';
  const gateway = spawn(process.execPath, [path.join(ROOT, 'src', 'main.reg.js')], {
    cwd: ROOT,
    env: {
      PATH: process.env.PATH,
      HOME: process.env.HOME,
      JWT_SECRET: crypto.randomBytes(48).toString('base64'),
      REDIS_URL: redis.url,
      PORT: String(port),
      PUBLIC_URL: publicUrl,
      UPSTREAM_ALLOWED_CIDRS: '127.0.0.0/8',
      REGISTRY_URL: `http://127.0.0.1:${await freePort()}`,
      LOG_DIR: path.join(dir, 'logs'),
      INITIAL_ADMIN_PASSWORD_FILE: files.gatewayAdmin,
      IDP_BOOTSTRAP_PASSWORD_FILE: files.consoleAdmin,
      ...env,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  gateway.stdout.on('data', (chunk) => { output += chunk; });
  gateway.stderr.on('data', (chunk) => { output += chunk; });
  await waitFor(async () => {
    if (gateway.exitCode !== null) throw new Error(`gateway exited:\n${output.slice(-4000)}`);
    const res = await fetch(`${publicUrl}/health/ready`);
    return res.ok;
  }, { timeoutMs: 30000, what: 'the gateway' });

  return {
    url: publicUrl,
    redis: redis.client,
    files,
    output: () => output,
    async stop() {
      gateway.kill('SIGTERM');
      await new Promise((resolve) => { if (gateway.exitCode !== null) resolve(); else gateway.once('exit', resolve); });
      redis.client.disconnect();
      redis.proc.kill('SIGTERM');
      fs.rmSync(dir, { recursive: true, force: true });
    },
  };
}

// ── a user agent ───────────────────────────────────────────────────────────

class Browser {
  constructor(base) {
    this.base = base;
    this.cookies = new Map(); // name|path -> { name, value, path }
  }

  cookieHeader(url) {
    const { pathname } = new URL(url);
    return [...this.cookies.values()].filter((c) => pathname.startsWith(c.path)).map((c) => `${c.name}=${c.value}`).join('; ');
  }

  cookie(name) {
    return [...this.cookies.values()].find((c) => c.name === name)?.value ?? null;
  }

  store(res) {
    for (const line of res.headers.getSetCookie()) {
      const [pair, ...attrs] = line.split(';').map((s) => s.trim());
      const at = pair.indexOf('=');
      const name = pair.slice(0, at);
      const value = pair.slice(at + 1);
      const attr = Object.fromEntries(attrs.map((a) => { const i = a.indexOf('='); return i < 0 ? [a.toLowerCase(), true] : [a.slice(0, i).toLowerCase(), a.slice(i + 1)]; }));
      const cookiePath = attr.path || '/';
      const key = `${name}|${cookiePath}`;
      const expired = attr['max-age'] === '0' || (attr.expires && Date.parse(attr.expires) < Date.now()) || value === '';
      if (expired) this.cookies.delete(key); else this.cookies.set(key, { name, value: decodeURIComponent(value), path: cookiePath });
    }
  }

  async request(url, { method = 'GET', headers = {}, body, form } = {}) {
    const target = new URL(url, this.base).toString();
    const h = { ...headers };
    const cookie = this.cookieHeader(target);
    if (cookie) h.Cookie = cookie;
    let payload = body;
    if (form) {
      h['Content-Type'] = 'application/x-www-form-urlencoded';
      payload = new URLSearchParams(form).toString();
    } else if (body !== undefined && typeof body !== 'string') {
      h['Content-Type'] = 'application/json';
      payload = JSON.stringify(body);
    }
    const res = await fetch(target, { method, headers: h, body: payload, redirect: 'manual' });
    this.store(res);
    const text = await res.text();
    let json = null;
    try { json = JSON.parse(text); } catch { /* not json */ }
    return { status: res.status, headers: res.headers, text, json, url: target, location: res.headers.get('location') };
  }

  /** Follows redirects on this origin; stops at the first one leaving it (or at a page). */
  async follow(url, opts) {
    let res = await this.request(url, opts);
    for (let hops = 0; hops < 10 && res.status >= 300 && res.status < 400 && res.location; hops++) {
      const next = new URL(res.location, res.url);
      if (next.origin !== new URL(this.base).origin) return res;
      res = await this.request(next.toString());
    }
    return res;
  }

  /** The console's own calls: same origin, the CSRF double-submit header on writes. */
  api(method, pathname, body, { idempotencyKey } = {}) {
    const headers = { Accept: 'application/json' };
    if (method !== 'GET') {
      headers['X-XSRF-TOKEN'] = this.cookie('XSRF-TOKEN') || '';
      // Every write carries a key, as the console sends one; null leaves it out.
      const key = idempotencyKey === undefined ? crypto.randomUUID() : idempotencyKey;
      if (key) headers['Idempotency-Key'] = key;
    }
    return this.request(pathname, { method, headers, body });
  }
}

/** The fields of the first <form> on a page (hidden inputs included) and its action. */
function parseForm(html, index = 0) {
  const forms = [...html.matchAll(/<form[^>]*action="([^"]*)"[^>]*>([\s\S]*?)<\/form>/g)];
  const match = forms[index];
  if (!match) return null;
  const decode = (s) => s.replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');
  const fields = {};
  for (const [tag] of match[2].matchAll(/<input[^>]*>/g)) {
    const name = /\sname="([^"]+)"/.exec(tag)?.[1];
    if (name) fields[name] = decode(/\svalue="([^"]*)"/.exec(tag)?.[1] ?? '');
  }
  return { action: decode(match[1]), fields };
}

// ── PKCE and an OIDC client ─────────────────────────────────────────────────

function pkce() {
  const verifier = crypto.randomBytes(48).toString('base64url');
  return { verifier, challenge: crypto.createHash('sha256').update(verifier).digest('base64url') };
}

const decodeJwt = (token) => JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8'));

/**
 * Signs `username` in to `clientId` through the browser and returns the code.
 * If the sign-in page asks for a new password, `newPassword` is set.
 */
async function signIn(browser, { realm, clientId, redirectUri, username, password, newPassword, scope = 'openid profile email', extra = {} }) {
  const { verifier, challenge } = pkce();
  const state = crypto.randomBytes(8).toString('hex');
  const nonce = crypto.randomBytes(8).toString('hex');
  const params = new URLSearchParams({
    response_type: 'code', client_id: clientId, redirect_uri: redirectUri, scope, state, nonce,
    code_challenge: challenge, code_challenge_method: 'S256', ...extra,
  });
  let res = await browser.request(`/realms/${realm}/protocol/openid-connect/auth?${params}`);
  if (res.status === 200 && res.text.includes('name="password"')) {
    const login = parseForm(res.text);
    res = await browser.request(login.action, { method: 'POST', form: { ...login.fields, username, password } });
  }
  if (res.status === 200 && res.text.includes('name="new_password"')) {
    const change = parseForm(res.text);
    res = await browser.request(change.action, { method: 'POST', form: { ...change.fields, new_password: newPassword, confirm_password: newPassword } });
  }
  if (res.status === 200 && res.text.includes('id="response"')) {
    // response_mode=form_post: the parameters arrive as a self-submitting form.
    const post = parseForm(res.text);
    const back = new URL(post.action);
    for (const [name, value] of Object.entries(post.fields)) back.searchParams.set(name, value);
    return { res, code: post.fields.code, state: post.fields.state, sentState: state, nonce, verifier, location: back };
  }
  if (res.status !== 302) return { res };
  const back = new URL(res.location);
  return { res, code: back.searchParams.get('code'), state: back.searchParams.get('state'), sentState: state, nonce, verifier, location: back };
}

async function tokenRequest(base, realm, form, { basic } = {}) {
  const headers = { 'Content-Type': 'application/x-www-form-urlencoded' };
  if (basic) headers.Authorization = `Basic ${Buffer.from(`${encodeURIComponent(basic[0])}:${encodeURIComponent(basic[1])}`).toString('base64')}`;
  const res = await fetch(`${base}/realms/${realm}/protocol/openid-connect/token`, { method: 'POST', headers, body: new URLSearchParams(form) });
  return { status: res.status, json: await res.json().catch(() => null) };
}

module.exports = {
  startStack, redisAvailable, Browser, parseForm, pkce, decodeJwt, signIn, tokenRequest, waitFor, sleep, freePort,
};
