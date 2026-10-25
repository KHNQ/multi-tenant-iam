/**
 * SSO sessions, authorization codes and refresh tokens.
 * ─────────────────────────────────────────────────────────────────────────────
 * A session (`sid`) is one sign-in of one account in one realm. Clients that
 * sign in through it get their own refresh tokens, all tied to it, so ending
 * the session — logout, an administrator, a password change — ends every
 * refresh token it produced.
 *
 * Lifetimes follow the realm: a session dies after `ssoSessionIdleTimeout`
 * seconds without use (the key's TTL, renewed on every use) and, however busy,
 * after `ssoSessionMaxLifespan` seconds from sign-in.
 *
 * Nothing that is a credential is stored as itself: codes and refresh tokens
 * are kept as their SHA-256, so a Redis dump yields neither.
 *
 * Refresh tokens rotate (`revokeRefreshToken`, reuse 0): every use returns a
 * new one and retires the old. A retired token presented again means two
 * parties hold it — one of them is not the client — so the whole session is
 * revoked. Rotation is one Lua script: of two concurrent uses, exactly one
 * succeeds.
 */

const { randomUUID } = require('crypto');
const { randomToken, sha256b64, nowSeconds } = require('./util');

const CODE_TTL_SECONDS = 60;

const ROTATE = `
  local cur = redis.call('GET', KEYS[1])
  if not cur then return false end
  redis.call('DEL', KEYS[1])
  redis.call('SET', KEYS[2], ARGV[6], 'EX', ARGV[3])
  redis.call('SET', KEYS[3], ARGV[1], 'EX', ARGV[2])
  redis.call('SREM', KEYS[4], ARGV[4])
  redis.call('SADD', KEYS[4], ARGV[5])
  return cur
`;

const TAKE = `
  local value = redis.call('GET', KEYS[1])
  if value then redis.call('DEL', KEYS[1]) end
  return value
`;

function createSessions({ redis }) {
  redis.defineCommand('idpRotateRefresh', { numberOfKeys: 4, lua: ROTATE });
  redis.defineCommand('idpTakeOnce', { numberOfKeys: 1, lua: TAKE });

  const k = {
    session: (r, sid) => `idp:${r}:sess:${sid}`,
    userSessions: (r, uid) => `idp:${r}:user-sess:${uid}`,
    sessionTokens: (r, sid) => `idp:${r}:sess-rt:${sid}`,
    refresh: (r, hash) => `idp:${r}:rt:${hash}`,
    usedRefresh: (r, hash) => `idp:${r}:rt-used:${hash}`,
    code: (r, hash) => `idp:${r}:code:${hash}`,
    usedCode: (r, hash) => `idp:${r}:code-used:${hash}`,
    revoked: (r, jti) => `idp:${r}:revoked:${jti}`,
  };

  const idle = (settings) => Math.max(60, Number(settings.ssoSessionIdleTimeout) || 1800);
  const max = (settings) => Math.max(60, Number(settings.ssoSessionMaxLifespan) || 36000);

  /** Seconds the session may still live, given both limits. */
  function remaining(session, settings) {
    const ageLeft = Math.floor((session.created + max(settings) * 1000 - Date.now()) / 1000);
    return Math.min(idle(settings), ageLeft);
  }

  async function create(realm, settings, { user, securityVersion, ip, acr = '1' }) {
    const sid = randomUUID();
    const now = Date.now();
    const session = {
      sid, userId: user.id, username: user.username, created: String(now), lastAccess: String(now),
      authTime: String(nowSeconds()), ip: ip || '', securityVersion: String(securityVersion), acr,
    };
    await redis.multi()
      .hset(k.session(realm, sid), session)
      .expire(k.session(realm, sid), idle(settings))
      .sadd(k.userSessions(realm, user.id), sid)
      .exec();
    return get(realm, settings, sid);
  }

  function decode(raw) {
    if (!raw?.sid) return null;
    const clients = {};
    for (const [field, value] of Object.entries(raw)) {
      if (field.startsWith('client:')) clients[field.slice(7)] = JSON.parse(value);
    }
    return {
      sid: raw.sid, userId: raw.userId, username: raw.username,
      created: Number(raw.created), lastAccess: Number(raw.lastAccess), authTime: Number(raw.authTime),
      ip: raw.ip, securityVersion: Number(raw.securityVersion), acr: raw.acr || '1', clients,
    };
  }

  /** The session if it is still alive under the realm's limits, else null (and it is ended). */
  async function get(realm, settings, sid) {
    if (typeof sid !== 'string' || !/^[0-9a-f-]{36}$/.test(sid)) return null;
    const session = decode(await redis.hgetall(k.session(realm, sid)));
    if (!session) return null;
    if (remaining(session, settings) <= 0) {
      await end(realm, sid);
      return null;
    }
    return session;
  }

  /** Marks the session used now, renewing its idle window (never past its maximum). */
  async function touch(realm, settings, session) {
    const ttl = remaining(session, settings);
    if (ttl <= 0) return false;
    await redis.multi()
      .hset(k.session(realm, session.sid), 'lastAccess', String(Date.now()))
      .expire(k.session(realm, session.sid), ttl)
      .exec();
    return true;
  }

  /** A fresh authentication inside an existing session: new auth_time, same sid. */
  async function reauthenticate(realm, settings, session, { securityVersion, ip }) {
    await redis.hset(k.session(realm, session.sid), {
      authTime: String(nowSeconds()), acr: '1', securityVersion: String(securityVersion), ip: ip || session.ip, lastAccess: String(Date.now()),
    });
    await touch(realm, settings, session);
    return get(realm, settings, session.sid);
  }

  async function noteClient(realm, session, client, scope) {
    const existing = session.clients[client.clientId];
    const entry = { name: client.name || client.clientId, scope, started: existing?.started || Date.now(), lastRefresh: Date.now() };
    await redis.hset(k.session(realm, session.sid), `client:${client.clientId}`, JSON.stringify(entry));
    session.clients[client.clientId] = entry;
  }

  async function end(realm, sid) {
    const raw = await redis.hgetall(k.session(realm, sid));
    const tokens = await redis.smembers(k.sessionTokens(realm, sid));
    const multi = redis.multi().del(k.session(realm, sid)).del(k.sessionTokens(realm, sid));
    for (const hash of tokens) multi.del(k.refresh(realm, hash));
    if (raw?.userId) multi.srem(k.userSessions(realm, raw.userId), sid);
    await multi.exec();
    return Boolean(raw?.sid);
  }

  /** Live sessions of one account, oldest first; dead ids are tidied away. */
  async function listForUser(realm, settings, userId) {
    const sids = await redis.smembers(k.userSessions(realm, userId));
    const sessions = [];
    for (const sid of sids) {
      const session = await get(realm, settings, sid);
      if (session) sessions.push(session);
      else await redis.srem(k.userSessions(realm, userId), sid);
    }
    return sessions.sort((a, b) => a.created - b.created);
  }

  async function endAllForUser(realm, userId) {
    const sids = await redis.smembers(k.userSessions(realm, userId));
    for (const sid of sids) await end(realm, sid);
    return sids.length;
  }

  // ── authorization codes ───────────────────────────────────────────────────

  async function issueCode(realm, grant) {
    const code = randomToken();
    await redis.set(k.code(realm, sha256b64(code)), JSON.stringify(grant), 'EX', CODE_TTL_SECONDS);
    return code;
  }

  /** @returns {Promise<{ grant?: object, reusedSid?: string }>} */
  async function takeCode(realm, code) {
    if (typeof code !== 'string' || code.length > 256) return {};
    const hash = sha256b64(code);
    const stored = await redis.idpTakeOnce(k.code(realm, hash));
    if (stored) return { grant: JSON.parse(stored), hash };
    const reusedSid = await redis.idpTakeOnce(k.usedCode(realm, hash));
    return reusedSid ? { reusedSid } : {};
  }

  /** Remembers which session a code bought, so a second use of it can withdraw that. */
  const noteCodeUsed = (realm, hash, sid) => redis.set(k.usedCode(realm, hash), sid, 'EX', 10 * 60);

  // ── refresh tokens ────────────────────────────────────────────────────────

  async function issueRefresh(realm, settings, session, data) {
    const token = randomToken(32);
    const hash = sha256b64(token);
    const ttl = remaining(session, settings);
    await redis.multi()
      .set(k.refresh(realm, hash), JSON.stringify({ ...data, sid: session.sid, issuedAt: Date.now() }), 'EX', Math.max(1, ttl))
      .sadd(k.sessionTokens(realm, session.sid), hash)
      .expire(k.sessionTokens(realm, session.sid), max(settings))
      .exec();
    return { token, expiresIn: Math.max(0, ttl) };
  }

  /** @returns {Promise<{ data?: object, reusedSid?: string }>} */
  async function peekRefresh(realm, token) {
    if (typeof token !== 'string' || token.length < 20 || token.length > 512) return {};
    const hash = sha256b64(token);
    const raw = await redis.get(k.refresh(realm, hash));
    if (raw) return { data: JSON.parse(raw), hash };
    const reusedSid = await redis.get(k.usedRefresh(realm, hash));
    return reusedSid ? { reusedSid } : {};
  }

  /**
   * Retires `oldHash` and issues its successor, atomically.
   * @returns {Promise<{ token: string, expiresIn: number } | null>} null if another use got there first
   */
  async function rotateRefresh(realm, settings, session, oldHash, data) {
    const token = randomToken(32);
    const hash = sha256b64(token);
    const ttl = Math.max(1, remaining(session, settings));
    const won = await redis.idpRotateRefresh(
      k.refresh(realm, oldHash), k.usedRefresh(realm, oldHash), k.refresh(realm, hash), k.sessionTokens(realm, session.sid),
      JSON.stringify({ ...data, sid: session.sid, issuedAt: Date.now() }), ttl, max(settings), oldHash, hash, session.sid,
    );
    return won ? { token, expiresIn: ttl } : null;
  }

  async function revokeRefresh(realm, token) {
    const { data, hash } = await peekRefresh(realm, token);
    if (!data) return null;
    await redis.multi().del(k.refresh(realm, hash)).srem(k.sessionTokens(realm, data.sid), hash).exec();
    return data;
  }

  // ── access token denylist ─────────────────────────────────────────────────

  async function revokeAccessToken(realm, jti, exp) {
    const ttl = exp - nowSeconds();
    if (jti && ttl > 0) await redis.set(k.revoked(realm, jti), '1', 'EX', ttl);
  }
  const accessTokenRevoked = async (realm, jti) => (await redis.exists(k.revoked(realm, jti))) === 1;

  return {
    create, get, touch, reauthenticate, noteClient, end, listForUser, endAllForUser, remaining,
    issueCode, takeCode, noteCodeUsed,
    issueRefresh, peekRefresh, rotateRefresh, revokeRefresh,
    revokeAccessToken, accessTokenRevoked,
  };
}

module.exports = { createSessions, CODE_TTL_SECONDS };
