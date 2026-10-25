/**
 * Signing keys, one set per realm.
 * ─────────────────────────────────────────────────────────────────────────────
 * Each realm signs with its own RSA-2048 key (RS256), identified by `kid` — the
 * key's RFC 7638 thumbprint. A realm can hold several keys at once:
 *
 *   active   signs new tokens (exactly one)
 *   passive  no longer signs, still published at /certs, so tokens it signed
 *            stay verifiable until they have expired
 *
 * Rotation adds a new active key and turns the old one passive; retiring a
 * passive key removes it from JWKS. These keys belong to this system alone and
 * are never shared with the primary IdP: applications trust both JWKS
 * endpoints.
 *
 * Private keys are stored sealed (AES-GCM under a key derived from JWT_SECRET),
 * so a Redis dump does not contain a usable one. Every gateway instance keeps a
 * copy in memory and reloads it when the realm's key version moves.
 */

const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { b64url, sha256 } = require('./util');

const RELOAD_INTERVAL_MS = 15_000;

function createKeyring({ store, sealer, log }) {
  const { redis } = store;
  const cache = new Map(); // realm -> { version, checkedAt, keys: [{ kid, status, jwk, privateKey, publicKey, createdAt }] }

  function generate() {
    const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    const jwk = publicKey.export({ format: 'jwk' });
    const kid = b64url(sha256(JSON.stringify({ e: jwk.e, kty: jwk.kty, n: jwk.n })));
    return {
      kid,
      jwk: { kty: jwk.kty, n: jwk.n, e: jwk.e },
      sealed: sealer.seal(privateKey.export({ type: 'pkcs8', format: 'pem' })),
      createdAt: new Date().toISOString(),
    };
  }

  async function load(realm) {
    const [stored, version] = await Promise.all([redis.hgetall(store.keys.keys(realm)), redis.get(store.keys.keysVersion(realm))]);
    const keys = [];
    for (const raw of Object.values(stored)) {
      const key = JSON.parse(raw);
      try {
        const privateKey = key.status === 'active' ? crypto.createPrivateKey(sealer.unseal(key.sealed)) : null;
        keys.push({
          kid: key.kid, status: key.status, jwk: key.jwk, createdAt: key.createdAt,
          privateKey, publicKey: crypto.createPublicKey({ key: { ...key.jwk }, format: 'jwk' }),
        });
      } catch {
        log.warn('idp', `A signing key of realm '${realm}' could not be decrypted (JWT_SECRET changed?) and is ignored`, { realm, kid: key.kid });
      }
    }
    const entry = { version: version || '0', checkedAt: Date.now(), keys };
    cache.set(realm, entry);
    return entry;
  }

  async function current(realm) {
    const entry = cache.get(realm);
    if (entry && Date.now() - entry.checkedAt < RELOAD_INTERVAL_MS) return entry;
    if (entry) {
      const version = (await redis.get(store.keys.keysVersion(realm))) || '0';
      if (version === entry.version) { entry.checkedAt = Date.now(); return entry; }
    }
    return load(realm);
  }

  /** Makes sure the realm has an active key; the first instance to get here creates it. */
  async function ensure(realm) {
    const entry = await current(realm);
    if (entry.keys.some((key) => key.status === 'active' && key.privateKey)) return entry;
    const lock = `idp:${realm}:keys:lock`;
    if (await redis.set(lock, '1', 'EX', 30, 'NX')) {
      try {
        const fresh = await load(realm);
        if (!fresh.keys.some((key) => key.status === 'active' && key.privateKey)) {
          await addActiveKey(realm);
          log.audit('idp', `Created the first signing key of realm '${realm}'`, { realm });
        }
      } finally {
        await redis.del(lock);
      }
    } else {
      await new Promise((resolve) => { setTimeout(resolve, 300); });
    }
    return load(realm);
  }

  /** Adds a new active key; whatever was active becomes passive. One transaction. */
  async function addActiveKey(realm) {
    const stored = await redis.hgetall(store.keys.keys(realm));
    const key = { ...generate(), status: 'active' };
    const multi = redis.multi();
    for (const raw of Object.values(stored)) {
      const existing = JSON.parse(raw);
      if (existing.status === 'active') {
        multi.hset(store.keys.keys(realm), existing.kid, JSON.stringify({ ...existing, status: 'passive', retiredAt: new Date().toISOString() }));
      }
    }
    multi.hset(store.keys.keys(realm), key.kid, JSON.stringify(key)).incr(store.keys.keysVersion(realm));
    await multi.exec();
    cache.delete(realm);
    return key.kid;
  }

  async function rotate(realm) {
    const kid = await addActiveKey(realm);
    log.audit('idp', `Rotated the signing key of realm '${realm}'; the previous key stays published as passive`, { realm, kid });
    return kid;
  }

  /** Removes a passive key from JWKS. The active key cannot be retired. */
  async function retire(realm, kid) {
    const raw = await redis.hget(store.keys.keys(realm), kid);
    if (!raw) return 'missing';
    if (JSON.parse(raw).status === 'active') return 'active';
    await redis.multi().hdel(store.keys.keys(realm), kid).incr(store.keys.keysVersion(realm)).exec();
    cache.delete(realm);
    log.audit('idp', `Retired passive signing key '${kid}' of realm '${realm}'`, { realm, kid });
    return 'ok';
  }

  async function jwks(realm) {
    const { keys } = await current(realm);
    return {
      keys: keys
        .sort((a, b) => (a.status === b.status ? 0 : a.status === 'active' ? -1 : 1))
        .map((key) => ({ kid: key.kid, kty: 'RSA', alg: 'RS256', use: 'sig', n: key.jwk.n, e: key.jwk.e })),
    };
  }

  async function describe(realm) {
    const { keys } = await current(realm);
    return keys.map(({ kid, status, createdAt }) => ({ kid, status, createdAt, algorithm: 'RS256' }));
  }

  async function sign(realm, payload) {
    const { keys } = await current(realm);
    const active = keys.find((key) => key.status === 'active' && key.privateKey);
    if (!active) throw new Error(`Realm '${realm}' has no active signing key`);
    return jwt.sign(payload, active.privateKey, { algorithm: 'RS256', keyid: active.kid, header: { typ: 'JWT' } });
  }

  /** The active key's public half as Keycloak's realm document presents it (base64 DER). */
  async function publicKeyText(realm) {
    const { keys } = await current(realm);
    const active = keys.find((key) => key.status === 'active');
    return active ? active.publicKey.export({ type: 'spki', format: 'der' }).toString('base64') : null;
  }

  /**
   * Verifies a token this realm signed, with whichever of its published keys
   * signed it. Options are passed to jsonwebtoken (issuer, ignoreExpiration…).
   * @returns {object|null} the claims, or null if it is not a valid token of this realm
   */
  async function verify(realm, token, options = {}) {
    if (typeof token !== 'string' || token.length > 16384) return null;
    const decoded = jwt.decode(token, { complete: true });
    if (!decoded?.header?.kid) return null;
    const { keys } = await current(realm);
    const key = keys.find((candidate) => candidate.kid === decoded.header.kid);
    if (!key) return null;
    try {
      return jwt.verify(token, key.publicKey, { algorithms: ['RS256'], ...options });
    } catch {
      return null;
    }
  }

  async function ready(realm) {
    const { keys } = await current(realm);
    return keys.some((key) => key.status === 'active' && key.privateKey);
  }

  return { ensure, rotate, retire, jwks, describe, sign, verify, publicKeyText, ready };
}

module.exports = { createKeyring };
