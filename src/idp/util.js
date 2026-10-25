/**
 * Small helpers shared by the identity provider's modules: encoding, hashing,
 * sealing secrets at rest, and the exact-match rules for redirect URIs.
 */

const crypto = require('crypto');
const net = require('net');

const b64url = (buffer) => Buffer.from(buffer).toString('base64url');
const sha256 = (value) => crypto.createHash('sha256').update(value).digest();
const sha256b64 = (value) => b64url(sha256(value));
const randomToken = (bytes = 32) => crypto.randomBytes(bytes).toString('base64url');
const nowSeconds = () => Math.floor(Date.now() / 1000);

/** Compares two strings without the time taken depending on where they differ. */
function sameSecret(presented, expected) {
  if (typeof presented !== 'string' || typeof expected !== 'string') return false;
  return crypto.timingSafeEqual(sha256(presented), sha256(expected));
}

const escapeHtml = (value) => String(value ?? '').replace(/[&<>"']/g, (c) => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
}[c]));

/**
 * AES-256-GCM under a key derived from the gateway secret. Used for what must
 * not be readable from a Redis dump: private signing keys and imported
 * password hashes.
 */
function createSealer(secret, purpose) {
  const key = Buffer.from(crypto.hkdfSync('sha256', secret, 'iam-idp', purpose, 32));
  return {
    seal(plaintext) {
      const iv = crypto.randomBytes(12);
      const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
      const data = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
      return `${b64url(iv)}.${b64url(cipher.getAuthTag())}.${b64url(data)}`;
    },
    unseal(sealed) {
      const [iv, tag, data] = String(sealed).split('.');
      const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(iv, 'base64url'));
      decipher.setAuthTag(Buffer.from(tag, 'base64url'));
      return Buffer.concat([decipher.update(Buffer.from(data, 'base64url')), decipher.final()]).toString('utf8');
    },
  };
}

/** HMAC-signed, expiring blobs: what a login form carries between two requests. */
function createBlobSigner(secret) {
  const key = Buffer.from(crypto.hkdfSync('sha256', secret, 'iam-idp', 'signed-forms', 32));
  return {
    sign(payload, ttlSeconds) {
      const body = b64url(JSON.stringify({ ...payload, exp: nowSeconds() + ttlSeconds }));
      return `${body}.${b64url(crypto.createHmac('sha256', key).update(body).digest())}`;
    },
    read(blob, kind) {
      if (typeof blob !== 'string') return null;
      const [body, mac] = blob.split('.');
      if (!body || !mac) return null;
      const expected = crypto.createHmac('sha256', key).update(body).digest();
      const given = Buffer.from(mac, 'base64url');
      if (given.length !== expected.length || !crypto.timingSafeEqual(given, expected)) return null;
      try {
        const payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
        return payload.kind === kind && payload.exp > nowSeconds() ? payload : null;
      } catch {
        return null;
      }
    },
  };
}

// ── redirect URIs ───────────────────────────────────────────────────────────

const LOOPBACK_HOSTS = new Set(['127.0.0.1', '[::1]']);

function parseUri(value) {
  try { return new URL(value); } catch { return null; }
}

/**
 * Whether `presented` is one of the `registered` URIs. Exact string equality,
 * with the single exception RFC 8252 §7.3 asks for: a native app listening on
 * the loopback interface picks its port at run time, so for 127.0.0.1 and
 * [::1] over plain http the port is not compared. Never a prefix, never a
 * wildcard — `https://host/*` registered matches only the literal string.
 */
function redirectUriMatches(registered, presented) {
  if (typeof presented !== 'string' || !presented) return false;
  if (registered.includes(presented)) return true;
  const url = parseUri(presented);
  if (!url || url.protocol !== 'http:' || !LOOPBACK_HOSTS.has(url.hostname)) return false;
  const withoutPort = (u) => `${u.protocol}//${u.hostname}${u.pathname}${u.search}`;
  const wanted = withoutPort(url);
  return registered.some((uri) => {
    const candidate = parseUri(uri);
    return candidate && candidate.protocol === 'http:' && LOOPBACK_HOSTS.has(candidate.hostname)
      && !candidate.hash && withoutPort(candidate) === wanted;
  });
}

/**
 * What is wrong with a URI an administrator wants to register, or null.
 * https anywhere; http only on the loopback interface; a private-use scheme
 * (RFC 8252 §7.1: reverse-DNS, so it contains a dot) for native apps. Never a
 * fragment, credentials or a wildcard.
 */
function redirectUriProblem(value) {
  if (typeof value !== 'string' || !value || value.length > 2048) return 'must be a URI of at most 2048 characters';
  if (value.includes('*')) return 'must not contain a wildcard — redirect URIs are matched exactly';
  const url = parseUri(value);
  if (!url) return 'is not a valid URI';
  if (url.hash) return 'must not contain a fragment';
  if (url.username || url.password) return 'must not contain credentials';
  if (url.protocol === 'https:') return null;
  if (url.protocol === 'http:') {
    return ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname) ? null : 'must be https (plain http only on the loopback interface)';
  }
  const scheme = url.protocol.slice(0, -1);
  if (/^[a-z][a-z0-9+.-]*\.[a-z0-9+.-]+$/i.test(scheme) && !['javascript', 'data', 'file', 'vbscript'].includes(scheme)) return null;
  return 'must be https, loopback http, or a reverse-DNS private-use scheme (com.example.app:/callback)';
}

/** An allowed CORS origin: `scheme://host[:port]`, or `+` (the redirect URIs' origins), or `*`. */
function webOriginProblem(value) {
  if (value === '+' || value === '*') return null;
  const url = parseUri(value);
  if (!url || !['http:', 'https:'].includes(url.protocol)) return 'must be an origin such as https://app.example.org';
  if (url.origin !== value) return 'must be an origin only — scheme, host and port, with no path';
  return null;
}

/** The origins a client's browser code may call the token and userinfo endpoints from. */
function clientOrigins(client) {
  const origins = new Set();
  for (const entry of client.webOrigins || []) {
    if (entry === '+') {
      for (const uri of client.redirectUris || []) {
        const url = parseUri(uri);
        if (url && ['http:', 'https:'].includes(url.protocol)) origins.add(url.origin);
      }
    } else {
      origins.add(entry);
    }
  }
  return origins;
}

// ── addresses ───────────────────────────────────────────────────────────────

/** A BlockList from "10.0.0.0/8,::1/128,192.168.1.4" — or null when the list is empty. */
function parseCidrList(value) {
  const entries = String(value || '').split(',').map((s) => s.trim()).filter(Boolean);
  if (!entries.length) return null;
  const list = new net.BlockList();
  for (const entry of entries) {
    const [address, bits] = entry.split('/');
    const family = net.isIPv6(address) ? 'ipv6' : net.isIPv4(address) ? 'ipv4' : null;
    if (!family) throw new Error(`'${entry}' is not an address or CIDR range`);
    if (bits === undefined) list.addAddress(address, family);
    else list.addSubnet(address, Number(bits), family);
  }
  return list;
}

function addressAllowed(list, ip) {
  if (!list || !ip) return false;
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(ip);
  const address = mapped ? mapped[1] : ip;
  return list.check(address, net.isIPv6(address) ? 'ipv6' : 'ipv4');
}

/** Reads one cookie out of the Cookie header. */
function readCookie(req, name) {
  for (const part of (req.headers.cookie || '').split(';')) {
    const at = part.indexOf('=');
    if (at > 0 && part.slice(0, at).trim() === name) {
      try { return decodeURIComponent(part.slice(at + 1).trim()); } catch { return null; }
    }
  }
  return null;
}

module.exports = {
  b64url, sha256, sha256b64, randomToken, nowSeconds, sameSecret, escapeHtml,
  createSealer, createBlobSigner,
  redirectUriMatches, redirectUriProblem, webOriginProblem, clientOrigins,
  parseCidrList, addressAllowed, readCookie,
};
