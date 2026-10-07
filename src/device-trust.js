/**
 * Recognising a client an account has signed in from before.
 * ─────────────────────────────────────────────────────────────────────────────
 * A lockout keyed by username alone is a switch anyone can flip: five wrong
 * guesses from anywhere and the real owner is locked out too. Keying it by
 * username AND address fixes that for one attacker, but not for many — and
 * dropping the account-wide limit altogether leaves distributed guessing
 * bounded only by how many addresses the attacker has.
 *
 * So the account-wide limit stays, and applies only to clients the account
 * has never signed in from (the approach OWASP calls "device cookies"). Each
 * successful sign-in hands the client a device token: a signed note saying
 * "this client signed in to account <id>". A client that presents one for the
 * account it is signing in to is counted on its own, per-device limit and is
 * not stopped by the account-wide one. An attacker spraying guesses from many
 * addresses can still exhaust the account-wide limit — which then stops only
 * clients the owner has never used.
 *
 * A device token is not a credential: it signs nobody in. It only decides
 * which counter an attempt is charged to. It is bound to one account id, so a
 * token from one account does nothing for another, and it carries a random
 * device id so a stolen one is limited on its own counter rather than
 * borrowing the owner's.
 *
 * Format: d1.<base64url(JSON {u, d, exp})>.<base64url(HMAC-SHA256)>
 */

const crypto = require('crypto');

const PREFIX = 'd1';
const DEFAULT_TTL_SECONDS = 180 * 24 * 60 * 60;

/**
 * @param {string} secret the gateway's signing secret; a separate key is derived from it
 * @param {object} [opts]
 * @param {number} [opts.ttlSeconds]
 */
function createDeviceTrust(secret, { ttlSeconds = DEFAULT_TTL_SECONDS } = {}) {
  const key = Buffer.from(crypto.hkdfSync('sha256', Buffer.from(secret), Buffer.alloc(0), 'iam device trust v1', 32));
  const mac = (body) => crypto.createHmac('sha256', key).update(`${PREFIX}.${body}`).digest('base64url');

  /** A token saying this client signed in to `userId`. Pass `deviceId` to renew one. */
  function issue(userId, deviceId = crypto.randomBytes(12).toString('base64url')) {
    const body = Buffer.from(JSON.stringify({ u: userId, d: deviceId, exp: Math.floor(Date.now() / 1000) + ttlSeconds })).toString('base64url');
    return `${PREFIX}.${body}.${mac(body)}`;
  }

  /** @returns {{ userId: string, deviceId: string } | null} */
  function read(token) {
    if (typeof token !== 'string' || token.length > 600) return null;
    const [prefix, body, signature] = token.split('.');
    if (prefix !== PREFIX || !body || !signature) return null;
    const expected = Buffer.from(mac(body));
    const given = Buffer.from(signature);
    if (given.length !== expected.length || !crypto.timingSafeEqual(given, expected)) return null;
    try {
      const { u, d, exp } = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
      if (typeof u !== 'string' || typeof d !== 'string' || !(exp > Date.now() / 1000)) return null;
      return { userId: u, deviceId: d };
    } catch {
      return null;
    }
  }

  return { issue, read, ttlSeconds };
}

module.exports = { createDeviceTrust };
