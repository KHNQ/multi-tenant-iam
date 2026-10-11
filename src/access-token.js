/**
 * The gateway's session (access) tokens.
 * ─────────────────────────────────────────────────────────────────────────────
 * HS256 with JWT_SECRET — and only for this gateway. A token is issued by it
 * (iss), addressed to it (aud), always expires (exp, no more than the
 * lifetime it issues), and says it is an access token (token_use).
 * Verification insists on every one of those. Restricting the algorithm alone
 * would accept any HS256 token made with the same secret for some other
 * purpose, or one with no expiry at all — valid forever.
 *
 * What the token carries is deliberately little: the account id (sub), its
 * security version, a token id (jti) and, for a session issued through an
 * OIDC client, that client (cid). Everything else is read from Redis on every
 * request (see authenticate() in main.reg.js).
 */

const crypto = require('crypto');
const jwt = require('jsonwebtoken');

const ALGORITHM = 'HS256';
const TOKEN_USE = 'access';

/**
 * @param {object} opts
 * @param {string} opts.secret
 * @param {string} opts.issuer      the gateway's public URL
 * @param {string} opts.audience    what the tokens are for
 * @param {number} opts.ttlSeconds  how long a token lives
 */
function createAccessTokens({ secret, issuer, audience, ttlSeconds }) {
  /**
   * @param {{ id: string, tokenVersion: number, clientId?: string }} claims
   */
  function sign({ id, tokenVersion, clientId }) {
    return jwt.sign(
      { sub: id, tokenVersion, jti: crypto.randomUUID(), token_use: TOKEN_USE, ...(clientId ? { cid: clientId } : {}) },
      secret,
      { algorithm: ALGORITHM, expiresIn: ttlSeconds, issuer, audience },
    );
  }

  /** The claims of a valid access token; throws otherwise. */
  function verify(token) {
    const payload = jwt.verify(token, secret, { algorithms: [ALGORITHM], issuer, audience, clockTolerance: 30 });
    // jsonwebtoken checks exp only when it is present. Here it must be, and
    // no token may claim a longer life than this gateway gives out.
    if (typeof payload.exp !== 'number' || typeof payload.iat !== 'number' || payload.exp - payload.iat > ttlSeconds + 60) {
      throw new jwt.JsonWebTokenError('the token has no valid expiry');
    }
    if (payload.token_use !== TOKEN_USE) throw new jwt.JsonWebTokenError('not an access token');
    if (typeof payload.sub !== 'string' || typeof payload.jti !== 'string') throw new jwt.JsonWebTokenError('the token names no account');
    return payload;
  }

  return { sign, verify, issuer, audience, ttlSeconds };
}

module.exports = { createAccessTokens, ALGORITHM, TOKEN_USE };
