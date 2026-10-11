const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { createAccessTokens } = require('../../src/access-token');

const secret = crypto.randomBytes(48).toString('base64');
const issuer = 'https://iam.example.test';
const audience = 'iam-gateway';
const tokens = createAccessTokens({ secret, issuer, audience, ttlSeconds: 3600 });

const now = () => Math.floor(Date.now() / 1000);
/**
 * A token made by hand with the gateway's secret. `claims` override the
 * defaults; a claim set to undefined is left out.
 */
function forge(claims) {
  const payload = { sub: 'acc-1', tokenVersion: 0, jti: 'j-1', token_use: 'access', iss: issuer, aud: audience, iat: now(), exp: now() + 600, ...claims };
  for (const key of Object.keys(payload)) if (payload[key] === undefined) delete payload[key];
  // jsonwebtoken drops a given iat under noTimestamp, so ask for that only when iat is to be absent.
  return jwt.sign(payload, secret, { algorithm: 'HS256', noTimestamp: !('iat' in payload) });
}

describe('access tokens', () => {
  test('a token the gateway signs verifies, with the claims it was given', () => {
    const claims = tokens.verify(tokens.sign({ id: 'acc-1', tokenVersion: 3, clientId: 'app-1' }));
    expect(claims).toMatchObject({ sub: 'acc-1', tokenVersion: 3, cid: 'app-1', iss: issuer, aud: audience, token_use: 'access' });
    expect(claims.exp - claims.iat).toBe(3600);
  });

  test('a hand-made token with every claim right also verifies (the control for the cases below)', () => {
    expect(() => tokens.verify(forge({}))).not.toThrow();
  });

  test.each([
    ['no expiry', { exp: undefined }],
    ['no issued-at', { iat: undefined }],
    ['a lifetime longer than the gateway issues', { exp: now() + 30 * 24 * 3600 }],
    ['another issuer', { iss: 'https://evil.example.test' }],
    ['no issuer', { iss: undefined }],
    ['another audience', { aud: 'some-other-service' }],
    ['no audience', { aud: undefined }],
    ['no token type', { token_use: undefined }],
    ['the wrong token type', { token_use: 'gateway-assertion' }],
    ['no account', { sub: undefined }],
    ['an expiry in the past', { iat: now() - 7200, exp: now() - 3600 }],
  ])('a token with %s is refused', (what, claims) => {
    expect(() => tokens.verify(forge(claims))).toThrow();
  });

  test('a token signed with another secret is refused', () => {
    const other = jwt.sign({ sub: 'acc-1', jti: 'j', token_use: 'access' }, 'another-secret-of-sufficient-length-123', { algorithm: 'HS256', expiresIn: 60, issuer, audience });
    expect(() => tokens.verify(other)).toThrow();
  });

  test('alg "none" and asymmetric algorithms are refused', () => {
    const unsigned = `${Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url')}.${Buffer.from(JSON.stringify({ sub: 'acc-1', jti: 'j', token_use: 'access', iss: issuer, aud: audience, iat: now(), exp: now() + 60 })).toString('base64url')}.`;
    expect(() => tokens.verify(unsigned)).toThrow();
    const { privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    const rs256 = jwt.sign({ sub: 'acc-1', jti: 'j', token_use: 'access' }, privateKey, { algorithm: 'RS256', expiresIn: 60, issuer, audience });
    expect(() => tokens.verify(rs256)).toThrow();
  });
});
