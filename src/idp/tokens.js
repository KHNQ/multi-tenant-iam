/**
 * Issuing tokens: access, ID and UserInfo, built from current data.
 * ─────────────────────────────────────────────────────────────────────────────
 * Every token is assembled afresh from the account, its roles and the client's
 * mappers as they are *now* — a refresh never copies the previous token — so a
 * role taken away in the primary system is gone from the next token.
 *
 * `sub` is the account's id, which for a synchronised account is the primary
 * system's user id byte for byte; `iss` is this system's issuer for the realm.
 * Everything else follows Keycloak's shapes (see mappers.js).
 */

const { randomUUID, createHash } = require('crypto');
const { buildCatalogue } = require('./roles');
const { activeScopes, mapClaims, audienceValue } = require('./mappers');
const { nowSeconds } = require('./util');

function createTokenService({ store, keyring, issuerFor }) {
  /** Everything about a realm a token needs, read in one go. */
  async function realmContext(realm) {
    const [settings, realmRoles, clientRoles, groups, scopes, clients] = await Promise.all([
      store.getRealm(realm), store.listRealmRoles(realm), store.listClientRoles(realm), store.listGroups(realm),
      store.listScopes(realm), store.listClients(realm),
    ]);
    return {
      settings,
      catalogue: buildCatalogue({ realmRoles, clientRoles, groups }),
      scopes: new Map(scopes.map((scope) => [scope.name, scope])),
      clientsById: new Map(clients.map((client) => [client.clientId, client])),
    };
  }

  const atHash = (token) => createHash('sha256').update(token, 'ascii').digest().subarray(0, 16).toString('base64url');

  /**
   * The claims a token would carry, built from current data. Nothing is
   * signed and nothing is stored: issue() signs these, preview() shows them.
   */
  async function buildClaims({ realm, client, user, session, scope, nonce, acr, serviceAccount, context }) {
    const ctx = context || await realmContext(realm);
    const { settings } = ctx;
    const issuer = issuerFor(realm);
    const { active, scopeClaim } = activeScopes(client, ctx.scopes, scope);
    const now = nowSeconds();
    const lifespan = Number(client.attributes?.['access.token.lifespan']) || Number(settings.accessTokenLifespan) || 300;
    const authTime = session ? session.authTime : now;
    const mapCtx = {
      client, user, catalogue: ctx.catalogue, activeScopeList: active, clientsById: ctx.clientsById,
      acr: acr ?? session?.acr ?? '1', authTime,
    };

    const access = mapClaims(mapCtx, 'access');
    const accessClaims = {
      exp: now + lifespan,
      iat: now,
      auth_time: authTime,
      jti: randomUUID(),
      iss: issuer,
      ...(audienceValue(access.audience) !== undefined ? { aud: audienceValue(access.audience) } : {}),
      sub: user.id,
      typ: 'Bearer',
      azp: client.clientId,
      ...(session ? { sid: session.sid } : {}),
      ...access.claims,
      scope: scopeClaim,
      ...(serviceAccount ? { client_id: client.clientId, clientHost: serviceAccount.clientHost, clientAddress: serviceAccount.clientAddress } : {}),
    };
    // A mapper cannot overwrite what identifies the token.
    Object.assign(accessClaims, { iss: issuer, sub: user.id, azp: client.clientId, typ: 'Bearer' });

    let idClaims = null;
    if (String(scope || '').split(/\s+/).includes('openid') && !serviceAccount) {
      const id = mapClaims(mapCtx, 'id');
      idClaims = {
        exp: now + lifespan,
        iat: now,
        auth_time: authTime,
        jti: randomUUID(),
        iss: issuer,
        aud: client.clientId,
        sub: user.id,
        typ: 'ID',
        azp: client.clientId,
        ...(nonce ? { nonce } : {}),
        ...(session ? { sid: session.sid } : {}),
        ...id.claims,
      };
      Object.assign(idClaims, { iss: issuer, sub: user.id, aud: client.clientId, azp: client.clientId, typ: 'ID' });
    }
    const userinfo = { sub: user.id, ...mapClaims(mapCtx, 'userinfo').claims };
    return { accessClaims, idClaims, userinfo, lifespan, scope: scopeClaim };
  }

  /**
   * @param {object} p
   * @param {string} p.realm
   * @param {object} p.client
   * @param {object} p.user
   * @param {object|null} p.session  the SSO session, or null (client credentials)
   * @param {string} p.scope          the requested scope parameter
   * @param {string} [p.nonce]
   * @param {string} [p.acr]
   * @param {object} [p.serviceAccount] { clientHost, clientAddress } for client credentials
   * @returns {Promise<{ accessToken, accessClaims, idToken, expiresIn, scope }>}
   */
  async function issue(params) {
    const built = await buildClaims(params);
    const accessToken = await keyring.sign(params.realm, built.accessClaims);
    let idToken = null;
    if (built.idClaims) {
      // Left half of the access token's hash (OIDC Core 3.1.3.6).
      idToken = await keyring.sign(params.realm, { ...built.idClaims, at_hash: atHash(accessToken) });
    }
    return { accessToken, accessClaims: built.accessClaims, idToken, expiresIn: built.lifespan, scope: built.scope };
  }

  /** What a sign-in by `user` to `client` would put in each token — for the console's access test. */
  async function preview({ realm, client, user, scope }) {
    const built = await buildClaims({ realm, client, user, session: null, scope, acr: '1' });
    return { accessToken: built.accessClaims, idToken: built.idClaims, userinfo: built.userinfo, scope: built.scope, lifespan: built.lifespan };
  }

  /** The UserInfo response for an account, through a client's mappers. */
  async function userInfo({ realm, client, user, session, scope }) {
    const ctx = await realmContext(realm);
    const { active } = activeScopes(client, ctx.scopes, scope);
    const { claims } = mapClaims({
      client, user, catalogue: ctx.catalogue, activeScopeList: active, clientsById: ctx.clientsById,
      acr: session?.acr, authTime: session?.authTime,
    }, 'userinfo');
    return { sub: user.id, ...claims };
  }

  return { issue, preview, userInfo, realmContext };
}

module.exports = { createTokenService };
